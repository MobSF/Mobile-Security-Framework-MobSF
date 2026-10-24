import logging
import os
import threading
from pathlib import Path
import time
import uuid

from django.conf import settings

import frida

from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.DynamicAnalyzer.views.android.frida_scripts import (
    class_pattern,
    class_trace,
    get_loaded_classes,
    get_methods,
    string_catch,
    string_compare,
)
from mobsf.DynamicAnalyzer.views.common.frida import (
    get_bridge_loader,
)
from mobsf.MobSF.security import sanitize_for_logging

logger = logging.getLogger(__name__)
_ACTIVE_SESSIONS = {}
_ACTIVE_SESSIONS_LOCK = threading.RLock()
_SESSION_LOCKS = {}
_SESSION_LOCKS_GUARD = threading.Lock()
_SESSION_OWNER_PID = os.getpid()
_SESSION_OWNER_TOKEN = f'{_SESSION_OWNER_PID}:{uuid.uuid4().hex}'
_SESSION_OWNER_TOKEN_LOCK = threading.Lock()


def _session_owner_token():
    """Return a process-unique token, including after a prefork."""
    global _SESSION_OWNER_PID  # pylint: disable=global-statement
    global _SESSION_OWNER_TOKEN  # pylint: disable=global-statement
    pid = os.getpid()
    with _SESSION_OWNER_TOKEN_LOCK:
        if pid != _SESSION_OWNER_PID:
            _SESSION_OWNER_PID = pid
            _SESSION_OWNER_TOKEN = f'{pid}:{uuid.uuid4().hex}'
        return _SESSION_OWNER_TOKEN


class Frida:

    def __init__(
            self, app_hash, package, defaults, auxiliary, extras, code,
            identifier=None):
        self.hash = app_hash
        self.package = package
        self.defaults = defaults
        self.auxiliary = auxiliary
        self.extras = extras
        self.code = code
        self.identifier = identifier
        self.pid = None
        self.frida_dir = Path(settings.TOOLS_DIR) / 'frida_scripts' / 'android'
        self.apk_dir = Path(settings.UPLD_DIR) / self.hash
        self.api_mon = self.apk_dir / 'mobsf_api_monitor.txt'
        self.frida_log = self.apk_dir / 'mobsf_frida_out.txt'
        self.deps = self.apk_dir / 'mobsf_app_deps.txt'
        self.clipboard = self.apk_dir / 'mobsf_app_clipboard.txt'
        self.gadget_marker = self.apk_dir / '.mobsf-gadget-mode'
        self.owner_file = self.apk_dir / '.mobsf-frida-owner'
        self.completion_event = threading.Event()
        self.last_error = ''
        self.bridge_loader = get_bridge_loader()

    def _session_key(self):
        return (self.hash, self.identifier)

    @classmethod
    def _operation_lock(cls, key):
        with _SESSION_LOCKS_GUARD:
            return _SESSION_LOCKS.setdefault(key, threading.RLock())

    @staticmethod
    def _process_alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True
        return True

    def _claim_owner(self):
        """Claim this analysis session for the current worker process."""
        process_token = _session_owner_token()
        for _ in range(2):
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                descriptor = os.open(self.owner_file, flags, 0o600)
                with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
                    target.write(process_token)
                return True
            except FileExistsError:
                try:
                    if self.owner_file.is_symlink():
                        self.last_error = 'Unsafe Frida owner state path'
                        logger.error('Unsafe Frida owner state path')
                        return False
                    owner = self.owner_file.read_text(
                        encoding='utf-8',
                        errors='ignore',
                    ).strip()
                    if owner == process_token:
                        return True
                    pid_text = owner.partition(':')[0]
                    if pid_text == str(os.getpid()):
                        self.owner_file.unlink(missing_ok=True)
                        continue
                    if pid_text.isdigit() and self._process_alive(
                            int(pid_text)):
                        self.last_error = (
                            'The active Frida session belongs to another '
                            'MobSF worker; retry this operation')
                        logger.error(
                            self.last_error)
                        return False
                    self.owner_file.unlink(missing_ok=True)
                except OSError:
                    self.last_error = 'Unable to inspect Frida session owner'
                    logger.exception('Unable to inspect Frida session owner')
                    return False
        return False

    def _release_owner(self):
        process_token = _session_owner_token()
        try:
            if self.owner_file.is_symlink():
                return
            owner = self.owner_file.read_text(
                encoding='utf-8',
                errors='ignore',
            ).strip()
            if owner == process_token:
                self.owner_file.unlink(missing_ok=True)
        except FileNotFoundError:
            pass
        except OSError:
            logger.exception('Unable to release Frida session ownership')

    @staticmethod
    def _close_entry(entry):
        try:
            entry['script'].unload()
        except Exception:
            pass
        try:
            entry['session'].detach()
        except Exception:
            pass

    @classmethod
    def close_active(cls, app_hash, identifier, package=None):
        """Close the active Frida session for one analysis."""
        key = (app_hash, identifier)
        with cls._operation_lock(key):
            with _ACTIVE_SESSIONS_LOCK:
                entry = _ACTIVE_SESSIONS.pop(key, None)
            if entry:
                cls._close_entry(entry)
            owner_file = (
                Path(settings.UPLD_DIR) / app_hash / '.mobsf-frida-owner')
            process_token = _session_owner_token()
            try:
                if (not owner_file.is_symlink()
                        and owner_file.read_text(
                            encoding='utf-8',
                            errors='ignore',
                ).strip() == process_token):
                    owner_file.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
            except OSError:
                logger.exception('Unable to release Frida session ownership')

    def reuse_session(self, replace=True, completion_timeout=30):
        """Inject through an existing Frida session."""
        key = self._session_key()
        with self._operation_lock(key):
            if not self._claim_owner():
                return False
            with _ACTIVE_SESSIONS_LOCK:
                entry = _ACTIVE_SESSIONS.get(key)
            if not entry:
                self._release_owner()
                return False
            script = None
            try:
                self.completion_event.clear()
                script = entry['session'].create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                api = script.exports_sync
                self.api_handler(api)
                self.pid = entry['pid']
                if replace:
                    old_script = entry['script']
                    entry['script'] = script
                    try:
                        old_script.unload()
                    except Exception:
                        pass
                    logger.info('Reloaded Frida script in the active session')
                    return True
            except Exception:
                logger.exception('Failed to reuse the active Frida session')
                if script:
                    try:
                        script.unload()
                    except Exception:
                        pass
                return False
            completed = self.completion_event.wait(completion_timeout)
            try:
                script.unload()
            except Exception:
                pass
            if not completed:
                logger.error('Timed out waiting for temporary Frida script')
                return False
            logger.info('Completed temporary Frida injection')
            return True

    def get_scripts(self, script_type, selected_scripts):
        """Get Frida Scripts."""
        combined_script = []
        header = []
        if not selected_scripts:
            return header
        all_scripts = self.frida_dir / script_type
        for script in all_scripts.rglob('*.js'):
            if '*' in selected_scripts:
                combined_script.append(script.read_text('utf-8', 'ignore'))
            if script.stem in selected_scripts:
                header.append(f'send("Loaded Frida Script - {script.stem}");')
                combined_script.append(script.read_text('utf-8', 'ignore'))
        return header + combined_script

    def get_auxiliary(self):
        """Get auxiliary hooks."""
        scripts = []
        if not self.auxiliary:
            return scripts
        for itm in self.auxiliary:
            if itm == 'enum_class':
                scripts.append(get_loaded_classes())
            elif itm == 'get_dependencies':
                scripts.append(
                    get_loaded_classes()
                    .replace('[AUXILIARY] ', '[RUNTIME-DEPS] ')
                    .replace(
                        '[AUXILIARY-DONE]',
                        '[RUNTIME-DEPS-DONE]',
                    ),
                )
            elif itm == 'string_catch':
                scripts.append(string_catch())
            elif itm == 'string_compare':
                scripts.append(string_compare())
            elif itm == 'enum_methods' and 'class_name' in self.extras:
                scripts.append(get_methods(self.extras['class_name']))
            elif itm == 'search_class' and 'class_search' in self.extras:
                scripts.append(class_pattern(self.extras['class_search']))
            elif itm == 'trace_class' and 'class_trace' in self.extras:
                scripts.append(class_trace(self.extras['class_trace']))
        return scripts

    def get_script(self, nolog=False):
        """Get final script."""
        if not self.code:
            self.code = ''
        rpc_list = []
        # Load custom code first
        scripts = [self.code]
        scripts.extend(self.get_scripts('default', self.defaults))
        rpc_list.extend(self.get_scripts('rpc', ['*']))
        scripts.extend(self.get_auxiliary())
        rpc_script = ','.join(rpc_list)
        rpc = f'rpc.exports = {{ \n{rpc_script}\n }};'
        combined = '\n'.join(scripts)
        final = f'{rpc}\n{combined}'

        # Use bridges only for Frida 17.0.0+
        if self.bridge_loader.is_required_and_available():
            try:
                final = self.bridge_loader.inject_bridge_support(
                    final, 'java')
                if not nolog:
                    logger.info('Frida Script injected with bridges')
            except Exception:
                logger.exception(
                    'Failed to inject script with bridges '
                    '(required for Frida 17.0.0+)')
        else:
            if not nolog:
                logger.info('Frida Script injected')

        return final

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            api_mon = 'MobSF-API-Monitor: '
            aux = '[AUXILIARY] '
            aux_done = '[AUXILIARY-DONE]'
            deps = '[RUNTIME-DEPS] '
            deps_done = '[RUNTIME-DEPS-DONE]'
            clip = 'mobsf-android-clipboard:'
            if not isinstance(msg, str):
                msg = str(msg)
            if msg.startswith(api_mon):
                self.write_log(self.api_mon, msg.replace(api_mon, ''))
            elif msg.startswith(clip):
                msg = msg.replace(clip, '')
                self.write_log(self.clipboard, f'{msg}\n')
            elif msg.startswith(deps):
                info = msg.replace(deps, '')
                self.write_log(self.deps, f'{info}\n')
                self.write_log(self.frida_log, f'{info}\n')
            elif msg == deps_done:
                self.completion_event.set()
            elif msg == aux_done:
                logger.debug('[Frida] Auxiliary script completed')
            elif msg.startswith(aux):
                msg = msg.replace(aux, '[*] ')
                self.write_log(self.frida_log, f'{msg}\n')
            else:
                logger.debug('[Frida] %s', msg)
                self.write_log(self.frida_log, f'{msg}\n')
        else:
            logger.error('[Frida] %s', message)

    def _find_gadget_process(self, device):
        application = device.get_frontmost_application()
        if (application
                and application.pid
                and application.identifier in (
                    self.package,
                    're.frida.Gadget',
                )):
            return application.pid
        applications = device.enumerate_applications(scope='minimal')
        for application in applications:
            if (application.identifier in (
                    self.package,
                    're.frida.Gadget',
            )
                    and application.pid):
                return application.pid
        return None

    def instrument(self, pid=None, package=None, completion_timeout=None):
        """Start and synchronously instrument an Android process."""
        key = self._session_key()
        with self._operation_lock(key):
            if not self._claim_owner():
                return False
            env = Environment(self.identifier)
            gadget = self.gadget_marker.exists()
            device = None
            session = None
            script = None
            started = False
            registered = False
            target_package = package if pid and package else self.package
            try:
                if gadget and pid:
                    logger.error(
                        'PID attachment is unavailable in Frida Gadget mode')
                    return False
                with _ACTIVE_SESSIONS_LOCK:
                    previous = _ACTIVE_SESSIONS.pop(key, None)
                if previous:
                    self._close_entry(previous)
                self.clean_up()
                self.completion_event.clear()
                if gadget:
                    if not env.stop_frida_server():
                        return False
                    env.adb_command(
                        ['am', 'force-stop', self.package], True, True)
                    if not env.run_app(self.package):
                        logger.error(
                            'Unable to launch the Gadget-injected app')
                        return False
                    started = True
                    for attempt in range(5):
                        try:
                            device = env.get_frida_device(gadget=True)
                            self.pid = self._find_gadget_process(device)
                            if self.pid:
                                break
                        except (frida.ServerNotRunningError,
                                frida.TimedOutError,
                                frida.TransportError):
                            if attempt == 4:
                                raise
                        time.sleep(1)
                    if not self.pid:
                        logger.error('Unable to find the Gadget process')
                        return False
                else:
                    if not env.run_frida_server():
                        return False
                    device = env.get_frida_device()
                    if pid:
                        self.pid = pid
                    else:
                        logger.info(
                            'Spawning %s',
                            sanitize_for_logging(target_package),
                        )
                        env.adb_command(
                            ['am', 'force-stop', target_package], True, True)
                        self.pid = device.spawn([target_package])
                        started = True
                session = device.attach(self.pid)
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()

                def detached(*_args):
                    removed = False
                    with _ACTIVE_SESSIONS_LOCK:
                        active = _ACTIVE_SESSIONS.get(key)
                        if active and active['session'] is session:
                            _ACTIVE_SESSIONS.pop(key, None)
                            removed = True
                    if removed:
                        self._release_owner()

                session.on('detached', detached)
                with _ACTIVE_SESSIONS_LOCK:
                    _ACTIVE_SESSIONS[key] = {
                        'session': session,
                        'script': script,
                        'pid': self.pid,
                        'package': target_package,
                    }
                registered = True
                if started:
                    device.resume(self.pid)
                api = script.exports_sync
                self.api_handler(api)
                if (completion_timeout is not None
                        and not self.completion_event.wait(
                            completion_timeout)):
                    logger.error(
                        'Timed out waiting for Frida script completion')
                    return False
                logger.info('Frida session is active')
                return True
            except frida.NotSupportedError:
                logger.exception('Not Supported Error')
            except frida.ServerNotRunningError:
                logger.warning('Frida server is not running')
            except frida.TimedOutError:
                logger.error('Timed out while waiting for device to appear')
            except (frida.ProcessNotFoundError,
                    frida.ProcessNotRespondingError,
                    frida.TransportError,
                    frida.InvalidOperationError):
                logger.exception('Frida instrumentation failed')
            except Exception:
                logger.exception('Error Connecting to Frida')
            finally:
                if not registered:
                    if script:
                        try:
                            script.unload()
                        except Exception:
                            pass
                    if session:
                        try:
                            session.detach()
                        except Exception:
                            pass
                    if started:
                        env.adb_command(
                            ['am', 'force-stop', target_package], True, True)
                    self._release_owner()
            return False

    def spawn(self, retry=True):
        """Start and instrument the analyzed package."""
        return self.instrument()

    def session(self, pid, package):
        """Start instrumentation or attach to a rooted process."""
        return self.instrument(pid, package)

    def ps(self):
        """Get running process pid."""
        ps_dict = []
        try:
            device = Environment(self.identifier).get_frida_device(
                gadget=self.gadget_marker.exists())
            processes = device.enumerate_applications(scope='minimal')
            if device and processes:
                for process in processes:
                    if process.pid != 0:
                        ps_dict.append({
                            'pid': process.pid,
                            'name': process.name,
                            'identifier': process.identifier,
                        })
        except Exception:
            logger.exception('Failed to enumerate running applications')
        return ps_dict

    def api_handler(self, api):
        """Call Frida rpc functions."""
        loaded_classes = []
        loaded_class_methods = []
        implementations = []
        try:
            if not self.extras:
                return
            raction = self.extras.get('rclass_action')
            rclass = self.extras.get('rclass_name')
            rclass_pattern = self.extras.get('rclass_pattern')
            rmethod = self.extras.get('rmethod_name')
            rmethod_pattern = self.extras.get('rmethod_pattern')
            if raction == 'raction':
                loaded_classes = api.getLoadedClasses()
            elif raction == 'getclasses' and rclass_pattern:
                loaded_classes = api.getLoadedClasses(f'/{rclass_pattern}/i')
            elif raction == 'getmethods' and rclass and rmethod:
                loaded_class_methods = api.getMethods(rclass)
            elif raction == 'getmethods' and rclass and rmethod_pattern:
                loaded_class_methods = api.getMethods(
                    rclass,
                    f'/{rmethod_pattern}/i')
            elif raction == 'getimplementations' and rclass and rmethod:
                implementations = api.getImplementations(rclass, rmethod)
        except Exception:
            logger.exception('Error while calling Frida RPC functions')
        if loaded_classes:
            rpc_classes = self.apk_dir / 'mobsf_rpc_classes.txt'
            loaded_classes = sorted(loaded_classes)
            rpc_classes.write_text('\n'.join(
                loaded_classes), 'utf-8')
        if loaded_class_methods:
            rpc_methods = self.apk_dir / 'mobsf_rpc_methods.txt'
            loaded_class_methods = sorted(loaded_class_methods)
            rpc_methods.write_text('\n'.join(
                loaded_class_methods), 'utf-8')
        if implementations:
            implementations = sorted(implementations)
            rpc_impl = self.apk_dir / 'mobsf_rpc_impl.txt'
            rpc_impl.write_text('\n'.join(
                implementations), 'utf-8')

    def clean_up(self):
        if self.api_mon.exists():
            self.api_mon.unlink()
        if self.frida_log.exists():
            self.frida_log.unlink()
        if self.clipboard.exists():
            self.clipboard.unlink()

    def write_log(self, file_path, data):
        with file_path.open('a',
                            encoding='utf-8',
                            errors='replace') as flip:
            flip.write(data)
