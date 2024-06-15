import logging
from pathlib import Path
import sys
import time

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
from mobsf.MobSF.utils import (
    get_device,
)

logger = logging.getLogger(__name__)
_FPID = None


class Frida:

    def __init__(self, app_hash, package, defaults, auxiliary, extras, code):
        self.hash = app_hash
        self.package = package
        self.defaults = defaults
        self.auxiliary = auxiliary
        self.extras = extras
        self.code = code
        self.frida_dir = Path(settings.TOOLS_DIR) / 'frida_scripts' / 'android'
        self.apk_dir = Path(settings.UPLD_DIR) / self.hash
        self.api_mon = self.apk_dir / 'mobsf_api_monitor.txt'
        self.frida_log = self.apk_dir / 'mobsf_frida_out.txt'
        self.deps = self.apk_dir / 'mobsf_app_deps.txt'
        self.clipboard = self.apk_dir / 'mobsf_app_clipboard.txt'

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
                scripts.append(get_loaded_classes().replace(
                    '[AUXILIARY] ', '[RUNTIME-DEPS] '))
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

    def get_script(self):
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
        final = f'{rpc}\n setTimeout(function() {{ \n{combined}\n }}, 1000)'
        return final

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            api_mon = 'MobSF-API-Monitor: '
            aux = '[AUXILIARY] '
            deps = '[RUNTIME-DEPS] '
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
            elif msg.startswith(aux):
                msg = msg.replace(aux, '[*] ')
                self.write_log(self.frida_log, f'{msg}\n')
            else:
                logger.debug('[Frida] %s', msg)
                self.write_log(self.frida_log, f'{msg}\n')
        else:
            logger.error('[Frida] %s', message)

    def spawn(self):
        """Frida Spawn."""
        global _FPID
        try:
            env = Environment()
            self.clean_up()
            env.run_frida_server()
            device = frida.get_device(
                get_device(),
                settings.FRIDA_TIMEOUT)
            logger.info('Spawning %s', self.package)
            _FPID = device.spawn([self.package])
            device.resume(_FPID)
            time.sleep(1)
        except frida.NotSupportedError:
            logger.exception('Not Supported Error')
            return
        except frida.ServerNotRunningError:
            logger.warning('Frida server is not running')
            self.spawn()
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except (frida.ProcessNotFoundError,
                frida.ProcessNotRespondingError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida')

    def session(self, pid, package):
        """Use existing session to inject frida scripts."""
        global _FPID
        try:
            try:
                device = frida.get_device(
                    get_device(),
                    settings.FRIDA_TIMEOUT)
                if pid and package:
                    _FPID = pid
                    self.package = package
                try:
                    front = device.get_frontmost_application()
                    if front and front.pid != _FPID:
                        # Not the front most app.
                        # Get the pid of the front most app
                        logger.warning('Front most app has PID %s', front.pid)
                        _FPID = front.pid
                except Exception:
                    pass
                # pid is the fornt most app
                session = device.attach(_FPID)
                time.sleep(2)
            except frida.NotSupportedError:
                logger.exception('Not Supported Error')
                return
            except Exception:
                logger.exception('Cannot attach to pid, spawning again')
                self.spawn()
                session = device.attach(_FPID)
                time.sleep(2)
            if session and device and _FPID:
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                api = script.exports_sync
                self.api_handler(api)
                sys.stdin.read()
                script.unload()
                session.detach()
        except frida.NotSupportedError:
            logger.exception('Not Supported Error')
        except (frida.ProcessNotFoundError,
                frida.ProcessNotRespondingError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida')

    def ps(self):
        """Get running process pid."""
        ps_dict = []
        try:
            device = frida.get_device(
                get_device(),
                settings.FRIDA_TIMEOUT)
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
