import logging
from threading import Thread
from pathlib import Path
import sys
import time

from django.conf import settings

import frida

from mobsf.DynamicAnalyzer.views.ios.frida_auxiliary_scripts import (
    class_pattern,
    class_trace,
    classes_with_method,
    get_loaded_classes,
    get_loaded_classes_methods,
    get_methods,
    string_capture,
    string_compare,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_frida_ssh import (
    ssh_jumphost_port_forward,
)


logger = logging.getLogger(__name__)
_PID = None


class Frida:

    def __init__(
            self,
            ci,
            app_hash,
            bundle_id,
            defaults,
            dump,
            auxiliary,
            extras,
            code,
            action):
        self.ssh_connection_string = ci.get_ssh_connection_string()
        self.app_container = None
        self.hash = app_hash
        self.bundle_id = bundle_id
        self.defaults = defaults
        self.dump = dump
        self.auxiliary = auxiliary
        self.extras = extras
        self.code = code
        self.action = action
        self.frida_dir = Path(settings.TOOLS_DIR) / 'frida_scripts_ios'
        self.ipa_dir = Path(settings.UPLD_DIR) / self.hash
        self.frida_log = self.ipa_dir / 'mobsf_frida_out.txt'
        self.dump_file = self.ipa_dir / 'mobsf_dump_file.txt'
        self.container_file = self.ipa_dir / 'mobsf_app_container_path.txt'

    def get_scripts(self, script_type, selected_scripts):
        """Get Frida Scripts."""
        combined_script = []
        header = []
        # Do not add interceptor hooks more than once.
        tracers = ('file-access', 'nslog', 'pasteboard', 'network',
                   'text-inputs', 'jailbreak_bypass', 'crypto', 'sqlite')
        if not selected_scripts:
            return header
        all_scripts = self.frida_dir / script_type
        for script in all_scripts.rglob('*.js'):
            if '*' in selected_scripts:
                combined_script.append(script.read_text())
            if self.action != 'spawn' and script.stem in tracers:
                continue
            if script.stem in selected_scripts:
                header.append(f'send("Loaded Frida Script - {script.stem}");')
                combined_script.append(script.read_text())
        return header + combined_script

    def get_auxiliary(self):
        """Get auxiliary hooks."""
        scripts = []
        if not self.auxiliary:
            return scripts
        for itm in self.auxiliary:
            if itm == 'enum_class':
                scripts.append(get_loaded_classes())
            elif itm == 'enum_class_methods':
                scripts.append(get_loaded_classes_methods())
            elif itm == 'string_capture':
                scripts.append(string_capture())
            elif itm == 'string_compare':
                scripts.append(string_compare())
            elif itm == 'enum_methods' and 'class_name' in self.extras:
                scripts.append(
                    get_methods(self.extras['class_name']))
            elif itm == 'search_class' and 'class_search' in self.extras:
                scripts.append(
                    class_pattern(self.extras['class_search']))
            elif itm == 'search_method' and 'method_search' in self.extras:
                scripts.append(
                    classes_with_method(self.extras['method_search']))
            elif itm == 'trace_class' and 'class_trace' in self.extras:
                scripts.append(
                    class_trace(self.extras['class_trace']))
        return scripts

    def get_script(self):
        """Get final script."""
        if not self.code:
            self.code = ''
        # Load custom code first
        rpc_list = []
        scripts = [self.code]
        scripts.extend(self.get_scripts('default', self.defaults))
        scripts.extend(self.get_scripts('dump', self.dump))
        rpc_list.extend(self.get_scripts('rpc', ['*']))
        scripts.extend(self.get_auxiliary())
        rpc_script = ','.join(rpc_list)
        rpc = f'rpc.exports = {{ {rpc_script} }};'
        combined = '\n'.join(scripts)
        final = f'{rpc} setTimeout(function() {{ {combined} }}, 2000)'
        return final

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            aux = '[AUXILIARY] '
            jb = '[Jailbreak Detection Bypass] '
            dump = '[MBSFDUMP] '
            if not isinstance(msg, str):
                msg = str(msg)

            if dump in msg:
                self.write_log(self.dump_file, msg.replace(dump, '') + '\n')
            elif msg.startswith(jb):
                self.write_log(self.frida_log, msg + '\n')
            elif msg.startswith(aux):
                self.write_log(self.frida_log,
                               msg.replace(aux, '[*] ') + '\n')
            else:
                logger.debug('[Frida] %s', msg)
                self.write_log(self.frida_log, msg + '\n')
        else:
            logger.error('[Frida] %s', message)

    def frida_ssh_forward(self):
        """Setup SSH tunnel and port forwarding for corellium."""
        try:
            logger.info('Setting up SSH tunnel and port forwarding')
            # Corellium VM provides SSH over bastion host
            # Frida server is not reachable, open SSH tunnel
            # and port forward
            Thread(
                target=ssh_jumphost_port_forward,
                args=(self.ssh_connection_string,),
                daemon=True).start()
            time.sleep(3)
        except Exception:
            logger.exception('Setting up SSH tunnel')

    def spawn(self):
        """Connect to Frida Server and spawn the app."""
        global _PID
        try:
            self.clean_up()
            try:
                _PID = frida.get_remote_device().spawn([self.bundle_id])
            except frida.NotSupportedError:
                logger.exception('Not Supported Error')
                return
            except frida.ServerNotRunningError:
                self.frida_ssh_forward()
            if not _PID:
                _PID = frida.get_remote_device().spawn([self.bundle_id])
            logger.info('Spawning %s', self.bundle_id)
            time.sleep(2)
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except frida.NotSupportedError:
            logger.exception('Not Supported Error')
            return
        except (frida.ProcessNotFoundError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida Server')

    def session(self, pid, bundle_id):
        """Use existing session to inject frida scripts."""
        global _PID
        try:
            self.clean_up()
            try:
                device = frida.get_remote_device()
                if pid and bundle_id:
                    _PID = pid
                    self.bundle_id = bundle_id
                front = device.get_frontmost_application()
                if not front:
                    # No frontmost app, spawn the app
                    _PID = device.spawn([self.bundle_id])
                elif front.pid != _PID:
                    # pid is not the frontmost app
                    _PID = device.spawn([self.bundle_id])
                # pid is the forntmost app
                session = device.attach(_PID)
            except frida.NotSupportedError:
                logger.exception('Not Supported Error')
                return
            except Exception:
                logger.warning('Cannot attach to pid, spawning again')
                self.spawn()
                session = device.attach(_PID)
            if session and device and _PID:
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                api = script.exports_sync
                device.resume(_PID)
                self.app_container = api.get_container()
                self.container_file.write_text(self.app_container)
                sys.stdin.read()
                script.unload()
                session.detach()
        except frida.NotSupportedError:
            logger.exception('Not Supported Error')
        except (frida.ProcessNotFoundError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida Server')

    def ps(self):
        """Get running process pid."""
        ps_dict = []
        try:
            try:
                device = frida.get_remote_device()
                processes = device.enumerate_applications(scope='minimal')
            except frida.ServerNotRunningError:
                self.frida_ssh_forward()
                device = frida.get_remote_device()
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

    def clean_up(self):
        if self.frida_log.exists():
            self.frida_log.unlink()
        if self.dump_file.exists():
            self.dump_file.unlink()
        if self.container_file.exists():
            self.container_file.unlink()

    def write_log(self, file_path, data):
        with file_path.open('a',
                            encoding='utf-8',
                            errors='replace') as flip:
            flip.write(data)
