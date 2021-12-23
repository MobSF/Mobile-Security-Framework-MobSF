import io
import os
import glob
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
    is_file_exists,
)

logger = logging.getLogger(__name__)


class Frida:

    def __init__(self, app_hash, package, defaults, auxiliary, extras, code):
        self.hash = app_hash
        self.package = package
        self.defaults = defaults
        self.auxiliary = auxiliary
        self.extras = extras
        self.code = code
        self.frida_dir = os.path.join(settings.TOOLS_DIR,
                                      'frida_scripts')
        self.apk_dir = os.path.join(settings.UPLD_DIR, self.hash + '/')
        self.api_mon = os.path.join(self.apk_dir, 'mobsf_api_monitor.txt')
        self.frida_log = os.path.join(self.apk_dir, 'mobsf_frida_out.txt')
        self.deps = os.path.join(self.apk_dir, 'mobsf_app_deps.txt')

    def get_default_scripts(self):
        """Get default Frida Scripts."""
        combined_script = []
        header = []
        if not self.defaults:
            return header
        def_scripts = os.path.join(self.frida_dir, 'default')
        files = glob.glob(def_scripts + '**/*.js', recursive=True)
        for item in files:
            script = Path(item)
            if script.stem in self.defaults:
                header.append('send("Loaded Frida Script - {}");'.format(
                    script.stem))
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
        # Load custom code first
        scripts = [self.code]
        scripts.extend(self.get_default_scripts())
        scripts.extend(self.get_auxiliary())
        final = 'setTimeout(function() {{ {} }}, 0)'.format(
            '\n'.join(scripts))
        return final

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            api_mon = 'MobSF-API-Monitor: '
            aux = '[AUXILIARY] '
            deps = '[RUNTIME-DEPS] '
            if not isinstance(msg, str):
                msg = str(msg)
            if msg.startswith(api_mon):
                self.write_log(self.api_mon, msg.replace(api_mon, ''))
            elif msg.startswith(deps):
                info = msg.replace(deps, '') + '\n'
                self.write_log(self.deps, info)
                self.write_log(self.frida_log, info)
            elif msg.startswith(aux):
                self.write_log(self.frida_log,
                               msg.replace(aux, '[*] ') + '\n')
            else:
                logger.debug('[Frida] %s', msg)
                self.write_log(self.frida_log, msg + '\n')
        else:
            logger.error('[Frida] %s', message)

    def connect(self):
        """Connect to Frida Server."""
        session = None
        device = None
        try:
            env = Environment()
            self.clean_up()
            env.run_frida_server()
            device = frida.get_device(get_device(), settings.FRIDA_TIMEOUT)
            pid = device.spawn([self.package])
            logger.info('Spawning %s', self.package)
            session = device.attach(pid)
            time.sleep(2)
        except frida.ServerNotRunningError:
            logger.warning('Frida server is not running')
            self.connect()
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except (frida.ProcessNotFoundError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida')
        try:
            if session:
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                device.resume(pid)
                sys.stdin.read()
                script.unload()
                session.detach()
        except (frida.ProcessNotFoundError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida')

    def clean_up(self):
        if is_file_exists(self.api_mon):
            os.remove(self.api_mon)
        if is_file_exists(self.frida_log):
            os.remove(self.frida_log)

    def write_log(self, file_path, data):
        with io.open(
                file_path,
                'a',
                encoding='utf-8',
                errors='replace') as flip:
            flip.write(data)
