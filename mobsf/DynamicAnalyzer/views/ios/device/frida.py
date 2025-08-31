"""Frida Core Class for iOS Device."""
import logging
import time
import sys

import frida

from mobsf.DynamicAnalyzer.views.ios.frida_core import Frida
from mobsf.DynamicAnalyzer.views.ios.device.environment import IOSEnvironment

logger = logging.getLogger(__name__)
_PID = None

class FridaIOSDevice(Frida):
    """Frida iOS Device for Dynamic Analysis."""

    def __init__(self, ios_device, ssh_string, app_hash, bundle_id, defaults, dump, auxiliary, extras, code):
        """Initialize."""
        
        super().__init__(ssh_string, app_hash, bundle_id, defaults, dump, auxiliary, extras, code)
        self.connector = ios_device.connector
        self.env = IOSEnvironment(ios_device)
        self.api = None
        if self.connector.connection_type == 'usb':
            self.frida_device = frida.get_device_manager().add_remote_device(f'{self.connector.host}:37042')
        else:
            self.frida_device = frida.get_device_manager().add_remote_device(self.connector.host)

    
    def run_app(self):
        """Run the app with frida."""
        pid = None
        try:
            try:
                pid = self.frida_device.spawn([self.bundle_id])
                self.frida_device.resume(pid)
                logger.info('Spawned %s with PID %s', self.bundle_id, pid)
                return pid
            except frida.NotSupportedError:
                logger.error(self.not_supported_text)
                logger.info('Spawned %s with PID %s', self.bundle_id, pid)
                return pid
            except frida.ServerNotRunningError:
                self.env.start_frida_server()
                time.sleep(1)
                pid = self.frida_device.spawn([self.bundle_id])
                self.frida_device.resume(pid)
                logger.info('Spawned %s with PID %s', self.bundle_id, pid)
                return pid
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except frida.ServerNotRunningError:
            logger.error('Frida Server is not running')
        except frida.NotSupportedError:
            logger.error(self.not_supported_text)
        except (frida.ProcessNotFoundError,
                frida.ProcessNotRespondingError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Failed to run app')
        return None
    
    def spawn(self):
        """Connect to Frida Server and spawn the app."""
        global _PID
        try:
            try:
                self.clean_up()
                _PID = self.frida_device.spawn([self.bundle_id])
            except frida.NotSupportedError:
                logger.error(self.not_supported_text)
                return
            except frida.ServerNotRunningError:
                self.env.start_frida_server()
                _PID = None
            if not _PID:
                _PID = self.frida_device.spawn([self.bundle_id])
            logger.info('Spawned %s with PID %s', self.bundle_id, _PID)
            #time.sleep(2)
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except frida.ServerNotRunningError:
            logger.error('Frida Server is not running')
        except frida.NotSupportedError:
            logger.error(self.not_supported_text)
            return
        except (frida.ProcessNotFoundError,
                frida.ProcessNotRespondingError,
                frida.TransportError,
                frida.InvalidOperationError):
            pass
        except Exception:
            logger.exception('Error Connecting to Frida Server')

    def session(self, pid, bundle_id):
        """Use existing session to inject frida scripts."""
        global _PID
        try:
            try:
                if pid and bundle_id:
                    _PID = pid
                    self.bundle_id = bundle_id
                try:
                    front = self.frida_device.get_frontmost_application()
                    if front or front.pid != _PID:
                        # Not the front most app.
                        # Get the pid of the front most app
                        logger.warning('Front most app has PID %s', front.pid)
                        _PID = front.pid
                except Exception:
                    pass
                self.frida_device.resume(_PID)
                time.sleep(2)
                session = self.frida_device.attach(_PID)
            except frida.NotSupportedError:
                logger.error(self.not_supported_text)
                return
            except Exception:
                logger.warning('Cannot attach to pid, spawning again.')
                self.spawn()
                self.frida_device.resume(_PID)
                time.sleep(2)
                session = self.frida_device.attach(_PID)
            if session and self.frida_device and _PID:
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                self.api = script.exports_sync
                self.api_handler(self.api)
                sys.stdin.read()
                script.unload()
                session.detach()
        except frida.NotSupportedError:
            logger.error(self.not_supported_text)
        except (frida.ProcessNotFoundError,
                frida.ProcessNotRespondingError,
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
                processes = self.frida_device.enumerate_applications(scope='minimal')
            except frida.ServerNotRunningError:
                self.env.start_frida_server()
                processes = self.frida_device.enumerate_applications(scope='minimal')
            if self.frida_device and processes:
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
