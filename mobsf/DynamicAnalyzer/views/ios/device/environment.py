# -*- coding: utf_8 -*-
"""iOS Device Environment for Dynamic Analysis."""

import io
import logging
import plistlib
import time
from pathlib import Path

from django.conf import settings

from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.views.common.frida.server_update import (
    FridaServerUpdater,
)

logger = logging.getLogger(__name__)


class IOSEnvironment:
    """iOS Device Environment for Dynamic Analysis."""

    def __init__(self, ios_device):
        """Initialize iOS Environment with device operations.

        Args:
            ios_device: IOSDevice instance
        """
        self.ios_device = ios_device
        self.connector = ios_device.connector
        self.frida_server_path = None
        self.frida_process = None
        self.frida_plist_path = None
        self.platform = None
        self.platform_architecture = self.ios_device.get_platform_architecture()

    def _find_frida_server_plist(self):
        """Find Frida server plist file on iOS device."""
        if self.frida_plist_path:
            return self.frida_plist_path

        try:
            # Common locations where Frida server plist might be installed
            plist_locations = [
                '/Library/LaunchDaemons/re.frida.server.plist',
                '/var/jb/Library/LaunchDaemons/re.frida.server.plist',
                '/System/Library/LaunchDaemons/re.frida.server.plist',
            ]

            for plist_path in plist_locations:
                output, _, exit_code = self.ios_device.execute_command(
                    f'ls -la {plist_path}',
                )

                if exit_code == 0 and 'No such file' not in output:
                    self.frida_plist_path = plist_path
                    return plist_path

            # If not found in common locations, search for it
            logger.info('Searching for Frida server plist files...')
            output, _, exit_code = self.ios_device.execute_command(
                'find / -name "*frida*server*.plist" 2>/dev/null',
            )

            if exit_code == 0 and output.strip():
                plist_files = output.strip().split('\n')
                for plist_file in plist_files:
                    if plist_file.strip():
                        self.frida_plist_path = plist_file.strip()
                        return plist_file.strip()

            logger.warning('No Frida server plist file found')
            return None

        except Exception:
            logger.exception('[ERROR] Finding Frida server plist')
            return None

    def _install_frida_server_on_device(self):
        """Install Frida server on iOS device."""
        try:
            logger.info('Installing Frida Server v%s on iOS device', frida_version)

            # Upload the binary to the device
            success = self.ios_device.upload_file(
                self.frida_server_path,
                '/tmp/fd.deb',
            )

            if not success:
                raise Exception(
                    'Failed to upload Frida server v%s binary to device', frida_version)

            success = self.ios_device.install_deb('/tmp/fd.deb')
            if not success:
                raise Exception(
                    'Failed to install Frida server v%s on device', frida_version)
            return True

        except Exception:
            logger.exception(
                '[ERROR] Installing Frida server v%s on iOS device', frida_version)
        return False

    def _modify_frida_plist_for_wifi(self):
        """Modify Frida server plist to enable WiFi access using plistlib."""
        try:
            self._find_frida_server_plist()
            if not self.frida_plist_path:
                logger.error('No Frida plist path available')
                return False

            logger.info('Modifying Frida plist for WiFi access')
            # Read as raw bytes — handles both XML and binary plist formats.
            # read_file() would fail on binary plists due to UTF-8 decoding.
            plist_bytes = self.ios_device.read_binary_file(self.frida_plist_path)
            if not plist_bytes:
                raise Exception('Failed to read Frida plist')

            # Quick check for already-patched XML plist (avoids re-parsing)
            if (b'<string>-l</string>' in plist_bytes
                    and b'<string>0.0.0.0</string>' in plist_bytes):
                logger.info('WiFi arguments already present in plist')
                return True

            # plistlib.loads() handles both XML and binary plist formats
            plist = plistlib.loads(plist_bytes)
            args = plist.get('ProgramArguments', [])
            if '-l' not in args:
                args.append('-l')
            if '0.0.0.0' not in args:
                args.append('0.0.0.0')
            plist['ProgramArguments'] = args
            logger.info('Added -l 0.0.0.0 to ProgramArguments')

            # Serialize back to XML and upload in-memory
            updated_bytes = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
            plist_name = Path(self.frida_plist_path).name
            plist_dir = str(Path(self.frida_plist_path).parent) + '/'
            self.ios_device.upload_file_object(
                io.BytesIO(updated_bytes), plist_name, plist_dir)

            logger.info('Successfully modified Frida plist for WiFi access')
            return True

        except Exception:
            logger.exception('[ERROR] Modifying Frida plist for WiFi access')
        return False

    def _enable_frida_on_wifi(self):
        """Enable Frida on WiFi."""
        try:
            logger.info('Enabling Frida Server v%s on 0.0.0.0', frida_version)
            self._find_frida_server_plist()
            if not self.frida_plist_path:
                raise ValueError('Frida server plist not found')

            # Modify the plist to add WiFi arguments
            if not self._modify_frida_plist_for_wifi():
                raise ValueError('Failed to modify plist for WiFi access')

            # Reload the modified plist
            self.start_frida_server()
            logger.info(
                'Successfully started Frida Server v%s on (0.0.0.0)', frida_version)
            return True

        except Exception:
            logger.exception(
                '[ERROR] Enabling Frida Server v%s on 0.0.0.0', frida_version)
        return False

    def setup_or_start_frida(self):
        """Setup and start Frida server for iOS device."""
        try:
            # Check if setup is already done
            if self.ios_device.read_file('/tmp/frida_setup_done') == frida_version:
                self.start_frida_server()
                logger.info(
                    'Successfully started Frida Server v%s on (0.0.0.0)', frida_version)
                return True

            # Get iOS platform architecture
            if not self.platform_architecture:
                raise ValueError('Failed to determine iOS platform architecture')

            logger.info('iOS platform architecture identified as %s',
                        self.platform_architecture)

            # Update/download Frida server
            platform = 'iphoneos'
            frida_bin = (
                f'frida_{frida_version}_{platform}-{self.platform_architecture}.deb')
            self.frida_server_path = Path(settings.DWD_DIR) / frida_bin
            if not self.frida_server_path.is_file():
                # Download Frida server binary if not found
                updater = FridaServerUpdater(platform, frida_version)
                success = updater.update_frida_server(
                    self.platform_architecture,
                )
                if not success:
                    msg = (
                        'Cannot download frida binary for iOS. You will need'
                        f' {frida_bin} in {settings.DWD_DIR}'
                        ' for Dynamic Analysis to work')
                    raise ValueError(msg)

            # install frida server on device
            self._install_frida_server_on_device()

            # Enable and start Frida on WiFi
            self._enable_frida_on_wifi()

            # Install oslog on device
            self.install_oslog()

            # Create a file to indicate that frida setup is done
            self.ios_device.write_file('/tmp/frida_setup_done', frida_version)
            return True
        except Exception:
            logger.exception('[ERROR] Setting up Frida for iOS')
            return False

    def start_frida_server(self):
        """Start Frida Server on iOS device using launchctl."""
        try:
            self.stop_frida_server()
            # Load and start the Frida server using launchctl
            output, _, exit_code = self.ios_device.execute_command(
                f'launchctl load {self.frida_plist_path}',
            )

            if exit_code != 0:
                raise ValueError('Failed to load Frida server plist')

            # Wait for the server to start
            logger.info('Waiting for Frida server to start...')

            # Verify the server is running
            output, _, exit_code = self.ios_device.execute_command(
                'ps aux | grep frida-server | grep -v grep',
            )

            if exit_code != 0:
                # Attempt to start the server using the binary
                _, error, exit_code = self.ios_device.execute_command(
                    'frida-server -l 0.0.0.0 &',
                )
                if exit_code != 0:
                    raise ValueError(
                        f'Failed to start Frida server using binary: {error}',
                    )
                output, _, exit_code = self.ios_device.execute_command(
                    'ps aux | grep frida-server | grep -v grep',
                )
            time.sleep(1)
            if exit_code == 0 and output.strip():
                logger.info('Frida Server started successfully')
                return True
            else:
                raise Exception('Frida Server failed to start')

        except Exception:
            logger.exception('[ERROR] Running Frida server on iOS device')
        return False

    def stop_frida_server(self):
        """Stop Frida server on iOS device using launchctl."""
        try:
            self._find_frida_server_plist()
            if not self.frida_plist_path:
                raise Exception('Frida server plist not found')

            # Unload the plist using launchctl
            output, error, exit_code = self.ios_device.execute_command(
                f'launchctl unload {self.frida_plist_path}',
            )

            if exit_code == 0:
                logger.info('Successfully stopped Frida server')
            else:
                logger.warning('Failed to stop Frida server: %s', error)

            # Also kill any remaining Frida server processes as fallback
            _, error, exit_code = self.ios_device.execute_command(
                'pkill -f frida-server',
            )

            if exit_code == 0:
                logger.info('Killed remaining Frida server processes')

            return True
        except Exception:
            logger.exception('[ERROR] Stopping Frida server')
        return False

    def install_oslog(self):
        """Install oslog on iOS device."""
        try:
            logger.info('Installing oslog on iOS device')
            if not self.platform_architecture:
                raise ValueError('Failed to determine iOS platform architecture')
            tools_dir = Path(settings.TOOLS_DIR) / 'ios' / 'oslog'
            if self.platform_architecture == 'arm64':
                oslog_bin = 'oslog_0.0.4.3_iphoneos-arm64.deb'
            else:
                oslog_bin = 'oslog_0.0.1-8_iphoneos-arm.deb'
            deb_file = tools_dir / oslog_bin
            if not deb_file.exists():
                raise ValueError('oslog deb file does not exist: %s', deb_file)
            remote_path = '/tmp/oslog.deb'
            self.ios_device.upload_file(deb_file, remote_path)
            if not self.ios_device.install_deb(remote_path):
                raise ValueError('Failed to install oslog on device')
            return True
        except Exception:
            logger.exception('[ERROR] Installing oslog on iOS device')
        return False
