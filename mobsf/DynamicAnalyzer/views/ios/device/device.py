# -*- coding: utf_8 -*-
"""iOS device operations using SSH connection."""

import logging
import hashlib
import platform
import subprocess
import base64
import tempfile
import shutil
import io
from pathlib import Path
import time
import plistlib

from django.conf import settings


logger = logging.getLogger(__name__)


class IOSDevice:
    """Handle iOS device operations using SSH connection."""

    def __init__(self, connector):
        """Initialize with an IOSConnector instance."""
        self.connector = connector

    def execute_command(self, command, timeout=30):
        """Execute a command on SSH client."""
        if not self.connector.ssh_client:
            return None, None, None
        
        return self.connector._ssh_execute_command(command, timeout)
    
    def ps(self):
        """Get the list of running processes."""
        if not self.connector.ssh_client:
            return None
        output, error, exit_code = self.execute_command('ps aux')
        if exit_code != 0:
            logger.error("Failed to get list of running processes: %s", error)
            return None
        
        # Parse ps aux output format
        processes = []
        lines = output.split('\n')
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                try:
                    # ps aux format: USER PID %CPU %MEM VSZ RSS TT STAT START TIME COMMAND
                    parts = line.split()
                    if len(parts) >= 11:
                        pid = parts[1]
                        command = ' '.join(parts[10:])
                        
                        # Only include processes with .app in the path (iOS applications)
                        if '.app/' in command:
                            # Extract app name from .app path
                            app_parts = command.split('.app/')
                            if app_parts:
                                app_path = app_parts[0]
                                app_name = app_path.split('/')[-1]
                                
                                processes.append({
                                    'pid': pid,
                                    'process_name': app_name
                                })
                except Exception as e:
                    logger.warning("Failed to parse process line: %s - %s", line, str(e))
                    continue
        
        return processes
    

    def get_cpu_architecture(self):
        """Get the device CPU architecture."""
        if not self.connector.ssh_client:
            return None
        
        try:
            err = "Failed to get device CPU architecture"
            output, error, exit_code = self.execute_command('arch')
            if exit_code != 0:
                logger.error("%s: %s", err, error)
                return None
            arch = output.strip()
            
            arch_mapping = {
                'arm64': 'arm64',           # iPhone 5s and later (A7+)
                'arm64e': 'arm64',          # iPhone XS and later (A12+)
                'armv7': 'arm',             # iPhone 4, 4S, 5, 5c
                'armv7s': 'arm',            # iPhone 5, 5c (optimized for Swift)
            }
            return arch_mapping.get(arch)
        

        except Exception:
            logger.exception(err)
        return None
    
    def get_platform_architecture(self):
        """Get the device platform architecture."""
        if not self.connector.ssh_client:
            return None
        
        try:
            err = "Failed to get device platform architecture"
            output, error, exit_code = self.execute_command('dpkg --print-architecture')
            if exit_code != 0:
                logger.error("%s: %s", err, error)
                return None
            arch = output.strip()
            
            if 'iphoneos-arm64' in arch:
                return 'arm64'
            return 'arm'
        except Exception:
            logger.exception(err)
        return None


    def upload_file(self, local_path, remote_path):
        """Upload a file to the iOS device."""
        if not self.connector.ssh_client:
            return False

        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                sftp.put(local_path, remote_path)
            logger.info("Uploaded %s to %s", local_path, remote_path)
            return True
        except Exception:
            logger.exception("Failed to upload file")
        return False
    
    def upload_file_object(self, fobject, filename, path='/tmp/'):
        """Upload a file object to the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            filename = Path(filename.replace('..', '')).name
            path = Path(path.replace('..', ''))
            remote_path = path / filename
            with self.connector.ssh_client.open_sftp() as sftp:
                sftp.putfo(fobject, str(remote_path))
            logger.info("Uploaded %s to %s", filename, str(remote_path))
            return True
        except Exception:
            logger.exception("Failed to upload file")
        return False

    def download_file(self, remote_path, local_path):
        """Download a file from the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                sftp.get(remote_path, local_path)
            logger.info("Downloaded %s to %s", remote_path, local_path)
            return True
        except FileNotFoundError:
            logger.error("File not found: %s", remote_path)
            return False
        except Exception:
            logger.exception("Failed to download file")
        return False
    
    def download_file_object(self, remote_path):
        """Return a file object from the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                with io.BytesIO() as buffer:
                    sftp.getfo(remote_path, buffer)
                    buffer.seek(0)
                    return buffer.read()
        except FileNotFoundError:
            logger.error("File not found: %s", remote_path)
            return False
        except Exception:
            logger.exception("Failed to download file")
        return False

    def write_file(self, remote_path, content):
        """Write a file to the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                with io.BytesIO(content.encode('utf-8')) as buffer:
                    sftp.putfo(buffer, remote_path)
            return True
        except Exception:
            logger.exception("Failed to write file")
        return False

    def read_file(self, remote_path):
        """Read a text file from the iOS device."""
        if not self.connector.ssh_client:
            return None
        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                with io.BytesIO() as buffer:
                    sftp.getfo(remote_path, buffer)
                    buffer.seek(0)
                    return buffer.read().decode('utf-8')
        except Exception:
            pass
        return None

    def read_binary_file(self, remote_path):
        """Read a binary file from the iOS device."""
        if not self.connector.ssh_client:
            return None
        try:
            with self.connector.ssh_client.open_sftp() as sftp:
                with io.BytesIO() as buffer:
                    sftp.getfo(remote_path, buffer)
                    buffer.seek(0)
                    return buffer.read()
        except Exception:
            logger.exception("Failed to read binary file")
        return None

    def install_deb(self, remote_path):
        """Install a deb file on the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            _, error, exit_code = self.execute_command(f'dpkg -i {remote_path}')
            if exit_code != 0:
                logger.error("Install failed in iOS device: %s", error)
                return False
            logger.info("Successfully installed deb file: %s", remote_path)
            return True
        except Exception:
            logger.exception("Failed to install deb file")
        return False
    
    def install_apt_package(self, package_name):
        """Install an apt package on the iOS device."""
        if not self.connector.ssh_client:
            return False
        try:
            _, error, exit_code = self.execute_command(f'apt-get install -y {package_name}')
            if exit_code != 0:
                logger.error("Install failed in iOS device: %s", error)
                return False
            logger.info("Successfully installed apt package: %s", package_name)
            return True
        except Exception:
            logger.exception("Failed to install apt package")
        return False

    def _appsync_install(self):
        """Check and install AppSync Unified."""
        check_install = 'apt list --installed | grep -E \'ai\.akemi\.app(inst|syncunified)\''
        out, _, _ = self.execute_command(check_install)
        if 'appsyncunified' in out or 'appinst' in out:
            return False
        
        # Install AppSync Unified
        logger.info('AppSync Unified is not installed. '
                    'Attempting to install...')
        # Method 1: Install AppSync Unified from deb file
        tools_dir = Path(settings.TOOLS_DIR) / 'ios' / 'appsync'
        if 'arm64' in self.get_platform_architecture():
            deb_file = tools_dir / 'ai.akemi.appsyncunified_116.0_iphoneos-arm64.akemi-git-235aca6cddfbdc9fa87fcb5b2aec2df37ed6d65a.deb'
        else:
            deb_file = tools_dir / 'ai.akemi.appsyncunified_116.0_iphoneos-arm.akemi-git-235aca6cddfbdc9fa87fcb5b2aec2df37ed6d65a.deb'
        if not deb_file.exists():
            raise Exception('AppSync Unified deb file does not exist: %s', deb_file)
        remote_path = '/tmp/appsync.deb'
        self.upload_file(deb_file, remote_path)
        self.install_apt_package('mobilesubstrate')
        if self.install_deb(remote_path):
            self.execute_command('launchctl reboot userspace')
            time.sleep(15)
            return True
        # Method 2: Install AppSync Unified from cydia.akemi.ai
        logger.info('Attempting to install AppSync Unified from cydia.akemi.ai')
        src_file = '/etc/apt/sources.list.d/cydia.list'
        src = 'deb https://cydia.akemi.ai/ ./'
        install_cmds = [
            f'grep -qxF \'{src}\' {src_file} || echo \'{src}\' >> {src_file}',
            'apt update',
            'apt install -y --allow-unauthenticated ai.akemi.appinst',
            'launchctl reboot userspace',
        ]
        for i in install_cmds:
            out, _, _ = self.execute_command(i)
            logger.info(out)
        logger.info('Please wait for 15 seconds for the userspace to reboot.')
        time.sleep(15)
        return True
    
    def install_ipa(self, checksum):
        """Install an IPA file on the iOS device."""
        if not self.connector.ssh_client:
            return False
        # Check if AppSync Unified is installed
        if self._appsync_install():
            logger.info('AppSync Unified is installed, please try again.')
            return False
        ipa_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.ipa'
        if not ipa_path.exists():
            logger.error("IPA file does not exist: %s", ipa_path)
            return False
        if not self.upload_file(ipa_path, f'/tmp/{checksum}.ipa'):
            logger.error("Failed to upload IPA file")
            return False
        out, error, exit_code = self.execute_command(f'appinst /tmp/{checksum}.ipa')
        self.execute_command(f'rm -f /tmp/{checksum}.ipa')
        if 'Successfully installed' in out:
            logger.info("Successfully installed IPA")
            return True
        if exit_code != 0:
            logger.error("Failed to install IPA: %s", error)
        else:
            logger.error("Failed to install IPA: %s", out)
        return False
    

    def list_applications(self):
        """List installed applications."""
        if not self.connector.ssh_client:
            return []
        logger.info("Listing applications on iOS device")
        classify = lambda path: "System" if path.startswith("/Applications/") else ("User" if "/var/containers/Bundle/Application" in path else "Other")
        checksum = lambda path: hashlib.md5(path.encode('utf-8')).hexdigest()
        bundle_ids = []
        try:
            sftp_client = self.connector.ssh_client.open_sftp()
            output, _, exit_code = self.execute_command(
                'uicache -l'
            )
            if exit_code == 0:
                for line in output.split('\n'):
                    if line.strip():
                        components = line.split(' : ')
                        bundle_id = components[0].strip()
                        app_path = components[1].strip()
                        app_name, app_icon = self.get_app_name(app_path, sftp_client)
                        bundle_ids.append({
                            'app_name': app_name,
                            'app_icon': self.get_app_icon(app_path, app_icon,  sftp_client),
                            'bundle_id': bundle_id,
                            'app_path': app_path,
                            'app_type': classify(app_path),
                        })
                sftp_client.close()
                return bundle_ids
            else:
                logger.error("Failed to get app details")
                return []
        except Exception:
            logger.exception("Failed to get app details")
            return []
        finally:
            if sftp_client:
                sftp_client.close()

    def get_app_name(self, app_path, sftp):
        """Get name of an app."""
        if not self.connector.ssh_client:
            return None
        try:
            plist_path = Path(app_path) / 'Info.plist'
            with io.BytesIO() as buffer:
                sftp.getfo(str(plist_path), buffer)
                buffer.seek(0)
                plist = plistlib.load(buffer)
            app_name = plist.get('CFBundleDisplayName') or plist.get('CFBundleName') or plist.get('CFBundleExecutable') or 'Unknown App'
            app_icon = None
            # First try modern nested structure
            try:
                icons = plist["CFBundleIcons"]["CFBundlePrimaryIcon"]["CFBundleIconFiles"]
                if isinstance(icons, list) and icons:
                    app_icon = icons[-1]  # Return the largest/resolution version
            except (KeyError, TypeError):
                pass
            if not app_icon:
                # Fallback to legacy key
                app_icon = plist.get("CFBundleIconFile", None)
            return app_name, app_icon
        except Exception:
            logger.exception("Failed to get app name")
        return None, None

    def _crush_png(self, icon_path):
        """Crush a png file."""
        try:
            tools_dir = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools' / 'ios'
            arch = platform.machine()
            system = platform.system()
            # Uncrush PNG. CgBI -> PNG
            # https://iphonedevwiki.net/index.php/CgBI_file_format
            if system == 'Darwin':
                args = ['xcrun', '-sdk', 'iphoneos', 'pngcrush', '-q',
                        '-revert-iphone-optimizations',
                        icon_path, icon_path + ".fixed"]
                try:
                    out = subprocess.run(args, capture_output=True)
                    if b'libpng error:' in out.stdout:
                        # PNG looks normal
                        raise ValueError('PNG is not CgBI')
                    shutil.move(icon_path + ".fixed", icon_path)
                except Exception:
                    pass
            else:
                # Windows/Linux
                cgbipng_bin = None
                if system == 'Windows' and arch in ('AMD64', 'x86'):
                    cgbipng_bin = 'CgbiPngFix.exe'
                elif system == 'Linux' and arch == 'x86_64':
                    cgbipng_bin = 'CgbiPngFix_amd64'
                elif system == 'Linux' and arch == 'aarch64':
                    cgbipng_bin = 'CgbiPngFix_arm64'
                if cgbipng_bin:
                    cbin = tools_dir / 'CgbiPngFix' / cgbipng_bin
                    args = [cbin.as_posix(), '-i',
                            icon_path, '-o', icon_path + ".fixed"]
                    try:
                        out = subprocess.run(args, capture_output=True)
                        shutil.move(icon_path + ".fixed", icon_path)
                    except Exception:
                        # Fails or PNG is not crushed
                       pass
                else:
                    logger.warning('CgbiPngFix not available for %s %s', system, arch)
        except Exception:
            logger.exception("Failed to crush png")
        return None

    def get_app_icon(self, app_path, app_icon, sftp):
        """Get app icon."""
        if not self.connector.ssh_client:
            return None
        temp_path = None
        try:
            if app_icon:
                # Use the provided icon name from Info.plist
                search_pattern = f'{app_icon}*.png'
            else:
                # Guess icon path
                search_pattern = 'AppIcon*.png'
            output, _, exit_code = self.execute_command(
                f'find "{app_path}" -iname "{search_pattern}"'
            )
            if exit_code == 0:
                if '.png' not in output:
                    return None
                for line in output.split('\n'):
                    if line.strip():
                        icon_path = Path(line.strip())
                        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                            temp_path = Path(temp_file.name)
                            sftp.get(str(icon_path), str(temp_path))
                            self._crush_png(str(temp_path))
                            return base64.b64encode(temp_path.read_bytes()).decode('utf-8')
        except Exception:
            logger.exception("Failed to get app icon")
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()
        return None