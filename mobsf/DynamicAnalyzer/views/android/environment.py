# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from base64 import b64encode
from hashlib import md5, sha256

from django.conf import settings

from OpenSSL import crypto

import frida
from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_ca_file,
    start_proxy,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.common.frida.server_update import (
    FridaServerUpdater,
)
from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_android_path,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    get_adb,
    get_android_devices,
    get_device,
    get_proxy_ip,
    is_file_exists,
    python_list,
    strict_package_check,
    valid_android_device_identifier,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)
ANDROID_API_SUPPORTED = 30
_FRIDA_FORWARD_LOCK = threading.Lock()
_MOBSF_FRIDA_FORWARDS = {}
_DEVICE_PACKAGE_CACHE = {}
_DEVICE_PACKAGE_CACHE_LOCK = threading.Lock()
_DEVICE_PACKAGE_CACHE_TTL = 300
_DEVICE_NOT_PROVIDED = object()


@dataclass(frozen=True)
class DeviceProfile:
    """Properties used to select an Android preparation strategy."""

    identifier: str
    state: str
    transport: str
    runtime: str
    android_version: float
    sdk: int
    abi: str
    abis: tuple
    root_method: str = 'none'
    root_status: str = 'not_checked'
    selinux: str = 'unknown'
    writable_temp: bool = False

    @property
    def is_physical(self):
        return self.runtime == 'physical'

    @property
    def has_root(self):
        return self.root_method != 'none'


class Environment:

    def __init__(self, identifier=_DEVICE_NOT_PROVIDED):
        if identifier is _DEVICE_NOT_PROVIDED:
            self.identifier = get_device()
        elif isinstance(identifier, str) and identifier.strip():
            self.identifier = identifier.strip()
        else:
            raise ValueError('No Android device selected')
        if (self.identifier
                and not valid_android_device_identifier(self.identifier)):
            raise ValueError('Invalid Android device identifier')
        self.tools_dir = settings.TOOLS_DIR
        self.frida_str = f'MobSF-Frida-{frida_version}'.encode('utf-8')
        self.xposed_str = b'MobSF-Xposed'
        self.root_method = 'none'
        self.root_status = 'not_checked'
        self._profile = None
        self._android_properties = None
        self._runtime = None

    def wait(self, sec):
        """Wait in Seconds."""
        if sec > 0:
            logger.info('Waiting for %s seconds...', str(sec))
            time.sleep(sec)

    def check_connect_error(self, output):
        """Check if connect failed."""
        if b'unable to connect' in output or b'failed to connect' in output:
            logger.error('%s', output.decode('utf-8').replace('\n', ''))
            return False
        return True

    def connect_network_device(self):
        """Connect the validated network ADB target."""
        try:
            out = subprocess.check_output(
                [get_adb(), 'connect', self.identifier],
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            logger.warning('Unable to connect to the Android ADB target')
            return False
        self.wait(2)
        return self.check_connect_error(out)

    def restart_adbd_as_root(self):
        """Restart adbd as root on a validated analysis target."""
        try:
            out = subprocess.check_output(
                [get_adb(), '-s', self.identifier, 'root'],
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            logger.warning('Android root ADB is unavailable')
            return False
        self.wait(2)
        return self.check_connect_error(out)

    def get_device_state(self):
        """Get the connection state of this device."""
        for device in get_android_devices():
            if device['identifier'] == self.identifier:
                return device['state']
        return 'disconnected'

    def is_network_device(self):
        """Check whether an identifier represents a network ADB target."""
        identifier = self.identifier or ''
        return (
            ':' in identifier
            or identifier.endswith('._adb-tls-connect._tcp')
        )

    def connect(self):
        """ADB Connect."""
        if not self.identifier:
            return False
        state = self.get_device_state()
        if state == 'device':
            return True
        if state in ('offline', 'unauthorized', 'no permissions'):
            logger.error(
                'Android device %s is %s',
                self.identifier,
                state,
            )
            return False
        if not self.is_network_device():
            logger.error('Android USB device %s is disconnected',
                         self.identifier)
            return False
        logger.info('Connecting to Android %s', self.identifier)
        if not self.connect_network_device():
            return False
        state = self.get_device_state()
        if state != 'device':
            logger.error(
                'Android device %s is %s',
                self.identifier,
                state,
            )
            return False
        return True

    def connect_n_mount(self):
        """Test ADB Connection."""
        if not self.identifier:
            return False
        if not self.connect():
            return False
        runtime = self.get_environment()
        if runtime == 'physical':
            profile = self.get_device_profile(probe_root=True)
            if not profile.has_root:
                logger.error(
                    'Physical Android root is %s. '
                    'Use Frida Gadget mode for a stock device.',
                    profile.root_status,
                )
                return False
            if not profile.writable_temp:
                logger.error(
                    '/data/local/tmp is not writable on the Android device')
                return False
            logger.info(
                'Using %s root on physical Android device',
                profile.root_method,
            )
            return True
        logger.info('Restarting ADB Daemon as root')
        if not self.restart_adbd_as_root():
            return False
        if self.is_network_device():
            logger.info('Reconnecting to Android Device')
            if not self.connect_network_device():
                return False
        logger.info('Remounting')
        self.adb_command(['remount'])
        logger.info('Performing System check')
        if not self.system_check(runtime):
            return False
        return True

    def get_device_profile(self, probe_root=False):
        """Collect stable properties used by dynamic analysis."""
        state = self.get_device_state()
        if state != 'device':
            raise RuntimeError(
                f'Android device {self.identifier} is {state}')
        transport = 'network' if self.is_network_device() else 'usb'
        root_method = 'none'
        root_status = 'not_checked'
        writable_temp = False
        if probe_root:
            root_method, root_status = self.probe_root()
            writable = self.adb_command(
                ['test', '-w', '/data/local/tmp'],
                True,
                True,
                timeout=5,
            )
            writable_temp = writable is not None
        selinux = self.adb_command(
            ['getenforce'], True, True) or b'unknown'
        profile = DeviceProfile(
            identifier=self.identifier,
            state=state,
            transport=transport,
            runtime=self.get_environment(),
            android_version=self.get_android_version(),
            sdk=int(self.get_android_sdk()),
            abi=self.get_android_arch(),
            abis=self.get_android_abis(),
            root_method=root_method,
            root_status=root_status,
            selinux=selinux.decode('utf-8', 'ignore').strip().lower(),
            writable_temp=writable_temp,
        )
        self._profile = profile
        return profile

    def is_package_installed(self, package, extra):
        """Check if package is installed."""
        success = '\nSuccess' in extra
        out = self.adb_command(['pm', 'list', 'packages'], True)
        pkg = f'{package}'.encode('utf-8')
        pkg_fmts = [pkg + b'\n', pkg + b'\r\n', pkg + b'\r\r\n']
        if any(pkg in out for pkg in pkg_fmts):
            # Windows uses \r\n and \r\r\n
            return True
        if success:
            # Fallback check
            return True
        return False

    def install_apk(
            self, apk_path, package, reinstall, modify_verifier=True):
        """Install APK and Verify Installation."""
        if self.is_package_installed(package, '') and reinstall != '0':
            logger.info('Removing existing installation')
            # Remove existing installation'
            self.adb_command(['uninstall', package], False, True)
        if modify_verifier:
            # Legacy VM images require install verification to be disabled.
            self.adb_command([
                'settings',
                'put',
                'global',
                'verifier_verify_adb_installs',
                '0',
            ], True)
        logger.info('Installing APK - %s', package)
        install_args = ['install', '-r', '-t', '-d']
        try:
            if int(self.get_android_sdk()) >= 34:
                install_args.append('--bypass-low-target-sdk-block')
        except (TypeError, ValueError):
            pass
        install_args.append(apk_path)
        output = self.adb_command(
            install_args,
            silent=True,
            timeout=settings.BINARY_ANALYSIS_TIMEOUT,
        )
        if output is None:
            message = (
                'adb install timed out'
                if self.adb_timed_out else 'adb install failed'
            )
            return False, message
        out = output.decode('utf-8', 'ignore')
        # Verify Installation
        return self.is_package_installed(package, out), out

    def install_apks(
            self, apk_paths, package, reinstall, modify_verifier=True):
        """Install and verify one complete split APK set."""
        paths = [Path(path).resolve() for path in apk_paths]
        upload_root = Path(settings.UPLD_DIR).resolve()
        valid_paths = []
        for path in paths:
            try:
                relative = path.relative_to(upload_root).as_posix()
            except ValueError:
                return False, 'Invalid split APK set'
            valid_paths.append(
                path.is_file()
                and not is_pipe_or_link(path)
                and path.suffix.lower() == '.apk'
                and is_safe_path(upload_root, path, relative),
            )
        if len(paths) < 2 or not all(valid_paths):
            return False, 'Invalid split APK set'
        if self.is_package_installed(package, '') and reinstall != '0':
            logger.info('Removing existing installation')
            self.adb_command(['uninstall', package], silent=True)
        if modify_verifier:
            self.adb_command([
                'settings',
                'put',
                'global',
                'verifier_verify_adb_installs',
                '0',
            ], True)
        logger.info('Installing %d APK splits - %s', len(paths), package)
        install_args = ['install-multiple', '-r', '-t', '-d']
        try:
            if int(self.get_android_sdk()) >= 34:
                install_args.append('--bypass-low-target-sdk-block')
        except (TypeError, ValueError):
            pass
        install_args.extend(path.as_posix() for path in paths)
        output = self.adb_command(
            install_args,
            silent=True,
            timeout=settings.BINARY_ANALYSIS_TIMEOUT,
        )
        if output is None:
            message = (
                'adb install-multiple timed out'
                if self.adb_timed_out else 'adb install-multiple failed'
            )
            return False, message
        out = output.decode('utf-8', 'ignore')
        return self.is_package_installed(package, out), out

    def has_package(self, package):
        """Check an exact package without changing device state."""
        result = self.adb_command(
            ['pm', 'path', package],
            True,
            True,
            timeout=10,
        )
        return bool(
            result and result.strip().startswith(b'package:'))

    def uninstall_package(self, package):
        """Uninstall a package after explicit analyst confirmation."""
        logger.info(
            'Uninstalling existing Android package after confirmation')
        result = self.adb_command(
            ['uninstall', package],
            silent=True,
            timeout=settings.BINARY_ANALYSIS_TIMEOUT,
        )
        if result is None:
            if self.adb_timed_out:
                logger.error('Timed out uninstalling Android package')
            return False
        success = (
            b'Success' in result
            and not self.has_package(package)
        )
        if success:
            logger.info('Existing Android package was uninstalled')
        else:
            logger.error('Existing Android package uninstall failed')
        return success

    def adb_command(
            self, cmd_list, shell=False, silent=False, timeout=None):
        """ADB Command wrapper."""
        args = [get_adb(),
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list
        self.adb_timed_out = False
        try:
            result = subprocess.check_output(  # lgtm[py/command-line-injection]
                args,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
            return result
        except subprocess.TimeoutExpired:
            self.adb_timed_out = True
            if not silent:
                logger.error('ADB command timed out')
            return None
        except subprocess.CalledProcessError as exp:
            if not silent:
                output = (exp.output or b'').decode('utf-8', 'ignore')
                logger.error(
                    'ADB command failed with exit status %s: %s',
                    exp.returncode,
                    sanitize_for_logging(output.strip()[:500]) or 'no output',
                )
            return None
        except Exception:
            if not silent:
                logger.exception('Error Running ADB Command')
            return None

    def probe_root(self):
        """Detect a non-interactive root command without assumptions."""
        logger.info('Probing Android root capabilities')
        self.root_method = 'none'
        self.root_status = 'unavailable'
        try:
            direct = self.adb_command(
                ['id'], True, True, timeout=5)
            if direct and b'uid=0' in direct:
                self.root_method = 'adbd'
                self.root_status = 'available'
                logger.info('Android root is available through root ADB')
                return self.root_method, self.root_status
            has_su = self.adb_command(
                ['command', '-v', 'su'], True, True, timeout=5)
            if not has_su or not has_su.strip():
                logger.info('Android root is unavailable')
                return self.root_method, self.root_status
            probes = (
                ('su-c', ['su', '-c', 'id']),
                ('su-uid', ['su', '0', 'id']),
            )
            for method, command in probes:
                result = self.adb_command(
                    command, True, True, timeout=5)
                if self.adb_timed_out:
                    self.root_status = 'interactive'
                    logger.warning(
                        'Android root requires interactive authorization')
                    return self.root_method, self.root_status
                if result and b'uid=0' in result:
                    self.root_method = method
                    self.root_status = 'available'
                    logger.info(
                        'Android root is available through %s',
                        method,
                    )
                    return self.root_method, self.root_status
            self.root_status = 'denied'
            logger.warning('Android root authorization was denied')
        except Exception:
            logger.exception('Failed to probe Android root capabilities')
            self.root_status = 'error'
        return self.root_method, self.root_status

    def supports_root_adbd(self):
        """Check whether a VM advertises or already uses root ADB."""
        identity = self.adb_command(
            ['id'], True, True, timeout=5)
        if identity and b'uid=0' in identity:
            return True
        return self.get_android_properties().get(
            'ro.debuggable') == '1'

    def root_command(self, cmd_list, timeout=30, silent=False):
        """Run a fixed command with the detected root capability."""
        if self.root_status == 'not_checked':
            self.probe_root()
        if self.root_method == 'none':
            if not silent:
                logger.error('Android root is %s', self.root_status)
            return None
        try:
            root_cmd = shlex.join(str(item) for item in cmd_list)
            if self.root_method == 'adbd':
                remote_command = root_cmd
            elif self.root_method == 'su-c':
                remote_command = f'su -c {shlex.quote(root_cmd)}'
            else:
                remote_command = (
                    f'su 0 sh -c {shlex.quote(root_cmd)}')
            result = subprocess.run(  # lgtm[py/command-line-injection]
                [
                    get_adb(),
                    '-s',
                    self.identifier,
                    'shell',
                    remote_command,
                ],
                capture_output=True,
                check=False,
                timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout
            if not silent:
                logger.error(
                    'Root command failed: %s',
                    result.stderr.decode('utf-8', 'ignore').strip(),
                )
        except subprocess.TimeoutExpired:
            if not silent:
                logger.error('Root command timed out')
        except Exception:
            if not silent:
                logger.exception('Root command failed')
        return None

    def dz_cleanup(self, bin_hash):
        """Clean up before Dynamic Analysis."""
        # Delete ScreenStream Cache
        screen_file = os.path.join(settings.SCREEN_DIR, 'screen.png')
        if os.path.exists(screen_file):
            os.remove(screen_file)
        # Delete Contents of Screenshot Dir
        screen_dir = os.path.join(
            settings.UPLD_DIR, bin_hash + '/screenshots-apk/')
        if os.path.isdir(screen_dir):
            shutil.rmtree(screen_dir)
        else:
            os.makedirs(screen_dir)

    def configure_proxy(self, project, request, install_ca=True):
        """HTTPS Proxy."""
        if not install_ca:
            logger.info('Using the MobSF Root CA embedded in the Gadget APK')
        elif self.get_environment() == 'physical':
            logger.warning(
                'MobSF Root CA was not installed automatically on the '
                'physical Android device')
        else:
            self.install_mobsf_ca('install')
        proxy_port = settings.PROXY_PORT
        logger.info('Starting HTTPS Proxy on %s', proxy_port)
        stop_httptools()
        start_proxy(proxy_port, project)

    def install_mobsf_ca(self, action):
        """Install or Remove MobSF Root CA."""
        mobsf_ca = get_ca_file()
        ca_file = None
        if is_file_exists(mobsf_ca):
            ca_construct = '{}.0'
            pem = open(mobsf_ca, 'rb')
            ca_obj = crypto.load_certificate(crypto.FILETYPE_PEM, pem.read())
            md = md5(ca_obj.get_subject().der()).digest()
            ret = (md[0] | (md[1] << 8) | (md[2] << 16) | md[3] << 24)
            ca_file_hash = hex(ret).lstrip('0x')
            ca_file = os.path.join('/system/etc/security/cacerts/',
                                   ca_construct.format(ca_file_hash))
            pem.close()
        else:
            logger.warning('mitmproxy root CA is not generated yet.')
            return
        if action == 'install':
            logger.info('Installing MobSF RootCA')
            self.adb_command(['push',
                              mobsf_ca,
                              ca_file])
            self.adb_command(['chmod',
                              '644',
                              ca_file], True)
        elif action == 'remove':
            logger.info('Removing MobSF RootCA')
            self.adb_command(['rm',
                              ca_file], True)
        # with a high timeout afterwards

    def set_global_proxy(self, version):
        """Set Global Proxy on device."""
        # Android 4.4+ supported
        proxy_ip = None
        proxy_port = settings.PROXY_PORT
        if version < 5:
            proxy_ip = get_proxy_ip(self.identifier)
        else:
            proxy_ip = settings.PROXY_IP
        if proxy_ip:
            if version < 4.4:
                logger.warning('Please set Android VM proxy as %s:%s',
                               proxy_ip, proxy_port)
                return
            logger.info('Setting Global Proxy for Android VM')
            self.adb_command(
                ['settings',
                 'put',
                 'global',
                 'http_proxy',
                 '{}:{}'.format(proxy_ip, proxy_port)], True)

    def get_mobsf_proxy(self, version):
        """Return the proxy value MobSF applies for this Android version."""
        proxy_ip = (
            get_proxy_ip(self.identifier)
            if version < 5 else settings.PROXY_IP
        )
        if not proxy_ip:
            return ''
        return f'{proxy_ip}:{settings.PROXY_PORT}'

    def unset_global_proxy(self):
        """Clear all global proxy settings on the device."""
        logger.info('Removing Global Proxy for Android VM')
        for name in ('http_proxy',
                     'global_http_proxy_host',
                     'global_http_proxy_port',
                     'global_http_proxy_exclusion_list',
                     'global_proxy_pac_url'):
            self.adb_command(
                ['settings', 'delete', 'global', name],
                True,
                timeout=10)
        # Some apps keep using the old proxy unless :0 is published.
        self.adb_command(
            ['settings', 'put', 'global', 'http_proxy', ':0'],
            True,
            timeout=10)

    def clear_proxy(self):
        """Best-effort removal of all MobSF proxy state on the device."""
        self.unset_global_proxy()
        self.disable_adb_reverse_tcp()

    def get_global_proxy(self):
        """Read the current global HTTP proxy without changing it."""
        output = self.adb_command([
            'settings',
            'get',
            'global',
            'http_proxy',
        ], True, True, timeout=10)
        if not output:
            return ''
        value = output.decode('utf-8', 'ignore').strip()
        if value in ('null', ':0'):
            return ''
        return value

    def enable_adb_reverse_tcp(self, version):
        """Enable ADB Reverse TCP for Proxy."""
        # Androd 5+ supported
        if not version >= 5:
            return False
        proxy_port = settings.PROXY_PORT
        logger.info('Enabling ADB Reverse TCP on %s', proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        result = self.adb_command(
            ['reverse', '--no-rebind', tcp, tcp],
            silent=True,
            timeout=10,
        )
        if result is None:
            logger.error('Failed to enable ADB reverse for the proxy')
            return False
        return True

    def disable_adb_reverse_tcp(self):
        """Remove the proxy reverse created by MobSF."""
        tcp = f'tcp:{settings.PROXY_PORT}'
        self.adb_command(
            ['reverse', '--remove', tcp],
            silent=True,
            timeout=10,
        )

    def has_adb_reverse_tcp(self):
        """Check whether the MobSF proxy reverse already exists."""
        tcp = f'tcp:{settings.PROXY_PORT}'
        return self.get_adb_reverse_target() == tcp

    def get_adb_reverse_target(self):
        """Return the host target using MobSF's device proxy port."""
        tcp = f'tcp:{settings.PROXY_PORT}'
        output = self.adb_command(
            ['reverse', '--list'],
            silent=True,
        )
        if not output:
            return False
        for line in output.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-2] == tcp:
                return parts[-1]
        return None

    def start_clipmon(self):
        """Start Clipboard Monitoring."""
        logger.info('Starting Clipboard Monitor')
        args = ['am', 'startservice',
                'opensecurity.clipdump/.ClipDumper']
        self.adb_command(args, True)

    def screen_shot(self, outfile):
        """Take Screenshot."""
        output = self.adb_command(
            ['exec-out', 'screencap', '-p'],
            silent=True,
        )
        if not output:
            return False
        Path(outfile).write_bytes(output)
        return True

    def screen_stream(self):
        """Screen Stream."""
        out = self.adb_command(
            ['exec-out', 'screencap', '-p'],
            silent=True,
        )
        if out:
            return b64encode(out).decode('utf-8')
        return ''

    def android_component(self, bin_hash, comp):
        """Get APK Components."""
        try:
            anddb = StaticAnalyzerAndroid.objects.get(MD5=bin_hash)
            resp = []
            if comp == 'activities':
                resp = python_list(anddb.ACTIVITIES)
            elif comp == 'receivers':
                resp = python_list(anddb.RECEIVERS)
            elif comp == 'providers':
                resp = python_list(anddb.PROVIDERS)
            elif comp == 'services':
                resp = python_list(anddb.SERVICES)
            elif comp == 'libraries':
                resp = python_list(anddb.LIBRARIES)
            elif comp == 'exported_activities':
                resp = python_list(anddb.EXPORTED_ACTIVITIES)
            return '\n'.join(resp)
        except Exception:
            return 'Static Analysis not done.'

    def get_environment(self):
        """Identify the environment."""
        if self._runtime:
            return self._runtime
        values = self.get_android_properties()
        if not values:
            # Unreadable properties must not be cached as a real device.
            return 'physical'
        combined = '\n'.join(values.values()).lower()
        hardware = values.get('ro.hardware', '').lower()
        genymotion_version = values.get(
            'ro.genymotion.version', '')
        if ('genymotion' in combined
                or any(char.isdigit() for char in genymotion_version)):
            logger.info('Found Genymotion Android VM')
            self._runtime = 'genymotion'
        elif 'corellium' in combined:
            logger.info('Found Corellium ARM Android VM')
            self._runtime = 'corellium'
        elif ('emulator' in combined
                or 'generic_x86' in combined
                or values.get('ro.kernel.qemu') == '1'
                or values.get('ro.boot.qemu') == '1'):
            logger.info('Found Android Studio Emulator')
            self._runtime = 'emulator'
        elif (hardware in ('goldfish', 'ranchu', 'cutf_cvm')
                or hardware.startswith('android_x86')
                or 'waydroid' in combined
                or 'cuttlefish' in combined):
            logger.info('Found Android VM')
            self._runtime = 'emulator'
        else:
            self._runtime = 'physical'
        return self._runtime

    def get_android_properties(self):
        """Read and cache the Android property map in one ADB call."""
        if self._android_properties is not None:
            return self._android_properties
        logger.info('Reading Android device properties')
        properties = {}
        output = self.adb_command(['getprop'], True, True, timeout=30)
        if output:
            for line in output.decode('utf-8', 'ignore').splitlines():
                match = re.match(r'^\[([^\]]+)\]: \[(.*)\]$', line)
                if match:
                    properties[match.group(1)] = match.group(2)
        self._android_properties = properties
        return properties

    def get_android_version(self):
        """Get Android version."""
        and_version = self.get_android_properties().get(
            'ro.build.version.release', '')
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        return float(and_version)

    def get_android_arch(self):
        """Get Android Architecture."""
        return self.get_android_properties().get(
            'ro.product.cpu.abi', '')

    def get_android_abis(self):
        """Return Android-supported ABIs in preference order."""
        properties = self.get_android_properties()
        abilist = properties.get('ro.product.cpu.abilist', '')
        abis = [
            abi.strip() for abi in abilist.split(',')
            if abi.strip()
        ]
        primary = self.get_android_arch()
        if primary and primary not in abis:
            abis.insert(0, primary)
        return tuple(abis)

    def get_android_sdk(self):
        """Get Android API version."""
        return self.get_android_properties().get(
            'ro.build.version.sdk', '')

    def get_device_packages(self, refresh=False):
        """Get all packages from device."""
        now = time.monotonic()
        with _DEVICE_PACKAGE_CACHE_LOCK:
            cached = _DEVICE_PACKAGE_CACHE.get(self.identifier)
            if (not refresh
                    and cached
                    and now - cached['created'] < _DEVICE_PACKAGE_CACHE_TTL):
                logger.info(
                    'Using cached Android package inventory (%d apps)',
                    len(cached['packages']),
                )
                return cached['packages']
        logger.info(
            'Hashing installed Android applications. '
            'This may take several seconds on a physical device.')
        started = time.monotonic()
        device_packages = {}
        script = (
            'pm list packages -f -3 | while IFS= read -r entry; do '
            'apk=${entry#package:}; package=${apk##*=}; apk=${apk%=*}; '
            'checksum=$(md5sum "$apk" 2>/dev/null | cut -d" " -f1); '
            'printf "%s\\t%s\\t%s\\n" "$checksum" "$package" "$apk"; '
            'done'
        )
        out = self.adb_command([script], True, True)
        if not out:
            logger.warning('Android package inventory returned no data')
            return device_packages
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split('\t', 2)
            if len(parts) != 3:
                continue
            checksum, package, apk = parts
            if (not re.fullmatch(r'[a-fA-F0-9]{32}', checksum)
                    or package == 'opensecurity.clipdump'
                    or not re.fullmatch(r'[A-Za-z][\w.-]{1,255}', package)
                    or not apk.startswith('/data/app/')):
                continue
            device_packages[checksum.lower()] = (package, apk)
        with _DEVICE_PACKAGE_CACHE_LOCK:
            _DEVICE_PACKAGE_CACHE[self.identifier] = {
                'created': now,
                'packages': device_packages,
            }
        logger.info(
            'Loaded %d installed Android applications in %.1f seconds',
            len(device_packages),
            time.monotonic() - started,
        )
        return device_packages

    def download_apk_packages(self, apk_paths, out_file):
        """Download APK package(s)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_files = []
            for index, apk_path in enumerate(apk_paths):
                filename = apk_path.name
                destination = Path(temp_dir) / filename
                if destination.exists():
                    destination = (
                        Path(temp_dir) / f'{index}-{filename}')
                out = self.adb_command([
                    'pull',
                    apk_path.as_posix(),
                    destination.as_posix(),
                ], silent=True)
                if out is None:
                    logger.error('Failed to pull an installed APK')
                    return False
                logger.info(
                    'Pulled installed APK %d of %d',
                    index + 1,
                    len(apk_paths),
                )
                if (destination.is_file()
                        and not destination.is_symlink()):
                    apk_files.append(destination)
            if not apk_files:
                return False
            if len(apk_files) == 1:
                shutil.move(apk_files[0], out_file)
                return 'apk'
            with zipfile.ZipFile(
                    out_file, 'w', compression=zipfile.ZIP_STORED) as archive:
                for apk_file in apk_files:
                    archive.write(apk_file, apk_file.name)
            return 'apks'

    def get_apk_packages(self, package):
        """Get all APK packages from device."""
        out = self.adb_command([
            'pm',
            'path',
            package], True)
        return out.decode('utf-8').strip()

    def get_apk_paths(self, package):
        """Get validated APK paths for an installed package."""
        package_out = self.get_apk_packages(package)
        apk_paths = []
        for line in package_out.splitlines():
            if not line.startswith('package:'):
                continue
            raw_path = line.split('package:', 1)[1].strip()
            if (not is_safe_android_path(raw_path)
                    or not re.fullmatch(
                        r'/data/app/[A-Za-z0-9_./=~+-]+\.apk',
                        raw_path)):
                logger.warning('Ignoring unsafe installed APK path')
                continue
            apk_paths.append(Path(raw_path))
        return apk_paths

    def get_apk(self, checksum, package):
        """Download APK from device."""
        try:
            # Do not download if already exists
            out_dir = Path(settings.UPLD_DIR) / checksum
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f'{checksum}.apk'
            if out_file.exists():
                try:
                    with zipfile.ZipFile(out_file) as archive:
                        names = archive.namelist()
                        nested_apks = [
                            name for name in names
                            if name.lower().endswith('.apk')
                        ]
                        if (nested_apks
                                and 'AndroidManifest.xml' not in names):
                            return 'apks'
                except zipfile.BadZipFile:
                    pass
                return 'apk'
            apk_paths = self.get_apk_paths(package)
            if apk_paths:
                # Download APK package(s)
                logger.info('Downloading APK')
                return self.download_apk_packages(apk_paths, out_file)
        except Exception:
            logger.exception('Failed to download APK')
        return False

    def archive_app_data(self, package, output_file):
        """Archive application data when the selected device permits it."""
        if (not isinstance(package, str)
                or not strict_package_check(package)):
            logger.error('Invalid package for application data archive')
            return 'failed'
        upload_root = Path(settings.UPLD_DIR).resolve()
        output_path = Path(output_file)
        try:
            raw_output = output_path.resolve().relative_to(
                upload_root).as_posix()
        except (OSError, ValueError):
            logger.error('Application data archive path is outside uploads')
            return 'failed'
        if (is_pipe_or_link(output_path)
                or not is_safe_path(
                    upload_root, output_path, raw_output)):
            logger.error('Unsafe application data archive path')
            return 'failed'
        archive = f'/data/local/tmp/mobsf-{package}.tar'
        runtime = self.get_environment()
        try:
            if runtime == 'physical':
                if self.root_status == 'not_checked':
                    self.probe_root()
                if self.root_method == 'none':
                    return 'unsupported'
                if self.root_command([
                        'tar', '-cf', archive,
                        '-C', '/data/data', package,
                ], timeout=120) is None:
                    return 'failed'
                if self.root_command(
                        ['chmod', '644', archive], silent=True) is None:
                    return 'failed'
            else:
                identity = self.adb_command(
                    ['id'], True, True, timeout=5)
                if not identity or b'uid=0' not in identity:
                    return 'unsupported'
                result = self.adb_command([
                    'tar', '-cf', archive,
                    '-C', '/data/data', package,
                ], True)
                if result is None:
                    return 'failed'
            pulled = self.adb_command(
                ['pull', archive, output_path.as_posix()],
                silent=True,
            )
            return 'ok' if pulled is not None else 'failed'
        finally:
            if runtime == 'physical':
                self.root_command(['rm', '-f', archive], silent=True)
            else:
                self.adb_command(
                    ['rm', '-f', archive], True, True)

    def system_check(self, runtime):
        """Check if /system is writable."""
        try:
            try:
                api = self.get_android_sdk()
                if api:
                    logger.info('Android API Level '
                                'identified as %s', api)
                    if int(api) > ANDROID_API_SUPPORTED:
                        logger.error('This API Level is not supported'
                                     ' for Dynamic Analysis.')
                        return False
            except Exception:
                pass
            err_msg = ('VM\'s /system is not writable. '
                       'This VM cannot be used for '
                       'Dynamic Analysis.')
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier,
                                     'shell',
                                     'touch',
                                     '/system/test'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'Read-only' in stderr:
                logger.error(err_msg)
                if runtime == 'emulator':
                    logger.error('Please start the AVD as per '
                                 'MobSF documentation!')
                return False
        except Exception:
            logger.exception('System check failed')
            logger.error(err_msg)
            return False
        return True

    def launch_n_capture(self, package, activity, outfile):
        """Launch and Capture Activity."""
        self.adb_command(['am',
                          'start',
                          '-n',
                          package + '/' + activity], True)
        sleep = getattr(settings, 'ACTIVITY_TESTER_SLEEP', 3)
        self.wait(sleep)
        self.screen_shot(outfile)
        logger.info('Activity screenshot captured')

    def run_app(self, package):
        """Launch an app with package name."""
        monkey = self.adb_command([
            'monkey',
            '-p',
            package,
            '-c',
            'android.intent.category.LAUNCHER',
            '1',
        ], True, True, timeout=30)
        if monkey is not None:
            return True
        logger.warning(
            'Monkey could not launch the Android app; '
            'resolving its launcher activity')
        launcher = self.adb_command([
            'cmd',
            'package',
            'resolve-activity',
            '--brief',
            '-a',
            'android.intent.action.MAIN',
            '-c',
            'android.intent.category.LAUNCHER',
            package,
        ], True, True, timeout=10)
        if launcher is None:
            logger.error('Unable to resolve the Android launcher activity')
            return False
        component = launcher.decode(
            'utf-8', 'ignore').strip().splitlines()[-1]
        if not re.fullmatch(
                r'[A-Za-z][\w.-]+/\.?[A-Za-z][\w.$-]+',
                component):
            logger.error('Android launcher activity is invalid')
            return False
        launched = self.adb_command(
            ['am', 'start', '-n', component],
            True,
            True,
            timeout=30,
        )
        if launched is None:
            logger.error('Unable to launch the Android app')
            return False
        return True

    def is_mobsfyied(self, android_version):
        """Check is Device is MobSFyed."""
        logger.info('Environment MobSFyed Check')
        if android_version < 5:
            agent_file = '.mobsf-x'
            agent_str = self.xposed_str
        else:
            agent_file = '.mobsf-f'
            agent_str = self.frida_str
        if self.get_environment() == 'physical':
            marker = f'/data/local/tmp/mobsf/{agent_file}'
            out = self.root_command(['cat', marker], silent=True)
            return bool(out and agent_str in out)
        try:
            out = subprocess.check_output(
                [get_adb(),
                 '-s', self.identifier,
                 'shell',
                 'cat',
                 '/system/' + agent_file])
            if agent_str not in out:
                return False
        except Exception:
            return False
        return True

    def mobsfy_init(self):
        """Init MobSFy."""
        version = self.get_android_version()
        logger.info('Android Version identified as %s', version)
        try:
            if self.get_environment() == 'physical':
                if self.root_status == 'not_checked':
                    self.probe_root()
                if self.root_method == 'none':
                    logger.error(
                        'Physical Android root is %s',
                        self.root_status,
                    )
                    return False
                if not self.frida_setup(rooted=True):
                    return False
                if not self.write_physical_agent_marker():
                    return False
                logger.info('Rooted Android device preparation completed')
                return version
            if version < 5:
                self.xposed_setup(version)
                self.mobsf_agents_setup('xposed')
            else:
                if not self.frida_setup():
                    return False
                self.mobsf_agents_setup('frida')
            logger.info('MobSFying Completed!')
            return version
        except Exception:
            logger.exception('Failed to MobSFy Android Instance')
            return False

    def mobsf_agents_setup(self, agent):
        """Setup MobSF agents."""
        # Install MITM RootCA
        self.install_mobsf_ca('install')
        if agent == 'frida':
            agent_file = '.mobsf-f'
            agent_str = self.frida_str
        else:
            agent_file = '.mobsf-x'
            agent_str = self.xposed_str
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(agent_str)
        f.close()
        self.adb_command(['push', f.name, '/system/' + agent_file])
        os.unlink(f.name)

    def write_physical_agent_marker(self):
        """Write a version marker without modifying the system partition."""
        marker = '/data/local/tmp/mobsf/.mobsf-f'
        tmp_marker = '/data/local/tmp/mobsf-frida-marker'
        marker_file = tempfile.NamedTemporaryFile(delete=False)
        try:
            marker_file.write(self.frida_str)
            marker_file.close()
            if not self.adb_command(
                    ['push', marker_file.name, tmp_marker], silent=True):
                return False
            return self.root_command([
                'mv', tmp_marker, marker,
            ], silent=True) is not None
        finally:
            marker_file.close()
            os.unlink(marker_file.name)

    def xposed_setup(self, android_version):
        """Setup Xposed."""
        xposed_dir = 'onDevice/xposed/'
        xposed_modules = xposed_dir + 'modules/'
        # Install MobSF Agents for Xposed
        clip_dump_apk = os.path.join(self.tools_dir,
                                     xposed_dir,
                                     'ClipDump.apk')
        logger.info('Installing MobSF Clipboard Dumper')
        self.adb_command(['install', '-r', clip_dump_apk])
        if android_version < 5:
            logger.info('Installing Xposed for Kitkat and below')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'Xposed.apk')
            hooks = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'hooks.json')
            droidmon = os.path.join(self.tools_dir,
                                    xposed_modules,
                                    'Droidmon.apk')
            logger.info('Installing Droidmon API Analyzer')
            self.adb_command(['install', '-r', droidmon])
            logger.info('Copying Droidmon hooks config')
            self.adb_command(['push', hooks, '/data/local/tmp/'])
        else:
            logger.info('Installing Xposed for Lollipop and above')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'XposedInstaller_3.1.5.apk')
        self.adb_command(['install', '-r', xposed_apk])
        # Xposed Modules and Support Files
        justrustme = os.path.join(self.tools_dir,
                                  xposed_modules,
                                  'JustTrustMe.apk')
        rootcloak = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'com.devadvance.rootcloak2_v18_c43b61.apk')
        proxyon = os.path.join(self.tools_dir,
                               xposed_modules,
                               'mobi.acpm.proxyon_v1_419b04.apk')
        sslunpin = os.path.join(self.tools_dir,
                                xposed_modules,
                                'mobi.acpm.sslunpinning_v2_37f44f.apk')
        bluepill = os.path.join(self.tools_dir,
                                xposed_modules,
                                'AndroidBluePill.apk')
        logger.info('Installing JustTrustMe')
        self.adb_command(['install', '-r', justrustme])
        logger.info('Installing SSLUnpinning')
        self.adb_command(['install', '-r', sslunpin])
        logger.info('Installing ProxyOn')
        self.adb_command(['install', '-r', proxyon])
        logger.info('Installing RootCloak')
        self.adb_command(['install', '-r', rootcloak])
        logger.info('Installing Android BluePill')
        self.adb_command(['install', '-r', bluepill])
        logger.info('Launching Xposed Framework.')
        xposed_installer = ('de.robv.android.xposed.installer/'
                            'de.robv.android.xposed.installer.'
                            'WelcomeActivity')
        self.adb_command(['am', 'start', '-n',
                          xposed_installer], True)

    def frida_setup(self, rooted=False):
        """Setup Frida."""
        frida_arch = None
        arch = self.get_android_arch()
        logger.info('Android OS architecture identified as %s', arch)
        if arch in ['armeabi-v7a', 'armeabi']:
            frida_arch = 'arm'
        elif arch == 'arm64-v8a':
            frida_arch = 'arm64'
        elif arch == 'x86':
            frida_arch = 'x86'
        elif arch == 'x86_64':
            frida_arch = 'x86_64'
        else:
            logger.error('Unsupported Android architecture: %s', arch)
            return False
        frida_bin = f'frida-server-{frida_version}-android-{frida_arch}'
        stat = FridaServerUpdater(
            'android', frida_version).update_frida_server(frida_arch)
        if not stat:
            msg = ('Cannot download frida-server binary. You will need'
                   f' {frida_bin} in {settings.DWD_DIR} for '
                   'Dynamic Analysis to work')
            logger.error(msg)
            return False
        frida_path = os.path.join(settings.DWD_DIR, frida_bin)
        logger.info('Copying frida server v%s for %s', frida_version, frida_arch)
        if rooted:
            temp_path = '/data/local/tmp/mobsf-fd-server'
            target_dir = '/data/local/tmp/mobsf'
            target_path = f'{target_dir}/fd_server'
            if self.root_command(
                    ['mkdir', '-p', target_dir], silent=True) is None:
                return False
            self.root_command(
                ['pkill', '-f', target_path], silent=True)
            if not self.adb_command(
                    ['push', frida_path, temp_path], silent=True):
                return False
            if self.root_command([
                    'mv', temp_path, target_path], silent=True) is None:
                return False
            if self.root_command([
                    'chmod', '700', target_path], silent=True) is None:
                return False
        else:
            self.adb_command(
                ['pkill', '-f', '/system/fd_server'], True, True)
            if not self.adb_command(
                    ['push', frida_path, '/system/fd_server']):
                return False
            if self.adb_command(
                    ['chmod', '755', '/system/fd_server'], True) is None:
                return False
        return True

    def run_frida_server(self):
        """Start Frida Server."""
        runtime = self.get_environment()
        if runtime == 'physical':
            if self.root_status == 'not_checked':
                self.probe_root()
            if self.root_method == 'none':
                logger.error('Android root is %s', self.root_status)
                return False
            server = '/data/local/tmp/mobsf/fd_server'
            running = self.root_command(
                ['pidof', 'fd_server'], timeout=5, silent=True)
            if running:
                logger.info(
                    'Frida Server v%s is already running',
                    frida_version,
                )
                return True
            started = self.root_command(
                [server, '-D'], timeout=10, silent=True)
            if started is None:
                logger.error(
                    'Unable to start Frida server; execution may be '
                    'blocked by device policy or SELinux')
                return False
            self.wait(2)
            running = self.root_command(
                ['pidof', 'fd_server'], timeout=5, silent=True)
            if not running:
                logger.error('Frida server exited during startup')
                return False
            logger.info('Started Frida Server v%s', frida_version)
            return True
        running = self.adb_command(
            ['pidof', 'fd_server'], True, True)
        if running and running.strip():
            logger.info('Frida Server v%s is already running', frida_version)
            return True

        def start_frida():
            fnull = open(os.devnull, 'w')
            argz = [get_adb(),
                    '-s',
                    self.identifier,
                    'shell',
                    '/system/fd_server']
            subprocess.call(argz, stdout=fnull, stderr=subprocess.STDOUT)
        trd = threading.Thread(target=start_frida)
        trd.daemon = True
        trd.start()
        logger.info('Starting Frida Server v%s', frida_version)
        logger.info('Waiting for 2 seconds...')
        time.sleep(2)
        running = self.adb_command(
            ['pidof', 'fd_server'], True, True)
        if not running or not running.strip():
            logger.error(
                'Frida Server exited during startup. '
                'Use Frida Gadget mode for this Android runtime.')
            return False
        return True

    def stop_frida_server(self):
        """Stop a running Frida server."""
        running = self.adb_command(
            ['pidof', 'fd_server'], True, True, timeout=5)
        if not running or not running.strip():
            return True
        logger.info('Stopping Frida Server')
        if self.get_environment() == 'physical':
            if self.root_status == 'not_checked':
                self.probe_root()
            if self.root_method == 'none':
                logger.error(
                    'Unable to stop the running Frida server; '
                    'Android root is unavailable')
                return False
            self.root_command(
                ['pkill', '-f', 'fd_server'], timeout=5, silent=True)
        else:
            self.adb_command(
                ['pkill', '-f', 'fd_server'], True, True, timeout=5)
        running = self.adb_command(
            ['pidof', 'fd_server'], True, True, timeout=5)
        if running and running.strip():
            logger.error('Unable to stop the Frida server')
            return False
        return True

    def stop_physical_frida_server(self):
        """Best-effort stop of the root Frida server on a physical device."""
        try:
            if self.get_environment() == 'physical':
                return self.stop_frida_server()
        except Exception:
            logger.exception('Unable to stop Frida server')
            return False
        return True

    def _frida_forward_state_file(self):
        """Return the persistent ownership record for this device."""
        digest = sha256(self.identifier.encode('utf-8')).hexdigest()
        return (
            Path(settings.DWD_DIR)
            / f'android-frida-forward-{digest}.json'
        )

    def _read_frida_forward_state(self):
        """Read a validated MobSF-owned Frida forward."""
        state_file = self._frida_forward_state_file()
        if not state_file.is_file() or state_file.is_symlink():
            return None
        try:
            state = json.loads(state_file.read_text(encoding='utf-8'))
        except (OSError, ValueError, TypeError):
            return None
        if (not isinstance(state, dict)
                or state.get('identifier') != self.identifier):
            return None
        local = state.get('local')
        if (not isinstance(local, str)
                or not re.fullmatch(r'tcp:[1-9]\d{0,4}', local)
                or int(local.split(':', 1)[1]) > 65535):
            return None
        return local

    def _save_frida_forward_state(self, local):
        """Persist exact forward ownership across worker processes."""
        state_file = self._frida_forward_state_file()
        state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                state_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._read_frida_forward_state()
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            json.dump({
                'identifier': self.identifier,
                'local': local,
            }, target)
        return local

    def get_frida_device(self, gadget=False):
        """Return a Frida device for the selected Android transport."""
        if not gadget and self.get_environment() != 'physical':
            return frida.get_device(
                self.identifier,
                settings.FRIDA_TIMEOUT,
            )
        remote = 'tcp:27042'
        with _FRIDA_FORWARD_LOCK:
            if self.get_device_state() != 'device':
                raise RuntimeError(
                    'Android device is disconnected')
            forwards = self.adb_command(
                ['forward', '--list'],
                silent=True,
            ) or b''
            local = None
            state_file = self._frida_forward_state_file()
            persisted_local = self._read_frida_forward_state()
            if (persisted_local is None
                    and state_file.is_file()
                    and not state_file.is_symlink()):
                state_file.unlink(missing_ok=True)
            owned_local = (
                persisted_local
                or _MOBSF_FRIDA_FORWARDS.get(self.identifier)
            )
            for line in forwards.decode('utf-8', 'ignore').splitlines():
                parts = line.split()
                if (len(parts) >= 3
                        and parts[0] == self.identifier
                        and parts[1] == owned_local
                        and parts[2] == remote):
                    local = parts[1]
                    break
            if not local:
                if owned_local:
                    stale_state = self._frida_forward_state_file()
                    if (stale_state.is_file()
                            and not stale_state.is_symlink()):
                        stale_state.unlink(missing_ok=True)
                    _MOBSF_FRIDA_FORWARDS.pop(
                        self.identifier, None)
                for attempt in range(1, 4):
                    result = self.adb_command(
                        ['forward', 'tcp:0', remote],
                        silent=True,
                        timeout=10,
                    )
                    assigned = (
                        result.decode('utf-8', 'ignore').strip()
                        if result else ''
                    )
                    if (assigned.isdigit()
                            and 0 < int(assigned) < 65536):
                        local = f'tcp:{assigned}'
                        recorded = self._save_frida_forward_state(local)
                        if recorded and recorded != local:
                            self.adb_command(
                                ['forward', '--remove', local],
                                silent=True,
                            )
                            local = recorded
                        elif not recorded:
                            self.adb_command(
                                ['forward', '--remove', local],
                                silent=True,
                            )
                            raise RuntimeError(
                                'Unable to record Frida forward ownership')
                        _MOBSF_FRIDA_FORWARDS[self.identifier] = local
                        logger.info(
                            'Forwarded Frida for Android device on '
                            'local TCP port %s',
                            local.rsplit(':', 1)[1],
                        )
                        break
                    logger.warning(
                        'ADB Frida forwarding attempt %d failed',
                        attempt,
                    )
                    self.wait(1)
                if not local:
                    raise RuntimeError(
                        'Unable to forward the physical-device Frida port')
            port = local.rsplit(':', 1)[1]
            frida_host = '127.0.0.1'
            adb_socket = os.getenv('ADB_SERVER_SOCKET', '')
            socket_match = re.fullmatch(
                r'tcp:(\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9.-]+):\d{1,5}',
                adb_socket,
            )
            if socket_match:
                frida_host = socket_match.group(1)
                if frida_host in ('localhost', '127.0.0.1'):
                    frida_host = '127.0.0.1'
        return frida.get_device_manager().add_remote_device(
            f'{frida_host}:{port}')

    def remove_frida_forward(self):
        """Remove the Frida port forward created by MobSF."""
        with _FRIDA_FORWARD_LOCK:
            state_file = self._frida_forward_state_file()
            memory_local = _MOBSF_FRIDA_FORWARDS.pop(
                self.identifier, None)
            local = (
                self._read_frida_forward_state()
                or memory_local
            )
            if local:
                self.adb_command(
                    ['forward', '--remove', local],
                    silent=True,
                )
                forwards = self.adb_command(
                    ['forward', '--list'],
                    silent=True,
                ) or b''
                for line in forwards.decode(
                        'utf-8', 'ignore').splitlines():
                    parts = line.split()
                    if (len(parts) >= 2
                            and parts[0] == self.identifier
                            and parts[1] == local):
                        return False
            if state_file.is_file() and not state_file.is_symlink():
                state_file.unlink(missing_ok=True)
            return True
