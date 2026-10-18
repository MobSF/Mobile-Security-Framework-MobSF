# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from base64 import b64encode
from hashlib import md5

from django.conf import settings

from OpenSSL import crypto

import frida
from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_ca_file,
    get_http_tools_url,
    start_proxy,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.common.frida.server_update import (
    FridaServerUpdater,
)
from mobsf.MobSF.utils import (
    get_adb,
    get_android_devices,
    get_device,
    get_proxy_ip,
    is_file_exists,
    python_list,
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

    def __init__(self, identifier=None):
        if identifier:
            self.identifier = identifier.strip()
        else:
            self.identifier = get_device()
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
            writable = self.adb_command_result(
                ['test', '-w', '/data/local/tmp'], True, 5)
            writable_temp = writable.returncode == 0
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
        try:
            result = self.adb_command_result(
                install_args,
                timeout=settings.BINARY_ANALYSIS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return False, 'adb install timed out'
        output = result.stdout + result.stderr
        out = output.decode('utf-8', 'ignore')
        if result.returncode != 0:
            return False, out or 'adb install failed'
        # Verify Installation
        return self.is_package_installed(package, out), out

    def has_package(self, package):
        """Check an exact package without changing device state."""
        result = self.adb_command_result(
            ['pm', 'path', package],
            shell=True,
            timeout=10,
        )
        return (
            result.returncode == 0
            and result.stdout.strip().startswith(b'package:')
        )

    def uninstall_package(self, package):
        """Uninstall a package after explicit analyst confirmation."""
        logger.info(
            'Uninstalling existing Android package after confirmation')
        try:
            result = self.adb_command_result(
                ['uninstall', package],
                timeout=settings.BINARY_ANALYSIS_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error('Timed out uninstalling Android package')
            return False
        success = (
            result.returncode == 0
            and b'Success' in result.stdout + result.stderr
            and not self.has_package(package)
        )
        if success:
            logger.info('Existing Android package was uninstalled')
        else:
            logger.error('Existing Android package uninstall failed')
        return success

    def adb_command(self, cmd_list, shell=False, silent=False):
        """ADB Command wrapper."""
        args = [get_adb(),
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list
        try:
            result = subprocess.check_output(
                args,  # lgtm [py/command-line-injection]
                stderr=subprocess.STDOUT)
            return result
        except Exception:
            if not silent:
                logger.exception('Error Running ADB Command')
            return None

    def adb_command_result(self, cmd_list, shell=False, timeout=30):
        """Run an ADB command and retain its status and output."""
        args = [get_adb(), '-s', self.identifier]
        if shell:
            args.append('shell')
        args.extend(cmd_list)
        return subprocess.run(
            args,  # lgtm [py/command-line-injection]
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    def probe_root(self):
        """Detect a non-interactive root command without assumptions."""
        logger.info('Probing Android root capabilities')
        self.root_method = 'none'
        self.root_status = 'unavailable'
        try:
            direct = self.adb_command_result(['id'], True, 5)
            if direct.returncode == 0 and b'uid=0' in direct.stdout:
                self.root_method = 'adbd'
                self.root_status = 'available'
                logger.info('Android root is available through root ADB')
                return self.root_method, self.root_status
            has_su = self.adb_command_result(
                ['command', '-v', 'su'], True, 5)
            if has_su.returncode != 0 or not has_su.stdout.strip():
                logger.info('Android root is unavailable')
                return self.root_method, self.root_status
            probes = (
                ('su-c', ['su', '-c', 'id']),
                ('su-uid', ['su', '0', 'id']),
            )
            for method, command in probes:
                try:
                    result = self.adb_command_result(command, True, 5)
                except subprocess.TimeoutExpired:
                    self.root_status = 'interactive'
                    logger.warning(
                        'Android root requires interactive authorization')
                    return self.root_method, self.root_status
                if result.returncode == 0 and b'uid=0' in result.stdout:
                    self.root_method = method
                    self.root_status = 'available'
                    logger.info(
                        'Android root is available through %s',
                        method,
                    )
                    return self.root_method, self.root_status
            self.root_status = 'denied'
            logger.warning('Android root authorization was denied')
        except subprocess.TimeoutExpired:
            self.root_status = 'interactive'
            logger.warning('Android root capability probe timed out')
        except Exception:
            logger.exception('Failed to probe Android root capabilities')
            self.root_status = 'error'
        return self.root_method, self.root_status

    def supports_root_adbd(self):
        """Check whether a VM advertises or already uses root ADB."""
        try:
            identity = self.adb_command_result(['id'], True, 5)
            if (identity.returncode == 0
                    and b'uid=0' in identity.stdout):
                return True
        except subprocess.TimeoutExpired:
            return False
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
            if self.root_method == 'adbd':
                command = cmd_list
            elif self.root_method == 'su-c':
                root_cmd = shlex.join(str(item) for item in cmd_list)
                command = ['su', '-c', root_cmd]
            else:
                command = ['su', '0', *cmd_list]
            result = self.adb_command_result(command, True, timeout)
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
        stop_httptools(get_http_tools_url(request))
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
        """Unset Global Proxy on device."""
        logger.info('Removing Global Proxy for Android VM')
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'http_proxy'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_host'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_port'], True)
        self.adb_command(
            ['settings',
             'put',
             'global',
             'http_proxy',
             ':0'], True)

    def get_global_proxy(self):
        """Read the current global HTTP proxy without changing it."""
        output = self.adb_command([
            'settings',
            'get',
            'global',
            'http_proxy',
        ], True, True)
        if not output:
            return ''
        value = output.decode('utf-8', 'ignore').strip()
        if value in ('null', ':0'):
            return ''
        return value

    def restore_global_proxy(self, value):
        """Restore a previously recorded global HTTP proxy."""
        results = []
        if value:
            results.append(self.adb_command([
                'settings',
                'put',
                'global',
                'http_proxy',
                value,
            ], True))
        else:
            results.append(self.adb_command([
                'settings',
                'delete',
                'global',
                'http_proxy',
            ], True))
            results.append(self.adb_command([
                'settings',
                'delete',
                'global',
                'global_http_proxy_host',
            ], True))
            results.append(self.adb_command([
                'settings',
                'delete',
                'global',
                'global_http_proxy_port',
            ], True))
            # Publish Android's canonical no-proxy value. Some apps retain
            # the previous proxy when the setting is only deleted.
            results.append(self.adb_command([
                'settings',
                'put',
                'global',
                'http_proxy',
                ':0',
            ], True))
        restored = (
            all(result is not None for result in results)
            and self.get_global_proxy() == value
        )
        if restored:
            logger.info('Restored the previous Android proxy setting')
        else:
            logger.error('Failed to restore the previous Android proxy')
        return restored

    def enable_adb_reverse_tcp(self, version):
        """Enable ADB Reverse TCP for Proxy."""
        # Androd 5+ supported
        if not version >= 5:
            return
        proxy_port = settings.PROXY_PORT
        logger.info('Enabling ADB Reverse TCP on %s', proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        try:
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier,
                                     'reverse', tcp, tcp],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'error: closed' in stderr:
                logger.warning('ADB Reverse TCP works only on'
                               ' Android 5.0 and above. Please '
                               'configure a reachable IP Address'
                               ' in Android proxy settings.')
            elif stderr:
                logger.error(stderr.decode('utf-8').replace('\n', ''))
        except Exception:
            logger.exception('Enabling ADB Reverse TCP')

    def disable_adb_reverse_tcp(self):
        """Remove the proxy reverse created by MobSF."""
        tcp = f'tcp:{settings.PROXY_PORT}'
        self.adb_command(
            ['reverse', '--remove', tcp],
            silent=True,
        )

    def has_adb_reverse_tcp(self):
        """Check whether the MobSF proxy reverse already exists."""
        tcp = f'tcp:{settings.PROXY_PORT}'
        output = self.adb_command(
            ['reverse', '--list'],
            silent=True,
        )
        if not output:
            return False
        for line in output.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-2:] == [tcp, tcp]:
                return True
        return False

    def start_clipmon(self):
        """Start Clipboard Monitoring."""
        logger.info('Starting Clipboard Monitor')
        args = ['am', 'startservice',
                'opensecurity.clipdump/.ClipDumper']
        self.adb_command(args, True)

    def screen_shot(self, outfile):
        """Take Screenshot."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/screen.png'], True, True)
        self.adb_command(['pull',
                          '/data/local/screen.png',
                          outfile], False, True)

    def screen_stream(self):
        """Screen Stream."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/stream.png'],
                         True, True)
        out = self.adb_command(['cat', '/data/local/stream.png'], True, True)
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
        values = self.get_android_properties()
        combined = '\n'.join(values.values()).lower()
        if 'genymotion' in combined:
            logger.info('Found Genymotion Android VM')
            return 'genymotion'
        elif 'corellium' in combined:
            logger.info('Found Corellium ARM Android VM')
            return 'corellium'
        elif ('emulator' in combined
                or 'generic_x86' in combined
                or values.get('ro.kernel.qemu') == '1'
                or values.get('ro.boot.qemu') == '1'):
            logger.info('Found Android Studio Emulator')
            return 'emulator'
        else:
            return 'physical'

    def get_android_properties(self):
        """Read and cache the Android property map in one ADB call."""
        if self._android_properties is not None:
            return self._android_properties
        logger.info('Reading Android device properties')
        properties = {}
        output = self.adb_command(['getprop'], True, True)
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

    def download_apk_packages(self, pkg_path, out_file):
        """Download APK package(s)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download APK package(s)
            # Can be single or multiple packages
            out = self.adb_command([
                'pull',
                pkg_path.as_posix(),
                temp_dir,
            ])
            fmt = out.decode('utf-8').strip()
            logger.info('ADB Pull Output: %s', fmt)
            # Filter for APK files in the directory
            apk_files = []
            for f in Path(temp_dir).glob('*.apk'):
                if f.is_file():
                    apk_files.append(f)
            # Check if there is exactly one APK file
            if len(apk_files) == 1:
                shutil.move(apk_files[0], out_file)
                return 'apk'
            else:
                # If there are multiple APK files, zip them
                shutil.make_archive(out_file, 'zip', root_dir=temp_dir, base_dir='.')
                # Rename the zip file to APK
                apks_file = out_file.with_suffix('.apk')
                os.rename(out_file.as_posix() + '.zip', apks_file)
                return 'apks'

    def get_apk_packages(self, package):
        """Get all APK packages from device."""
        out = self.adb_command([
            'pm',
            'path',
            package], True)
        return out.decode('utf-8').strip()

    def get_apk_parent_directory(self, package):
        """Get parent directory of APK packages."""
        package_out = self.get_apk_packages(package)
        package_out = package_out.split()
        if ('package:' in package_out[0]
                and package_out[0].endswith('.apk')):
            path = package_out[0].split('package:', 1)[1].strip()
            return Path(path).parent
        return False

    def get_apk(self, checksum, package):
        """Download APK from device."""
        try:
            # Do not download if already exists
            out_dir = Path(settings.UPLD_DIR) / checksum
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f'{checksum}.apk'
            if out_file.exists():
                return 'apk'
            # Get APK package parent directory
            pkg_path = self.get_apk_parent_directory(package)
            if pkg_path:
                # Download APK package(s)
                logger.info('Downloading APK')
                return self.download_apk_packages(pkg_path, out_file)
        except Exception:
            logger.exception('Failed to download APK')
        return False

    def archive_app_data(self, package, output_file):
        """Archive application data when the selected device permits it."""
        archive = f'/data/local/tmp/mobsf-{package}.tar'
        runtime = self.get_environment()
        try:
            if runtime == 'physical':
                if self.root_command([
                        'tar', '-cf', archive,
                        '-C', '/data/data', package,
                ], timeout=120) is None:
                    return False
                if self.root_command(
                        ['chmod', '644', archive], silent=True) is None:
                    return False
            else:
                result = self.adb_command([
                    'tar', '-cf', archive,
                    '-C', '/data/data', package,
                ], True)
                if result is None:
                    return False
            return self.adb_command(
                ['pull', archive, output_file],
                silent=True,
            ) is not None
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
        monkey = self.adb_command_result([
            'monkey',
            '-p',
            package,
            '-c',
            'android.intent.category.LAUNCHER',
            '1',
        ], True, 30)
        if monkey.returncode == 0:
            return True
        logger.warning(
            'Monkey could not launch the Android app; '
            'resolving its launcher activity')
        launcher = self.adb_command_result([
            'cmd',
            'package',
            'resolve-activity',
            '--brief',
            '-a',
            'android.intent.action.MAIN',
            '-c',
            'android.intent.category.LAUNCHER',
            package,
        ], True, 10)
        if launcher.returncode != 0:
            logger.error('Unable to resolve the Android launcher activity')
            return False
        component = launcher.stdout.decode(
            'utf-8', 'ignore').strip().splitlines()[-1]
        if not re.fullmatch(
                r'[A-Za-z][\w.-]+/\.?[A-Za-z][\w.$-]+',
                component):
            logger.error('Android launcher activity is invalid')
            return False
        launched = self.adb_command_result(
            ['am', 'start', '-n', component],
            True,
            30,
        )
        if launched.returncode != 0:
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
            for line in forwards.decode('utf-8', 'ignore').splitlines():
                parts = line.split()
                if (len(parts) >= 3
                        and parts[0] == self.identifier
                        and parts[2] == remote):
                    local = parts[1]
                    break
            if not local:
                for attempt in range(1, 4):
                    result = self.adb_command_result(
                        ['forward', 'tcp:0', remote],
                        timeout=10,
                    )
                    assigned = result.stdout.decode(
                        'utf-8', 'ignore').strip()
                    if (result.returncode == 0
                            and assigned.isdigit()
                            and 0 < int(assigned) < 65536):
                        local = f'tcp:{assigned}'
                        _MOBSF_FRIDA_FORWARDS[self.identifier] = local
                        logger.info(
                            'Forwarded Frida for Android device on '
                            'local TCP port %s',
                            assigned,
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
        return frida.get_device_manager().add_remote_device(
            f'127.0.0.1:{port}')

    def remove_frida_forward(self):
        """Remove the Frida port forward created by MobSF."""
        with _FRIDA_FORWARD_LOCK:
            local = _MOBSF_FRIDA_FORWARDS.pop(
                self.identifier, None)
            if local:
                self.adb_command(
                    ['forward', '--remove', local],
                    silent=True,
                )
