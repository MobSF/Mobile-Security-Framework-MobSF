# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from hashlib import md5

from django.conf import settings

from OpenSSL import crypto

from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.tools.webproxy import (
    create_ca,
    get_ca_file,
    get_http_tools_url,
    start_proxy,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.android import (
    frida_server_download as fserver,
)
from mobsf.MobSF.utils import (
    get_adb,
    get_device,
    get_proxy_ip,
    is_file_exists,
    python_list,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)
ANDROID_API_SUPPORTED = 30


class Environment:

    def __init__(self, identifier=None):
        if identifier:
            self.identifier = identifier
        else:
            self.identifier = get_device()
        self.tools_dir = settings.TOOLS_DIR
        self.frida_str = f'MobSF-Frida-{frida_version}'.encode('utf-8')
        self.xposed_str = b'MobSF-Xposed'

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

    def run_subprocess_verify_output(self, cmd, wait=2):
        """Run subprocess and verify execution."""
        out = subprocess.check_output(cmd)  # lgtm [py/command-line-injection]
        self.wait(wait)                        # adb shell is allowed
        return self.check_connect_error(out)

    def connect(self):
        """ADB Connect."""
        if not self.identifier:
            return False
        logger.info('Connecting to Android %s', self.identifier)
        self.run_subprocess_verify_output([get_adb(),
                                           'connect',
                                           self.identifier])

    def connect_n_mount(self):
        """Test ADB Connection."""
        if not self.identifier:
            return False
        self.adb_command(['kill-server'])
        self.adb_command(['start-server'])
        logger.info('ADB Restarted')
        self.wait(2)
        logger.info('Connecting to Android %s', self.identifier)
        if not self.run_subprocess_verify_output([get_adb(),
                                                 'connect',
                                                  self.identifier]):
            return False
        logger.info('Restarting ADB Daemon as root')
        if not self.run_subprocess_verify_output([get_adb(),
                                                  '-s',
                                                  self.identifier,
                                                  'root']):
            return False
        logger.info('Reconnecting to Android Device')
        # connect again with root adb
        if not self.run_subprocess_verify_output([get_adb(),
                                                  'connect',
                                                  self.identifier]):
            return False
        # identify environment
        runtime = self.get_environment()
        logger.info('Remounting')
        # Allow non supported environments also
        self.adb_command(['remount'])
        logger.info('Performing System check')
        if not self.system_check(runtime):
            return False
        return True

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

    def install_apk(self, apk_path, package, reinstall):
        """Install APK and Verify Installation."""
        if self.is_package_installed(package, '') and reinstall != '0':
            logger.info('Removing existing installation')
            # Remove existing installation'
            self.adb_command(['uninstall', package], False, True)
        # Disable install verification
        self.adb_command([
            'settings',
            'put',
            'global',
            'verifier_verify_adb_installs',
            '0',
        ], True)
        logger.info('Installing APK - %s', package)
        # Install APK
        out = self.adb_command([
            'install',
            '-r',
            '-t',
            '-d',
            apk_path], False, True)
        if not out:
            return False, 'adb install failed'
        out = out.decode('utf-8', 'ignore')
        # Verify Installation
        return self.is_package_installed(package, out), out

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

    def configure_proxy(self, project, request):
        """HTTPS Proxy."""
        self.install_mobsf_ca('install')
        proxy_port = settings.PROXY_PORT
        logger.info('Starting HTTPs Proxy on %s', proxy_port)
        httptools_url = get_http_tools_url(request)
        stop_httptools(httptools_url)
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

    def start_clipmon(self):
        """Start Clipboard Monitoring."""
        logger.info('Starting Clipboard Monitor')
        args = ['am', 'startservice',
                'opensecurity.clipdump/.ClipDumper']
        self.adb_command(args, True)

    def get_screen_res(self):
        """Get Screen Resolution of Android Instance."""
        logger.info('Getting screen resolution')
        try:
            resp = self.adb_command(['dumpsys', 'window'], True)
            scn_rgx = re.compile(r'mUnrestrictedScreen=\(0,0\) .*')
            scn_rgx2 = re.compile(r'mUnrestricted=\[0,0\]\[.*\]')
            match = scn_rgx.search(resp.decode('utf-8'))
            if match:
                screen_res = match.group().split(' ')[1]
                width, height = screen_res.split('x', 1)
                return width, height
            match = scn_rgx2.search(resp.decode('utf-8'))
            if match:
                res = match.group().split('][')[1].replace(']', '')
                width, height = res.split(',', 1)
                return width, height
            else:
                logger.error('Error getting screen resolution')
        except Exception:
            logger.exception('Getting screen resolution')
        return '1440', '2560'

    def screen_shot(self, outfile):
        """Take Screenshot."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/screen.png'], True)
        self.adb_command(['pull',
                          '/data/local/screen.png',
                          outfile])

    def screen_stream(self):
        """Screen Stream."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/stream.png'],
                         True)
        self.adb_command(['pull',
                          '/data/local/stream.png',
                          '{}screen.png'.format(settings.SCREEN_DIR)])

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
        out = self.adb_command(['getprop',
                                'ro.boot.serialno'], True)
        out += self.adb_command(['getprop',
                                 'ro.serialno'], True)
        out += self.adb_command(['getprop',
                                 'ro.build.user'], True)
        out += self.adb_command(['getprop',
                                 'ro.manufacturer.geny-def'], True)
        out += self.adb_command(['getprop',
                                 'ro.product.manufacturer.geny-def'], True)
        ver = self.adb_command(['getprop',
                                'ro.genymotion.version'],
                               True).decode('utf-8', 'ignore')
        if b'EMULATOR' in out:
            logger.info('Found Android Studio Emulator')
            return 'emulator'
        elif (b'genymotion' in out.lower()
                or any(char.isdigit() for char in ver)):
            logger.info('Found Genymotion x86 Android VM')
            return 'genymotion'
        elif b'corellium' in out:
            logger.info('Found Corellium ARM Android VM')
            return 'corellium'
        else:
            logger.warning(
                'Unable to identify Dynamic Analysis environment. '
                'Official support is available only for Android '
                'Emulator, Corellium, and Genymotion')
            return ''

    def get_android_version(self):
        """Get Android version."""
        out = self.adb_command(['getprop',
                                'ro.build.version.release'], True)
        and_version = out.decode('utf-8').rstrip()
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        return float(and_version)

    def get_android_arch(self):
        """Get Android Architecture."""
        out = self.adb_command([
            'getprop',
            'ro.product.cpu.abi'], True)
        return out.decode('utf-8').rstrip()

    def get_android_sdk(self):
        """Get Android API version."""
        out = self.adb_command([
            'getprop',
            'ro.build.version.sdk'], True)
        return out.decode('utf-8').strip()

    def get_device_packages(self):
        """Get all packages from device."""
        device_packages = {}
        out = self.adb_command([
            'pm',
            'list',
            'packages',
            '-f',
            '-3'], True, True)
        if not out:
            return device_packages
        for pkg_str in out.decode('utf-8').rstrip().split():
            path_pkg = pkg_str.split('package:', 1)[1].strip()
            parts = path_pkg.split('.apk=', 1)
            apk = f'{parts[0]}.apk'
            pkg = parts[1]
            if pkg == 'opensecurity.clipdump':
                # Do not include MobSF agent
                continue
            out1 = self.adb_command([
                'md5sum',
                '-b',
                apk], True)
            md5 = out1.decode('utf-8').strip()
            if '.apk' in md5:
                # -b not respected in Android 5.0
                md5 = md5.split()[0]
            device_packages[md5] = (pkg, apk)
        return device_packages

    def get_apk(self, checksum, package):
        """Download APK from device."""
        try:
            out_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
            if not os.path.exists(out_dir):
                os.makedirs(out_dir)
            out_file = os.path.join(out_dir, f'{checksum}.apk')
            if is_file_exists(out_file):
                return out_file
            out = self.adb_command([
                'pm',
                'path',
                package], True)
            out = out.decode('utf-8').rstrip()
            path = out.split('package:', 1)[1].strip()
            logger.info('Downloading APK')
            self.adb_command([
                'pull',
                path,
                out_file,
            ])
            if is_file_exists(out_file):
                return out_file
        except Exception:
            return False

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
        self.adb_command(['monkey',
                          '-p',
                          package,
                          '-c',
                          'android.intent.category.LAUNCHER',
                          '1'], True)

    def is_mobsfyied(self, android_version):
        """Check is Device is MobSFyed."""
        logger.info('Environment MobSFyed Check')
        if android_version < 5:
            agent_file = '.mobsf-x'
            agent_str = self.xposed_str
        else:
            agent_file = '.mobsf-f'
            agent_str = self.frida_str
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
            if version < 5:
                self.xposed_setup(version)
                self.mobsf_agents_setup('xposed')
            else:
                self.frida_setup()
                self.mobsf_agents_setup('frida')
            logger.info('MobSFying Completed!')
            return version
        except Exception:
            logger.exception('Failed to MobSFy Android Instance')
            return False

    def mobsf_agents_setup(self, agent):
        """Setup MobSF agents."""
        create_ca()
        # Install MITM RootCA
        self.install_mobsf_ca('install')
        # Install MobSF Agents
        mobsf_agents = 'onDevice/mobsf_agents/'
        clip_dump = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 'ClipDump.apk')
        logger.info('Installing MobSF Clipboard Dumper')
        self.adb_command(['install', '-r', clip_dump])
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

    def xposed_setup(self, android_version):
        """Setup Xposed."""
        xposed_dir = 'onDevice/xposed/'
        xposed_modules = xposed_dir + 'modules/'
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

    def frida_setup(self):
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
            logger.error('Make sure a Genymotion Android x86 VM'
                         ' or Android Studio Emulator'
                         ' instance is running')
            return
        frida_bin = f'frida-server-{frida_version}-android-{frida_arch}'
        stat = fserver.update_frida_server(frida_arch, frida_version)
        if not stat:
            msg = ('Cannot download frida-server binary. You will need'
                   f' {frida_bin} in {settings.DWD_DIR} for '
                   'Dynamic Analysis to work')
            logger.error(msg)
            return
        frida_path = os.path.join(settings.DWD_DIR, frida_bin)
        logger.info('Copying frida server for %s', frida_arch)
        self.adb_command(['push', frida_path, '/system/fd_server'])
        self.adb_command(['chmod', '755', '/system/fd_server'], True)

    def run_frida_server(self):
        """Start Frida Server."""
        check = self.adb_command(['ps'], True)
        if b'fd_server' in check:
            logger.info('Frida Server is already running')
            return

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
        logger.info('Starting Frida Server')
        logger.info('Waiting for 2 seconds...')
        time.sleep(2)
