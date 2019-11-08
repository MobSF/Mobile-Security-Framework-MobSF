# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import logging
import os
import re
import shutil
import subprocess
import time
import threading

from django.conf import settings

from DynamicAnalyzer.tools.webproxy import (get_ca_dir,
                                            start_proxy,
                                            stop_httptools)

from StaticAnalyzer.models import StaticAnalyzerAndroid

from MobSF.utils import (get_adb,
                         get_device,
                         get_proxy_ip,
                         python_list)

logger = logging.getLogger(__name__)


class Environment:

    def __init__(self, identifier=None):
        if identifier:
            self.identifier = identifier
        else:
            self.identifier = get_device()
        self.tools_dir = settings.TOOLS_DIR

    def wait(self, sec):
        """Wait in Seconds."""
        logger.info('Waiting for %s seconds...', str(sec))
        time.sleep(sec)

    def connect_n_mount(self):
        """Test ADB Connection."""
        self.adb_command(['kill-server'])
        self.adb_command(['start-server'])
        logger.info('ADB Restarted')
        self.wait(2)
        logger.info('Connecting to Android %s', self.identifier)
        out = subprocess.check_output([get_adb(), 'connect', self.identifier])
        if b'unable to connect' in out or b'failed to connect' in out:
            logger.error('%s', out.decode('utf-8').replace('\n', ''))
            return False
        else:
            logger.info('Remounting /system')
            self.adb_command(['mount', '-o',
                              'rw,remount', '/system'], True)
        return True

    def adb_command(self, cmd_list, shell=False, silent=False):
        """ADB Command wrapper."""
        args = [get_adb(),
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list

        try:
            result = subprocess.check_output(args)
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

    def configure_proxy(self, project):
        """HTTPS Proxy."""
        proxy_port = settings.PROXY_PORT
        logger.info('Starting HTTPs Proxy on %s', proxy_port)
        stop_httptools(proxy_port)
        start_proxy(proxy_port, project)

    def install_mobsf_ca(self, action):
        """Install or Remove MobSF Root CA."""
        ca_file = os.path.join('/system/etc/security/cacerts/',
                               settings.ROOT_CA)
        if action == 'install':
            logger.info('Installing MobSF RootCA')
            self.adb_command(['push', get_ca_dir(), ca_file])
            self.adb_command(['chmod',
                              '644',
                              ca_file], True)
        elif action == 'remove':
            logger.info('Removing MobSF RootCA')
            self.adb_command(['rm', ca_file], True)

    def set_global_proxy(self, version):
        """Set Global Proxy on device."""
        # Android 4.4+ supported
        proxy_ip = None
        proxy_port = settings.PROXY_PORT
        if version < 5:
            proxy_ip = get_proxy_ip(self.identifier)
        else:
            proxy_ip = '127.0.0.1'
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
        anddb = StaticAnalyzerAndroid.objects.filter(MD5=bin_hash)
        resp = []
        if comp == 'activities':
            resp = python_list(anddb[0].ACTIVITIES)
        elif comp == 'receivers':
            resp = python_list(anddb[0].RECEIVERS)
        elif comp == 'providers':
            resp = python_list(anddb[0].PROVIDERS)
        elif comp == 'services':
            resp = python_list(anddb[0].SERVICES)
        elif comp == 'libraries':
            resp = python_list(anddb[0].LIBRARIES)
        elif comp == 'exported_activities':
            resp = python_list(anddb[0].EXPORTED_ACT)
        return '\n'.join(resp)

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
        out = self.adb_command(['getprop',
                                'ro.product.cpu.abi'], True)
        return out.decode('utf-8').rstrip()

    def launch_n_capture(self, package, activity, outfile):
        """Launch and Capture Activity."""
        self.adb_command(['am',
                          'start',
                          '-n',
                          package + '/' + activity], True)
        self.wait(3)
        self.screen_shot(outfile)
        logger.info('Activity screenshot captured')
        logger.info('Stopping app')
        self.adb_command(['am', 'force-stop', package], True)

    def is_mobsfyied(self, android_version):
        """Check is Device is MobSFyed."""
        logger.info('Environment MobSFyed Check')
        if android_version < 5:
            agent_file = '.mobsf-x'
            agent_str = b'MobSF-Xposed'
        else:
            agent_file = '.mobsf-f'
            agent_str = b'MobSF-Frida'
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
        else:
            agent_file = '.mobsf-x'
        mobsf_env = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 agent_file)
        self.adb_command(['push', mobsf_env, '/system/' + agent_file])

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
                                 'RootCloak.apk')
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
        frida_dir = 'onDevice/frida/'
        frida_bin = os.path.join(self.tools_dir,
                                 frida_dir,
                                 'frida-server-12.7.20-android-x86')
        arch = self.get_android_arch()
        logger.info('Android instance architecture identified as %s', arch)
        if 'x86' not in arch:
            logger.error('Make sure a Genymotion Android x86'
                         'instance is running')
            return
        logger.info('Copying frida server')
        self.adb_command(['push', frida_bin, '/system/fd_server'])
        self.adb_command(['chmod', '755', '/system/fd_server'], True)

    def run_frida_server(self):
        """Start Frida Server."""
        check = self.adb_command(['ps'], True)
        if b'/system/fd_server' in check:
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
        logger.info('Frida Server is running')
