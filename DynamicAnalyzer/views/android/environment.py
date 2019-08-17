import logging
import os
import re
import shutil
import subprocess
import time
import threading

from django.conf import settings

from DynamicAnalyzer.tools.webproxy import (start_proxy, stop_capfuzz)

from StaticAnalyzer.models import StaticAnalyzerAndroid

from MobSF.utils import (get_adb, python_list)

logger = logging.getLogger(__name__)


class Environment:

    def __init__(self, identifier):
        self.identifier = identifier

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
        stop_capfuzz(proxy_port)
        start_proxy(proxy_port, project)

    def enable_adb_reverse_tcp(self):
        """Enable ADB Reverse TCP for Proxy."""
        proxy_port = settings.PROXY_PORT
        logger.info('Enabling ADB Reverse TCP on %s', proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        try:
            proc = subprocess.Popen([get_adb(), 'reverse', tcp, tcp],
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
                print(match.group())
                res = match.group().split('][')[1].replace(']', '')
                width, height = res.split(',', 1)
                return width, height
            else:
                logger.error('Error getting screen resolution')
        except Exception:
            logger.exception('Getting screen resolution')
        return '', ''

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
        out = subprocess.check_output([get_adb(),
                                       '-s',
                                       self.identifier,
                                       'shell',
                                       'getprop',
                                       'ro.build.version.release'])
        and_version = out.decode('utf-8').rstrip()
        logger.info('Android Version identified as %s', and_version)
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        return float(and_version)

    def run_frida_server(self):
        """Start Frida Server."""
        fda = [get_adb(),
               '-s',
               self.identifier,
               'shell',
               '/system/fd_server']
        trd = threading.Thread(target=subprocess.call, args=(fda,))
        trd.daemon = True
        trd.start()
        logger.info('Frida Server is running')
