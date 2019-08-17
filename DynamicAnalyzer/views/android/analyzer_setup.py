# -*- coding: utf_8 -*-
"""Configure Dynamic Analysis Runtime Environment."""
import os
import logging

from django.conf import settings

from DynamicAnalyzer.tools.webproxy import get_ca_dir
from DynamicAnalyzer.views.android.environment import Environment


logger = logging.getLogger(__name__)


class AnalyzerSetup:

    def __init__(self, identifier):
        self.identifier = identifier
        self.env = Environment(identifier)
        self.tools_dir = settings.TOOLS_DIR

    def setup(self):
        """Start setup."""
        version = self.env.get_android_version()
        try:
            if version < 5:
                self.xposed_setup(version)
                self.mobsf_agents_setup('xposed')
            else:
                self.frida_setup()
                self.mobsf_agents_setup('frida')
        except Exception:
            logger.exception('Failed to MobSFy Android Instance')

    def mobsf_agents_setup(self, agent):
        """Setup MobSF agents."""
        # Install MITM RootCA
        logger.info('Installing MobSF RootCA')
        mobsf_agents = 'onDevice/mobsf_agents/'
        ca_file = os.path.join('/system/etc/security/cacerts/',
                               settings.ROOT_CA)
        self.env.adb_command(['push',
                              get_ca_dir(),
                              ca_file])
        self.env.adb_command(['chmod',
                              '644',
                              ca_file], True)
        # Install MobSF Agents
        clip_dump = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 'ClipDump.apk')
        logger.info('Installing MobSF Clipboard Dumper')
        self.env.adb_command(['install', '-r', clip_dump])
        if agent == 'frida':
            agent_file = '.mobsf-f'
        else:
            agent_file = '.mobsf-x'
        mobsf_env = os.path.join(self.tools_dir,
                                 mobsf_agents,
                                 agent_file)
        self.env.adb_command(['push', mobsf_env, '/system/' + agent_file])
        logger.info('MobSFying Completed!')

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
            self.env.adb_command(['install', '-r', droidmon])
            logger.info('Copying Droidmon hooks config')
            self.env.adb_command(['push', hooks, '/data/local/tmp/'])
        else:
            logger.info('Installing Xposed for Lollipop and above')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'XposedInstaller_3.1.5.apk')
        self.env.adb_command(['install', '-r', xposed_apk])
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
        self.env.adb_command(['install', '-r', justrustme])
        logger.info('Installing SSLUnpinning')
        self.env.adb_command(['install', '-r', sslunpin])
        logger.info('Installing ProxyOn')
        self.env.adb_command(['install', '-r', proxyon])
        logger.info('Installing RootCloak')
        self.env.adb_command(['install', '-r', rootcloak])
        logger.info('Installing Android BluePill')
        self.env.adb_command(['install', '-r', bluepill])
        logger.info('Launching Xposed Framework.')
        xposed_installer = ('de.robv.android.xposed.installer/'
                            'de.robv.android.xposed.installer.'
                            'WelcomeActivity')
        self.env.adb_command(['am', 'start', '-n',
                              xposed_installer], True)

    def frida_setup(self):
        """Setup Frida."""
        frida_dir = 'onDevice/frida/'
        frida_bin = os.path.join(self.tools_dir,
                                 frida_dir,
                                 'frida-server-12.6.14-android-x86')
        logger.info('Copying frida server')
        self.env.adb_command(['push', frida_bin, '/system/fd_server'])
        self.env.adb_command(['chmod', '755', '/system/fd_server'], True)
