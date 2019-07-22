#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""Script to create MobSF Dynamic Analysis Environment."""
import argparse
import logging
import os
import platform
import subprocess
import sys

import capfuzz as cp

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TOOLSDIR = os.path.join(BASE_DIR, '../DynamicAnalyzer/tools/')  # TOOLS DIR
ROOTCA = os.path.join(os.path.dirname(cp.__file__),
                      'ca', 'mitmproxy-ca-cert.cer')
TYPE_VM = '1'
XPOSED_OLD = '1'


def execute_cmd(args, ret=False):
    """Execute Commands."""
    try:
        logger.info('Executing Command - %s', ' '.join(args))
        if ret:
            return subprocess.check_output(args)
        else:
            subprocess.call(args)
    except Exception:
        logger.error('Error Executing Command')


def get_adb():
    """Get ADB Location."""
    try:
        adb = 'adb'
        if platform.system() == 'Darwin':
            adb_dir = os.path.join(TOOLSDIR, 'adb/mac/')
            os.chmod(adb_dir, 0o777)
            adb = os.path.join(TOOLSDIR, 'adb/mac/adb')
        elif platform.system() == 'Linux':
            adb_dir = os.path.join(TOOLSDIR, 'adb/linux/')
            os.chmod(adb_dir, 0o777)
            adb = os.path.join(TOOLSDIR, 'adb/linux/adb')
        elif platform.system() == 'Windows':
            adb = os.path.join(TOOLSDIR, 'adb/windows/adb.exe')
        return adb
    except Exception as exp:
        logger.error(('Getting ADB Location - %s', str(exp)))
        return 'adb'


def main():
    """Main of Script."""
    print('\nMobSFy Script\n\nThis script allows you to configure any rooted '
          'android Device or VM to perfrom MobSF dynamic analysis.\n'
          '(Supports Android Version 4.03 to 4.4)')

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--identifier',
                        help='IP:PORT or Serial no of Device/VM.'
                        ' (ex: 192.168.1.2:5555)')
    parser.add_argument(
        '-t', '--type', help='Specify the type. Supported types are'
        ' 1. VM or 2.Device. (ex: 1)')
    parser.add_argument(
        '-v', '--version', help='Specify the Android Version. '
        'Available options are 1. <5 or 2. >=5. (ex: 1)')
    args = parser.parse_args()
    try:
        if args.identifier and args.type:
            adbconnect = args.identifier
            vm_or_ip = args.type
            xposed_ver = args.version
        else:
            adbconnect = input(
                'Enter the IP:PORT or Serial no of the Device/VM'
                ' (Ex: 192.168.1.2:5555) and press enter: ')
            vm_or_ip = input('Choose\n 1. VM\n 2. Device\nEnter your choice: ')
            xposed_ver = input(
                'Android Version\n1. <5\n2. >=5\nEnter your choice: ')
        execute_cmd([get_adb(), 'kill-server'])
        execute_cmd([get_adb(), 'start-server'])
        execute_cmd([get_adb(), 'connect', adbconnect])
        execute_cmd([get_adb(), '-s', adbconnect, 'wait-for-device'])
        # Install MITM RootCA
        execute_cmd([get_adb(), '-s', adbconnect, 'push',
                     ROOTCA, '/data/local/tmp/0025aabb.0'])
        execute_cmd([get_adb(), '-s', adbconnect, 'shell', 'su', '-c',
                     'mount', '-o', 'rw,remount,rw', '/system'])
        execute_cmd([get_adb(), '-s', adbconnect, 'shell', 'su', '-c', 'cp',
                     '/data/local/tmp/0025aabb.0',
                     '/system/etc/security/cacerts/0025aabb.0'])
        execute_cmd([get_adb(), '-s', adbconnect, 'shell', 'su', '-c', 'chmod',
                     '644', '/system/etc/security/cacerts/0025aabb.0'])
        execute_cmd([get_adb(), '-s', adbconnect, 'shell',
                     'rm', '/data/local/tmp/0025aabb.0'])
        # Install MobSF requirements
        data_pusher = os.path.join(TOOLSDIR, 'onDevice/DataPusher.apk')
        screen_cast = os.path.join(TOOLSDIR, 'onDevice/ScreenCast.apk')
        clip_dump = os.path.join(TOOLSDIR, 'onDevice/ClipDump.apk')
        # 3P
        if xposed_ver == XPOSED_OLD:
            xposed = os.path.join(TOOLSDIR, 'onDevice/Xposed.apk')
        else:
            xposed = os.path.join(
                TOOLSDIR, 'onDevice/XposedInstaller_3.1.5.apk')
        # Xposed Modules and Support Files
        hooks = os.path.join(TOOLSDIR, 'onDevice/hooks.json')
        droidmon = os.path.join(TOOLSDIR, 'onDevice/Droidmon.apk')
        justrustme = os.path.join(TOOLSDIR, 'onDevice/JustTrustMe.apk')
        rootcloak = os.path.join(TOOLSDIR, 'onDevice/RootCloak.apk')
        # Anti-VM Bypass
        bluepill = os.path.join(TOOLSDIR, 'onDevice/AndroidBluePill.apk')
        fake_build = os.path.join(TOOLSDIR, 'onDevice/antivm/fake-build.prop')
        fake_cpuinfo = os.path.join(TOOLSDIR, 'onDevice/antivm/fake-cpuinfo')
        fake_drivers = os.path.join(TOOLSDIR, 'onDevice/antivm/fake-drivers')

        logger.info('Installing MobSF DataPusher')
        execute_cmd([get_adb(), '-s', adbconnect,
                     'install', '-r', data_pusher])
        logger.info('Installing MobSF ScreenCast')
        execute_cmd([get_adb(), '-s', adbconnect,
                     'install', '-r', screen_cast])
        logger.info('Installing MobSF Clipboard Dumper')
        execute_cmd([get_adb(), '-s', adbconnect, 'install', '-r', clip_dump])
        logger.info('Copying hooks.json')
        execute_cmd([get_adb(), '-s', adbconnect,
                     'push', hooks, '/data/local/tmp/'])
        logger.info('Installing Xposed Framework')
        execute_cmd([get_adb(), '-s', adbconnect, 'install', '-r', xposed])
        logger.info('Installing Droidmon API Analyzer')
        execute_cmd([get_adb(), '-s', adbconnect, 'install', '-r', droidmon])
        logger.info('Installing JustTrustMe')
        execute_cmd([get_adb(), '-s', adbconnect, 'install', '-r', justrustme])
        logger.info('Installing RootCloak')
        execute_cmd([get_adb(), '-s', adbconnect, 'install', '-r', rootcloak])

        if vm_or_ip == TYPE_VM:
            logger.info('Installing Android BluePill')
            execute_cmd([get_adb(), '-s', adbconnect,
                         'install', '-r', bluepill])
            logger.info('Copying fake-build.prop')
            execute_cmd([get_adb(), '-s', adbconnect, 'push',
                         fake_build, '/data/local/tmp/'])
            logger.info('Copying fake-cpuinfo')
            execute_cmd([get_adb(), '-s', adbconnect, 'push',
                         fake_cpuinfo, '/data/local/tmp/'])
            logger.info('Copying fake-drivers')
            execute_cmd([get_adb(), '-s', adbconnect, 'push',
                         fake_drivers, '/data/local/tmp/'])
        logger.info('Launching Xposed Framework.')
        xposed_installer = ('de.robv.android.xposed.installer/'
                            'de.robv.android.xposed.installer.WelcomeActivity')
        execute_cmd([get_adb(), '-s', adbconnect, 'shell', 'am', 'start', '-n',
                     xposed_installer])
        if vm_or_ip == TYPE_VM:
            print('\n 1 .Install the Framework\n 2. Restart the device\n'
                  ' 3. Enable Android BluePill, Droidmon, '
                  'JustTrustMe and RootCloak.')
        else:
            print('\n 1 .Install the Framework\n 2. Restart the device\n '
                  '3. Enable Droidmon, JustTrustMe and RootCloak.')
        logger.info('MobSFy Script Executed Successfully')
    except Exception:
        logger.error('Error occurred')
        sys.exit(0)


if __name__ == '__main__':
    main()
