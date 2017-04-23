#!/usr/bin/env python
# -*- coding: utf_8 -*-
import os
import platform
import subprocess
import sys
import getpass
import shutil
import io
import string
import re

BASE_DIR = os.path.dirname(os.path.realpath(__file__))


def get_windows_drive():
    drive = os.getenv('WINDIR')[:1] + ':'
    if not drive:
        return 'C:'
    return drive


def print_log(msg, log_type='INFO'):
    print '\n[' + log_type + '] ' + msg + '\n'


def execute_cmd(args, ret=False):
    try:
        print "\n[INFO] Executing Command - " + ' '.join(args)
        if ret:
            return subprocess.check_output(args)
        else:
            subprocess.call(args)
    except Exception as e:
        print "\n[ERROR] Executing Command - " + str(e)


def verify_path(help_msg):
    path = raw_input(help_msg + ': ')
    path = path.strip()
    while not os.path.exists(path):
        print_log('Path specified does not exists \ no access', 'ERROR')
        path = raw_input(help_msg)
    return path


def guess_android_avd_folder():
    system = platform.system()

    if system == 'Darwin':
        username = getpass.getuser()
        first_guess = os.path.join('/Users', username, '.android/avd')
        if os.path.exists(first_guess):
            return first_guess

    elif system == "Linux":
        for path in [os.path.expanduser('~/.android/avd/')]:
            if os.path.exists(path):
                return path

    elif system == 'Windows':
        username = getpass.getuser()
        drive = get_windows_drive()
        for path in [os.path.join(drive + '\\Documents and Settings', username, '.android\\avd'),
                     os.path.join(drive + '\\Users', username, '.android\\avd')]:
            if os.path.exists(path):
                return path

    return False


def guess_android_sdk_folder():
    system = platform.system()
    username = getpass.getuser()

    if system == 'Darwin':
        for path in [os.path.join('/Users', username, 'Library/Android/Sdk/'),
                     os.path.join('/Users', username, 'Library/Android/sdk/')]:
            if os.path.exists(path):
                return path

    elif system == "Linux":
        for path in ['/usr/local/android-sdk',
                     '/usr/local/android',
                     '/usr/local/Android',
                     os.path.expanduser('~/Android/Sdk'),
                     os.path.expanduser('~/Android/sdk'),
                     os.path.expanduser('~/android/Sdk'),
                     os.path.expanduser('~/android/sdk')]:
            if os.path.exists(path):
                return path

    elif system == 'Windows':
        drive = get_windows_drive()
        for path in [os.path.join(drive + '\\Users', username, 'AppData\\Local\\Android\\sdk'),
                     os.path.join(drive + '\\Users', username,
                                  'AppData\\Local\\Android\\Sdk'),
                     os.path.join(drive + '\\Documents and Settings',
                                  username, 'AppData\\Local\\Android\\sdk'),
                     os.path.join(drive + '\\Documents and Settings', username, 'AppData\\Local\\Android\\Sdk')]:
            if os.path.exists(path):
                return path

    return False


def find_emulator_binary(sdk):
    system = platform.system()

    if system in ['Darwin', 'Linux']:
        # Prefer emulator folder on tools folder
        for path in [os.path.join(sdk, 'emulator', 'emulator'),
                     os.path.join(sdk, 'tools', 'emulator')]:
            if os.path.exists(path):
                return path

    elif system == 'Windows':
        for path in [os.path.join(sdk, 'emulator', 'emulator.exe'),
                     os.path.join(sdk, 'tools', 'emulator.exe')]:
            if os.path.exists(path):
                return path

    return False


def find_adb_binary(sdk):
    system = platform.system()

    if system in ['Darwin', 'Linux']:
        guess = os.path.join(sdk, 'platform-tools', 'adb')
        if os.path.exists(guess):
            return guess

    elif system == 'Windows':
        guess = os.path.join(sdk, 'platform-tools', 'adb.exe')
        if os.path.exists(guess):
            return guess

    return False


def find_skin(sdk):
    # Just a basic check
    system = platform.system()

    if system == 'Darwin':
        guess = r'/Applications/Android Studio.app/Contents/plugins/android/lib/device-art-resources/nexus_5'
        if os.path.exists(guess):
            return guess

    elif system in ['Windows', 'Linux']:
        guess = os.path.join(sdk, 'skins', 'nexus_5')
        if os.path.exists(guess):
            return guess

    return False


def is_file_exists(file_path):
    """Check if File Exists"""
    return bool(os.path.isfile(file_path))


# returns an array of [str(tabs_string), str(rest_of_the_string)]
def split_tabs(inp_string):
    rgx = re.compile(r"([\s]+)(.*)")
    match = rgx.match(inp_string)
    if match:
        return [match.group(1), match.group(2)]
    else:
        return ['', inp_string]


# path to modify, replace dict = {'field_to_replace1':'value1',
#                                 'field_to_replace2': 'value2'}
def replace_values_by_fieldnames(path, replace_dict):
    replaced_lines = []
    with io.open(path, mode='r', encoding="utf8", errors="ignore") as fild:
        for line in fild.readlines():
            tmp_line = line
            if path.endswith('.py'):
                tabs_and_str = split_tabs(line)
            for field_to_replace in replace_dict.keys():
                # Python files has annoying tabs that we should consider
                if path.endswith('.py'):
                    if tabs_and_str[1].lower().startswith(field_to_replace.lower()):
                        tmp_line = tabs_and_str[0] + field_to_replace + " = r\"" + replace_dict[
                            field_to_replace].strip(" \"'").lstrip("r\"") + "\"\n"
                else:
                    if line.startswith(field_to_replace + '='):
                        tmp_line = field_to_replace + '=' + \
                            replace_dict[field_to_replace].strip() + '\n'
            replaced_lines.append(tmp_line)
    with io.open(path, 'w') as fild:
        # newlines are validated before
        fild.write(string.join(replaced_lines, ''))


def main():
    sdk_path = ''
    avd_path = ''
    adb_path = ''
    emulator_binary = ''
    mobsf_arm_folder = ''
    settings_py = ''

    print "\nMobSFy_AVD Script\n\n"
    print_log('Starting MobSF - AVD interactive configuration script')
    print_log('Make sure to run this script ONLY after you successfuly installed leatest AndroidStudio & downloaded MobSF_ARM_Emulator.zip')

    # First gather all the paths needed to make to copy opera

    print_log('Please specify the path to MobSF_ARM_Emulator extracted folder')
    mobsf_arm_folder = verify_path('MobSF_ARM_Emulator folder')

    # Give the user the ability to change the sdk and avd folder, let me guess
    # the other tools
    print_log('This script will overwrite any previously generated files.')
    guessd_sdk_path = guess_android_sdk_folder()
    if guessd_sdk_path:
        user_approve = raw_input(
            "Guessing Android sdk path: " + guessd_sdk_path + '\n Press Enter/alternative path')
        if user_approve.strip() == '':
            sdk_path = guessd_sdk_path
        elif os.path.exists(user_approve):
            sdk_path = user_approve
    if not sdk_path:
        sdk_path = verify_path('Android SDK path')

    guessd_avd_path = guess_android_avd_folder()
    if guessd_avd_path:
        user_approve = raw_input(
            "Guessing Android AVD folder: " + guessd_avd_path + '\n Press Enter/alternative path')
        if user_approve.strip() == '':
            avd_path = guessd_avd_path
        elif os.path.exists(user_approve):
            avd_path = user_approve
    if not avd_path:
        avd_path = verify_path('Android AVD path')

    emulator_binary = find_emulator_binary(sdk_path)
    if not emulator_binary:
        emulator_binary = verify_path('emulator binary')

    adb_path = find_adb_binary(sdk_path)
    if not adb_path:
        adb_path = verify_path('adb binary')

    settings_py = os.path.join(BASE_DIR, 'MobSF', 'settings.py')
    if not os.path.exists(settings_py):
        settings_py = verify_path('MobSF/settings.py file')

    skin_path = find_skin(sdk_path)
    if not skin_path:
        skin_path = verify_path('nexus 5 skin path')

    print_log('Finished finding all the paths needed')

    ################## Copy the downloaded emulator and system image #########

    emulator_avd = os.path.join(mobsf_arm_folder, 'Nexus5API16.avd')
    emulator_ini = os.path.join(mobsf_arm_folder, 'Nexus5API16.ini')
    new_emulator_avd = os.path.join(avd_path, 'Nexus5API16.avd')
    new_emulator_ini = os.path.join(avd_path, 'Nexus5API16.ini')
    print_log('Copying emulator files to avd folder: ' + avd_path)
    if is_file_exists(new_emulator_ini):
        print_log("Replacing old Emulator INI")
        os.remove(new_emulator_ini)
    shutil.copyfile(emulator_ini, new_emulator_ini)
    if os.path.isdir(new_emulator_avd):
        print_log("Replacing old Emulator AVD")
        shutil.rmtree(new_emulator_avd)
    shutil.copytree(emulator_avd, new_emulator_avd)
    system_images = os.path.join(sdk_path, 'system-images')
    xposed_image_path = os.path.join(system_images, 'Xposed-android-16')
    downloaded_xposed_image = os.path.join(
        mobsf_arm_folder, 'Xposed-android-16')
    if os.path.isdir(xposed_image_path):
        print_log("Replacing old Xposed image")
        shutil.rmtree(xposed_image_path)
    shutil.copytree(downloaded_xposed_image, xposed_image_path)

    ################## Modify all the config files ###########################

    print_log('Modifying config files')

    # Nexus5API16.ini
    replace_values_by_fieldnames(new_emulator_ini, {
        'path': new_emulator_avd,
        'skin.path': skin_path
    })

    # Nexus5API16.avd/config.ini
    replace_values_by_fieldnames(os.path.join(new_emulator_avd, 'config.ini'), {
        'skin.path': skin_path
    })

    # Nexus5API16.avd/hardware-qemu.ini
    replace_values_by_fieldnames(os.path.join(new_emulator_avd, 'hardware-qemu.ini'), {
        'hw.sdCard.path': os.path.join(new_emulator_avd, 'sdcard.img'),
        'disk.cachePartition.path': os.path.join(new_emulator_avd, 'cache.img'),
        'kernel.path': os.path.join(xposed_image_path, 'kernel-qemu'),
        'disk.ramdisk.path': os.path.join(xposed_image_path, 'ramdisk.img'),
        'disk.systemPartition.initPath': os.path.join(xposed_image_path, 'system.img'),
        'disk.dataPartition.path': os.path.join(new_emulator_avd, 'userdata.img'),
    })

    replace_values_by_fieldnames(settings_py, {
        'AVD_EMULATOR': emulator_binary,
        'AVD_PATH': avd_path,
        'ADB_BINARY': 'r"' + adb_path + '"'
    })

    print "\n\nAll Done! you can now use MobSF AVD Emulator :)\n\n"

if __name__ == '__main__':
    sys.exit(main())
