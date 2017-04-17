#!/usr/bin/env python
# -*- coding: utf_8 -*-
import os
import platform
import subprocess
import sys
import getpass
import shutil
import io

BASE_DIR = os.path.dirname(os.path.realpath(__file__))


def print_log(str, log_type='INFO'):
    print '\n[' + log_type + '] ' + str + '\n'


def execute_cmd(args, ret=False):
    try:
        print "\n[INFO] Executing Command - " + ' '.join(args)
        if ret:
            return subprocess.check_output(args)
        else:
            subprocess.call(args)
    except Exception as e:
        print("\n[ERROR] Executing Command - " + str(e))


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
        for path in ['~/.android/avd/']:
            if os.path.exists(path):
                return path

    elif system == 'Windows':
        username = getpass.getuser()
        for path in [os.path.join('C:\\Documents and Settings', username, '.android\\avd'),
                     os.path.join('C:\\Users', username, '.android\\avd')]:
            if os.path.exists(path):
                return path

    return False


def guess_android_sdk_folder():
    system = platform.system()

    if system == 'Darwin':
        username = getpass.getuser()
        first_guess = os.path.join('/Users', username, 'Library/Android/sdk/')
        if os.path.exists(first_guess):
            return first_guess

    elif system == "Linux":
        for path in ['/usr/local/android-sdk', '/usr/local/android', '/usr/local/Android']:
            if os.path.exists(path):
                return path

    elif system == 'Windows':
        username = getpass.getuser()
        first_guess = os.path.join('C:\\Users', username, 'AppData\\Local\\Android\\sdk')
        if os.path.exists(first_guess):
            return first_guess

    return False


def find_emulator_binary(sdk):
    system = platform.system()

    if system in ['Darwin', 'Linux']:
        guess = os.path.join(sdk, 'tools', 'emulator')
        if os.path.exists(guess):
            return guess

    elif system == 'Windows':
        guess = os.path.join(sdk, 'emulator', 'emulator.exe')
        if os.path.exists(guess):
            return guess

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


# path to modify, replace dict = {'content_to_replace1': 'value_to_replace1', 'content_to_replace2': 'value_to_replace2'}
def replace_all_occurations_in_file(path, replace_dict):
        with io.open(path, 'r') as fd:
            replaced_file = fd.read()
            for what_to_replace in replace_dict.keys():
                replaced_file = replaced_file.replace(what_to_replace, replace_dict[what_to_replace])
        with io.open(path, 'w') as fd:
            fd.write(replaced_file)


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


    ################## First gather all the paths needed to make to copy operations ###############

    print_log('Please specify the path to MOBSF_ARM_Emulator extracted folder')
    mobsf_arm_folder = verify_path('MobSF_ARM_Emulator folder')

    # Give the user the ability to change the sdk and avd folder, let me guess the other tools
    guessd_sdk_path = guess_android_sdk_folder()
    if guessd_sdk_path:
        user_approve = raw_input("Guessing Android sdk path: " + guessd_sdk_path + '\n Press Enter/alternative path')
        if user_approve.strip() == '':
            sdk_path = guessd_sdk_path
        elif os.path.exists(user_approve):
            sdk_path = user_approve
    if not sdk_path:
        sdk_path = verify_path('Android SDK path')

    guessd_avd_path = guess_android_avd_folder()
    if guessd_avd_path:
        user_approve = raw_input("Guessing Android AVD folder: " + guessd_avd_path + '\n Press Enter/alternative path')
        if user_approve.strip() == '':
            avd_path = guessd_avd_path
        elif os.path.exists(user_approve):
            avd_path = user_approve
    if not sdk_path:
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
        skin_path = ''

    print_log('Finished finding all the paths needed')


    ################## Copy the downloaded emulator and system image ####################


    emulator_avd = os.path.join(mobsf_arm_folder, 'Nexus5API16.avd')
    emulator_ini = os.path.join(mobsf_arm_folder, 'Nexus5API16.ini')
    new_emulator_avd = os.path.join(avd_path, 'Nexus5API16.avd')
    new_emulator_ini = os.path.join(avd_path, 'Nexus5API16.ini')
    print_log('Copying emulator files to avd folder: ' + avd_path)
    shutil.copyfile(emulator_ini, new_emulator_ini)
    shutil.copytree(emulator_avd, new_emulator_avd)

    system_images = os.path.join(sdk_path, 'system-images')
    xposed_image_path = os.path.join(system_images, 'Xposed-android-16')
    downloaded_xposed_image = os.path.join(mobsf_arm_folder, 'Xposed-android-16')
    shutil.copytree(downloaded_xposed_image, xposed_image_path)



    ################## Modify all the config files #######################################

    print_log('Modifying config files')

    # Nexus5API16.ini
    replace_all_occurations_in_file(new_emulator_ini, {
        '[path_of_avd]': new_emulator_avd,
        '[skin_path]'  : skin_path
    })

    # Nexus5API16.avd/config.ini
    replace_all_occurations_in_file(os.path.join(new_emulator_avd, 'config.ini'), {
        '[skin_path]': skin_path
    })

    # Nexus5API16.avd/hardware-qemu.ini
    replace_all_occurations_in_file(os.path.join(new_emulator_avd, 'hardware-qemu.ini'), {
        '[sdcard]'        : os.path.join(new_emulator_avd, 'sdcard.img'),
        '[cache]'         : os.path.join(new_emulator_avd, 'cache.img'),
        '[kernel_path]'   : os.path.join(xposed_image_path, 'kernel-qemu'),
        '[ramdisk]'       : os.path.join(xposed_image_path, 'ramdisk.img'),
        '[system_image]'  : os.path.join(xposed_image_path, 'system.img'),
        '[data_partition]': os.path.join(new_emulator_avd, 'userdata.img'),
    })

    replace_all_occurations_in_file(settings_py, {
        '\'avd_path'       : 'r\'' + avd_path,
        '\'avd_emulator'   : 'r\'' + emulator_binary,
        'ADB_BINARY = ""'  : 'ADB_BINARY = r"' + adb_path + '"',
        'AVD = False'      : 'AVD = True'
    })

    print "\n\nAll Done! you can now use MobSF AVD Emulator :)\n\n"


if __name__ == '__main__':
    sys.exit(main())