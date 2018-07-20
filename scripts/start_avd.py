import sys
import os
import platform
import subprocess
import django
import time
from os.path import dirname, abspath
import traceback
from multiprocessing import Process


MobSF_path = dirname(dirname(abspath(__file__)))
sys.path.append(MobSF_path)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MobSF.settings')
django.setup()
from django.conf import settings

from DynamicAnalyzer.views.android.shared import adb_command
from DynamicAnalyzer.views.android.shared import get_identifier
from MobSF.utils import PrintException


def check_config():
    try:
        for path in [settings.AVD_EMULATOR,
                     settings.ADB_BINARY]:
            if not path:
                print("\n[ERROR] ADB binary not configured, please refer to the official documentation")
                return False
        if settings.ANDROID_DYNAMIC_ANALYZER != 'MobSF_AVD':
            print("\n[ERROR] Wrong configuration - ANDROID_DYNAMIC_ANALYZER, please refer to the official documentation")
            return False
        return True
    except:
        PrintException("[ERROR] check_config")
        return False


# In some cases, the modifications to the AVD won't let it boot, this will to the trick
def help_boot_avd():
    try:
        emulator = get_identifier()

        # Wait for the adb to answer
        args = [settings.ADB_BINARY,
                "-s",
                emulator,
                "wait-for-device"]
        print("[INFO] help_boot_avd: wait-for-device")
        subprocess.call(args)

        # Make sure adb running as root
        print("[INFO] help_boot_avd: root")
        adb_command(['root'])

        # Make sure the system verity feature is disabled (Obviously, modified the system partition)
        print("[INFO] help_boot_avd: disable-verity")
        adb_command(['disable-verity'])

        # Make SELinux permissive - in case SuperSu/Xposed didn't patch things right
        print("[INFO] help_boot_avd: setenforce")
        adb_command(['setenforce', '0'], shell=True)

        print("[INFO] help_boot_avd: finished!")
        return True
    except:
        PrintException("[ERROR] help_boot_avd")
        return False


def start_avd():
    try:
        if platform.system() == 'Darwin':
            # There is a strage error in mac with the dyld one in a while..
            # this should fix it..
            if 'DYLD_FALLBACK_LIBRARY_PATH' in list(os.environ.keys()):
                del os.environ['DYLD_FALLBACK_LIBRARY_PATH']

        args = [
            settings.AVD_EMULATOR,
            '-avd',
            settings.AVD_NAME,
            "-writable-system",
            "-no-snapshot-load",
            "-port",
            str(settings.AVD_ADB_PORT),
        ]
        print("[INFO] starting emulator: \r\n" + ' '.join(args))
        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except:
        PrintException("[ERROR] start_avd")
        return False


def guess_system_image(avd_emulator_path):
    potential_paths = list()
    if platform.system() == 'Darwin':
        # Get only /Users/username first
        user_home = '/'.join(avd_emulator_path.split(os.path.sep)[:3])
        potential_paths.append(os.path.join(user_home, 'Library/Android/Sdk/system-images/android-23/google_apis/armeabi-v7a/system.img'))
    elif platform.system() == 'Linux':
        # TODO: TBD
        pass
    elif platform.system() == 'Windows':
        # TODO: TBD
        pass
    for path in potential_paths:
        if os.path.exists(path):
            return path

    return None

def get_qcow_image(avd_emulator_path):
    potential_paths = list()
    if platform.system() == 'Darwin':
        # Get only /Users/username first
        user_home = '/'.join(avd_emulator_path.split(os.path.sep)[:3])
        potential_paths.append(os.path.join(user_home, '.android/avd/MobSFAPI23arm.avd/system.img.qcow2'))
    elif platform.system() == 'Linux':
        # TODO: TBD
        pass
    elif platform.system() == 'Windows':
        # TODO: TBD
        pass
    for path in potential_paths:
        if os.path.exists(path):
            return path
    return None


def extract_qcow_system(qcow_path):
    try:
        with open(qcow_path, 'rb') as read_fd:
            read_fd.seek(280)
            image_path = read_fd.read(256)
        return str(image_path.decode('ascii')).replace('\x00', '')
    except:
        print("[ERROR] Error reading qcow image")
        return None


def write_new_system_path_inside_qcow(qcow_path, system_path):
    try:
        # Get the length of the path so we can calculate how many zeros to append afterwards
        system_image_str_len = len(system_path)
        zeros_to_write = 256 - system_image_str_len

        # Open in override mode so we don't need to read the whole file just to replace a little string
        with open(qcow_path, 'r+b') as qcow_fd:
            # Seek to the strings offset
            qcow_fd.seek(280)

            # Write the new system.img path
            qcow_fd.write(system_path.encode('ascii'))

            # Append enough zeros to make sure we don't write just the begining of the previous path
            qcow_fd.write(b'\x00' * zeros_to_write)

        print("[INFO] New system path was written to qcow file")
        return True
    except:
        print(traceback.format_exc())
        print("[ERROR] Error writing new system file to qcow file")
        return False


def check_system_file():
    # ex. /Users/matandobr/Library/Android/sdk/tools/emulator
    emulator_binary = settings.AVD_EMULATOR

    # Check if the system image is installed currectly
    local_system_image = guess_system_image(emulator_binary)
    if not local_system_image:
        print("[ERROR] Cannot find system.img file, Please verify you've installed android 6 armv7 with google apis system image")
        return False

    # Check if the modified system is already been patched
    qcow_image = get_qcow_image(emulator_binary)
    if not os.path.exists(qcow_image):
        print("[ERROR] system.img.qcow2 wasn't found on the system, make sure you copied MobSFAPI23arm.avd folder to the proper folder")

    original_system_path = extract_qcow_system(qcow_image)
    if os.path.exists(original_system_path):
        print("[INFO] system.img.qcow path check passed successfully")
        return True

    print("[INFO] qcow path didn't match, replacing")
    if not write_new_system_path_inside_qcow(qcow_image, local_system_image):
        print("[ERROR] Error fixing system file")
        return False

    # After we wrote a new system path, verify it again
    new_system_path = extract_qcow_system(qcow_image)
    if os.path.exists(new_system_path):
        print("[INFO] system.img.qcow path check passed successfully")
        return True
    else:
        print("[ERROR] system file verification failed")
        return False


def main():
    print("[INFO] MobSF - start_avd.py has started")
    if not check_config():
        return -1
    if not check_system_file():
        return -1
    if not start_avd():
        return -1
    if not help_boot_avd():
        return -1
    print("[INFO] start_avd successfully finished")
    print("[INFO] Please wait untill the emulator will load completely, only then take a snapshot")


if __name__ == '__main__':
    sys.exit(main())
