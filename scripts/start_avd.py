import sys
import os
import platform
import subprocess
import django
from os.path import dirname, abspath

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
                print("\n[ERROR] AVD binaries not configured, please refer to the official documentation")
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
        subprocess.call(args)

        # Make sure adb running as root
        adb_command(['root'])

        # Make sure the system is writable
        adb_command(['remount'])

        # Make sure the system verity feature is disabled (Obviously, modified the system partition)
        adb_command(['disable-verity'])

        # Make SELinux permissive - in case SuperSu/Xposed didn't patch things right
        adb_command(['setenforce', '0'], shell=True)

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
        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except:
        PrintException("[ERROR] start_avd")
        return False


def main():
    print("[INFO] MobSF - start_avd.py has started")
    if not check_config():
        return -1
    if not start_avd():
        return -1
    if not help_boot_avd():
        return -1
    print("[INFO] start_avd successfully finished")
    print("[INFO] Please wait untill the emulator will load completely, only then take a snapshot")


if __name__ == '__main__':
    sys.exit(main())