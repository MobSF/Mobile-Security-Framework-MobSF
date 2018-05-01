"""
Android Dynamic Analyzer for Android AVD (ARM) VM
"""
import os
import time
import platform
import subprocess

from DynamicAnalyzer.views.android.shared import adb_command
from MobSF.utils import PrintException
from django.conf import settings


def stop_avd():
    """Stop AVD"""
    print("\n[INFO] Stopping MobSF Emulator")
    try:
        adb_command(['emu', 'kill'], silent=True)
    except:
        PrintException("[ERROR] Stopping MobSF Emulator")


def start_avd():
    """Start AVD"""
    print("\n[INFO] Starting MobSF Emulator")
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
            "-snapshot",
            "default_boot",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-port",
            str(settings.AVD_ADB_PORT),
        ]
        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Give a few seconds and check if the snapshot load succeed
        time.sleep(5)
        result = adb_command(["getprop", "init.svc.bootanim"], True)

        if result:
            if result.strip() == b"stopped":
                return True

        # Snapshot failed, stop the avd and return an error
        adb_command(["emu", "kill"])
        return False
    except:
        PrintException("[ERROR] Starting MobSF Emulator")
        return False


def refresh_avd():
    """Refresh AVD"""

    # Before we load the AVD, check paths
    for path in [settings.AVD_EMULATOR,
                 settings.ADB_BINARY]:
        if not path:
            print("\n[ERROR] AVD binaries not configured, please refer to the official documentation")
            return False

    print("\n[INFO] Refreshing MobSF Emulator")
    try:
        # Stop existing emulator
        stop_avd()

        # Start emulator
        if start_avd():
            print("\n[INFO] AVD has been loaded from snapshot successfully")
            return True
        return False

    except:
        PrintException("[ERROR] Refreshing MobSF VM")
        return False
