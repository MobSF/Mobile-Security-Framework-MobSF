"""
Android Dynamic Analyzer for Android AVD (ARM) VM
"""
import os
import io
import time
import platform
import shutil
import subprocess

from DynamicAnalyzer.views.android.android_dyn_shared import get_identifier
from MobSF.utils import PrintException
from django.conf import settings


def stop_avd(adb):
    """Stop AVD"""
    print "\n[INFO] Stopping MobSF Emulator"
    try:
        # adb -s emulator-xxxx emu kill
        FNULL = open(os.devnull, 'w')
        args = [adb, '-s', get_identifier(), 'emu', 'kill']
        subprocess.call(args, stderr=FNULL)
    except:
        PrintException("[ERROR] Stopping MobSF Emulator")


def delete_avd(avd_path, avd_name):
    """Delete AVD"""
    print "\n[INFO] Deleting emulator files"
    try:
        config_file = os.path.join(avd_path, avd_name + '.ini')
        if os.path.exists(config_file):
            os.remove(config_file)
        '''
        # todo: Sometimes there is an error here because of the locks that avd
        # does - check this out
        '''
        avd_folder = os.path.join(avd_path, avd_name + '.avd')
        if os.path.isdir(avd_folder):
            shutil.rmtree(avd_folder)
    except:
        PrintException("[ERROR] Deleting emulator files")


def duplicate_avd(avd_path, reference_name, dup_name):
    """Duplicate AVD"""
    print "\n[INFO] Duplicating MobSF Emulator"
    try:
        reference_ini = os.path.join(avd_path, reference_name + '.ini')
        dup_ini = os.path.join(avd_path, dup_name + '.ini')
        reference_avd = os.path.join(avd_path, reference_name + '.avd')
        dup_avd = os.path.join(avd_path, dup_name + '.avd')

        # Copy the files from the referenve avd to the one-time analysis avd
        shutil.copyfile(reference_ini, dup_ini)
        shutil.copytree(reference_avd, dup_avd)

        # Replacing every occuration of the reference avd name to the dup one
        for path_to_update in [dup_ini,
                               os.path.join(dup_avd, 'hardware-qemu.ini'),
                               os.path.join(dup_avd, 'config.ini')
                              ]:
            with io.open(path_to_update, mode='r', encoding="utf8", errors="ignore") as fled:
                replaced_file = fled.read()
                replaced_file = replaced_file.replace(reference_name, dup_name)
            with io.open(path_to_update, 'w') as fled:
                fled.write(replaced_file)
    except:
        PrintException("[ERROR] Duplicating MobSF Emulator")


def start_avd(emulator, avd_name, emulator_port):
    """Start AVD"""
    print "\n[INFO] Starting MobSF Emulator"
    try:
        args = [
            emulator,
            '-avd',
            avd_name,
            "-no-snapshot-save",
            "-netspeed",
            "full",
            "-netdelay",
            "none",
            "-port",
            str(emulator_port),
        ]

        if platform.system() == 'Darwin':
            # There is a strage error in mac with the dyld one in a while..
            # this should fix it..
            if 'DYLD_FALLBACK_LIBRARY_PATH' in os.environ.keys():
                del os.environ['DYLD_FALLBACK_LIBRARY_PATH']

        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        PrintException("[ERROR] Starting MobSF Emulator")


def refresh_avd(adb, avd_path, reference_name, dup_name, emulator):
    """Refresh AVD"""
    print "\n[INFO] Refreshing MobSF Emulator"
    try:
        # Stop existing emulator on the spesified port
        stop_avd(adb)

        # Windows has annoying lock system, it takes time for it to remove the locks after we stopped the emulator
        if platform.system() == 'Windows':
            time.sleep(3)

        # Delete old emulator
        delete_avd(avd_path, dup_name)

        # Copy and replace the contents of the reference machine
        duplicate_avd(avd_path, reference_name, dup_name)

        # Start emulator
        start_avd(emulator, dup_name, settings.AVD_ADB_PORT)
    except:
        PrintException("[ERROR] Refreshing MobSF VM")


def avd_load_wait(adb):
    """Wait for AVD Load"""
    try:
        emulator = get_identifier()

        print "[INFO] Wait for emulator to load"
        args = [adb,
                "-s",
                emulator,
                "wait-for-device"]
        subprocess.call(args)

        print "[INFO] Wait for dev.boot_complete loop"
        while True:
            args = [adb,
                    "-s",
                    emulator,
                    "shell",
                    "getprop",
                    "dev.bootcomplete"]
            try:
                result = subprocess.check_output(args)
            except:
                result = None
            if result is not None and result.strip() == "1":
                break
            else:
                time.sleep(1)

        print "[INFO] Wait for sys.boot_complete loop"
        while True:
            args = [adb,
                    "-s",
                    emulator,
                    "shell",
                    "getprop",
                    "sys.boot_completed"]
            try:
                result = subprocess.check_output(args)
            except:
                result = None
            if result is not None and result.strip() == "1":
                break
            else:
                time.sleep(1)

        print "[INFO] Wait for svc.boot_complete loop"
        while True:
            args = [adb,
                    "-s",
                    emulator,
                    "shell",
                    "getprop",
                    "init.svc.bootanim"]
            try:
                result = subprocess.check_output(args)
            except:
                result = None
            if result is not None and result.strip() == "stopped":
                break
            else:
                time.sleep(1)
        time.sleep(5)
        # Remount the partitions for RW
        subprocess.call([adb, "-s", emulator, "remount"])
        return True
    except:
        PrintException("[ERROR] emulator did not boot properly")
        return False
