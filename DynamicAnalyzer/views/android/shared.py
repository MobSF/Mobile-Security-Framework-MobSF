"""Shared Functions for Android Dynamic Analyzer"""
# -*- coding: utf_8 -*-
import subprocess
import time
import traceback
import logging
from django.conf import settings
from MobSF.utils import PrintException, getADB

logger = logging.getLogger(__name__)


def wait(sec):
    """Wait in Seconds"""
    logger.info("Waiting for " + str(sec) + " seconds...")
    time.sleep(sec)


def get_res():
    """Get Screen Resolution or Device or VM"""
    logger.info("Getting Screen Resolution")
    try:
        adb = getADB()
        resp = subprocess.check_output(
            [adb, "-s", get_identifier(), "shell", "dumpsys", "window"])
        resp = resp.decode("utf-8").split("\n")
        res = ""
        for line in resp:
            if "mUnrestrictedScreen" in line:
                res = line
                break
        res = res.split("(0,0)")[1]
        res = res.strip()
        res = res.split("x")
        if len(res) == 2:
            return res[0], res[1]
            # width, height
        return "", ""
    except:
        PrintException("[ERROR] Getting Screen Resolution")
        return "", ""


def get_identifier():
    """Get Device Type"""
    try:
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
            return settings.DEVICE_IP + ":" + str(settings.DEVICE_ADB_PORT)
        elif settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
            return 'emulator-' + str(settings.AVD_ADB_PORT)
        else:
            return settings.VM_IP + ":" + str(settings.VM_ADB_PORT)
    except:
        PrintException(
            "[ERROR] Getting ADB Connection Identifier for Device/VM")


def adb_command(cmd_list, shell=False, silent=False):
    emulator = get_identifier()
    adb = getADB()

    args = [adb,
            "-s",
            emulator]
    if shell:
        args += ['shell']
    args += cmd_list

    try:
        result = subprocess.check_output(args)
        return result
    except:
        if not silent:
            PrintException("[ERROR] adb_command")
        return None


def connect():
    """Connect to VM/Device"""
    logger.info("Connecting to VM/Device")
    adb = getADB()
    subprocess.call([adb, "kill-server"])
    subprocess.call([adb, "start-server"])
    logger.info("ADB Started")
    wait(5)
    logger.info("Connecting to VM/Device")
    out = subprocess.check_output([adb, "connect", get_identifier()])
    if b"unable to connect" in out:
        raise ValueError("ERROR Connecting to VM/Device. ",
                         out.decode("utf-8").replace("\n", ""))
    try:
        subprocess.call([adb, "-s", get_identifier(), "wait-for-device"])
        logger.info("Mounting")
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
            adb_command(["su", "-c", "mount", "-o",
                         "rw,remount,rw", "/system"], True)
        else:
            adb_command(["su", "-c", "mount", "-o",
                         "rw,remount,rw", "/system"], True)
            # This may not work for VMs other than the default MobSF VM
            adb_command(["mount", "-o", "rw,remount", "-t", "rfs",
                         "/dev/block/sda6", "/system"], True)
    except:
        PrintException("[ERROR]  Connecting to VM/Device")


def install_and_run(apk_path, package, launcher, is_activity):
    """Install APK and Run it"""
    logger.info("Starting App for Dynamic Analysis")
    try:
        adb = getADB()
        logger.info("Installing APK")
        adb_command(["install", "-r", apk_path])
        if is_activity:
            run_app = package + "/" + launcher
            logger.info("Launching APK Main Activity")
            adb_command(["am", "start", "-n", run_app], True)
        else:
            logger.info("App Doesn't have a Main Activity")
            # Handle Service or Give Choice to Select in Future.
        logger.info("Testing Environment is Ready!")
    except:
        PrintException("[ERROR]  Starting App for Dynamic Analysis")
