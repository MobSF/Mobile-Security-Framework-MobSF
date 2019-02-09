"""Core Functions of Android Dynamic Analysis"""
# -*- coding: utf_8 -*-
import os
import re
import ntpath
import io
import json
import random
import time
import socket
import shutil
import threading
import sqlite3 as sq
from django.shortcuts import render
from django.conf import settings
from django.template.defaulttags import register
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.html import escape
import logging
from StaticAnalyzer.models import StaticAnalyzerAndroid
from DynamicAnalyzer.tools.webproxy import (
    start_proxy,
    stop_capfuzz,
    start_fuzz_ui,
    get_ca_dir,
)

from DynamicAnalyzer.views.android.avd import (
    refresh_avd,
    stop_avd
)

from DynamicAnalyzer.views.android.analysis import (
    api_analysis,
    run_analysis,
    download
)
from DynamicAnalyzer.views.android.virtualbox_vm import (
    refresh_vm
)
from DynamicAnalyzer.views.android.shared import (
    connect,
    install_and_run,
    get_res,
    get_identifier,
    wait,
    adb_command,
)
from MobSF.utils import (
    PrintException,
    is_number,
    python_list,
    getADB,
    print_n_send_error_response
)
logger = logging.getLogger(__name__)

# ===========================================
# Dynamic Analyzer Related Views for Android
# ===========================================


"""
Need to improve RCE Detection on Framework, audit all subprocess calls
TCP Connnection to screenshot service needs to be secured.
Globals!
"""

TCP_SERVER_MODE = "off"  # ScreenCast TCP Service Status


@register.filter
def key(d, key_name):
    """To get dict element by key name in template"""
    return d.get(key_name)


def android_dynamic_analyzer(request):
    """Android Dynamic Analyzer View"""
    logger.info("Dynamic Analysis Started")
    try:
        if request.method == 'POST':
            md5_hash = request.POST['md5']
            package = request.POST['pkg']
            launcher = request.POST['lng']
            if re.findall(r';|\$\(|\|\||&&', package) or re.findall(r';|\$\(|\|\||&&', launcher):
                return print_n_send_error_response(request, "Possible RCE Attack")
            if re.match('^[0-9a-f]{32}$', md5_hash):
                # Delete ScreenCast Cache
                screen_file = os.path.join(settings.SCREEN_DIR, 'screen.png')
                if os.path.exists(screen_file):
                    os.remove(screen_file)
                # Delete Contents of Screenshot Dir
                screen_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/screenshots-apk/')
                if os.path.isdir(screen_dir):
                    shutil.rmtree(screen_dir)
                else:
                    os.makedirs(screen_dir)
                # Start DM
                stop_capfuzz(settings.PORT)
                adb = getADB()
                is_avd = False
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
                    logger.info(
                        "MobSF will perform Dynamic Analysis on real Android Device")
                elif settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                    # adb, avd_path, reference_name, dup_name, emulator
                    is_avd = True
                    if not os.path.exists(settings.AVD_EMULATOR):
                        return print_n_send_error_response(request, "Cannot Find AVD Emulator")
                    if not refresh_avd():
                        return print_n_send_error_response(request, "Cannot Refresh AVD")
                else:
                    # Refersh VM
                    refresh_vm(settings.UUID, settings.SUUID, settings.VBOX)
                context = {'md5': md5_hash,
                           'pkg': package,
                           'lng': launcher,
                           'title': 'Start Testing',
                           'AVD': is_avd, }
                template = "dynamic_analysis/start_test.html"
                return render(request, template, context)
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash")
        else:
            return print_n_send_error_response(request, "Only POST allowed")
    except:
        PrintException("DynamicAnalyzer")
        return print_n_send_error_response(request, "Dynamic Analysis Failed.")
# AJAX


def get_env(request):
    """Get Dynamic Analysis Environment for Android"""
    logger.info("Setting up Dynamic Analysis Environment")
    try:
        if request.method == 'POST':
            data = {}
            md5_hash = request.POST['md5']
            package = request.POST['pkg']
            launcher = request.POST['lng']
            if re.findall(r";|\$\(|\|\||&&", package) or re.findall(r";|\$\(|\|\||&&", launcher):
                return print_n_send_error_response(request, "Possible RCE Attack", True)
            if re.match('^[0-9a-f]{32}$', md5_hash):
                base_dir = settings.BASE_DIR
                app_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/')  # APP DIRECTORY
                app_file = md5_hash + '.apk'  # NEW FILENAME
                app_path = app_dir + app_file  # APP PATH
                adb = getADB()
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                    proxy_ip = '127.0.0.1'
                else:
                    proxy_ip = settings.PROXY_IP  # Proxy IP
                start_proxy(settings.PORT, package)
                # vm needs the connect function
                try:
                    if not settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                        connect()
                except Exception as exp:
                    data = {'ready': 'no',
                            'msg': 'Cannot Connect to the VM/Device.',
                            'error': str(exp)}
                    return HttpResponse(json.dumps(data), content_type='application/json')
                # Change True to support non-activity components
                install_and_run(app_path, package, launcher, True)
                screen_width, screen_width = get_res()
                data = {'ready': 'yes',
                        'screen_witdth': screen_width,
                        'screen_height': screen_width, }
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash", True)
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("Setting up Dynamic Analysis Environment")
        return print_n_send_error_response(request, "Environment Setup Failed", True)
# AJAX


def take_screenshot(request):
    """Take Screenshot"""
    logger.info("Taking Screenshot")
    try:
        if request.method == 'POST':
            md5_hash = request.POST['md5']
            if re.match('^[0-9a-f]{32}$', md5_hash):
                data = {}
                rand_int = random.randint(1, 1000000)
                base_dir = settings.BASE_DIR
                # make sure that list only png from this directory
                screen_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                adb_command(
                    ["screencap", "-p", "/data/local/screen.png"], True)
                adb_command(["pull", "/data/local/screen.png",
                             screen_dir + "screenshot-" + str(rand_int) + ".png"])
                logger.info("Screenshot Taken")
                data = {'screenshot': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash", True)
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("Taking Screenshot")
        return print_n_send_error_response(request, "Error Taking Screenshot", True)
# AJAX


def screen_cast(request):
    """Start or Stop ScreenCast Feature"""
    logger.info("Invoking ScreenCast Service in VM/Device")
    try:
        global TCP_SERVER_MODE
        data = {}
        if request.method == 'POST':
            mode = request.POST['mode']
            if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                ip_address = '10.0.2.2'
            else:
                ip_address = settings.SCREEN_IP
            port = str(settings.SCREEN_PORT)
            if mode == "on":
                args = ["am",
                        "startservice",
                        "-a",
                        ip_address + ":" + port,
                        "opensecurity.screencast/.StartScreenCast"]
                data = {'status': 'on'}
                TCP_SERVER_MODE = "on"
            elif mode == "off":
                args = ["am",
                        "force-stop",
                        "opensecurity.screencast"]
                data = {'status': 'off'}
                TCP_SERVER_MODE = "off"
            if (mode in ["on", "off"]):
                try:
                    adb_command(args, True)
                    screen_trd = threading.Thread(target=screencast_service)
                    screen_trd.setDaemon(True)
                    screen_trd.start()
                except:
                    PrintException("Casting Screen")
                    data = {'status': 'error'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                data = {'status': 'failed'}
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("Casting Screen")
        return print_n_send_error_response(request, "Error Casting Screen", True)
# AJAX


def clip_dump(request):
    """Dump Android ClipBoard"""
    logger.info("Starting Clipboard Dump Service in VM/Device")
    try:
        data = {}
        if request.method == 'POST':
            adb = getADB()
            args = ["am",
                    "startservice",
                    "opensecurity.clipdump/.ClipDumper"]
            try:
                adb_command(args, True)
                data = {'status': 'success'}
            except:
                PrintException("Dumping Clipboard")
                data = {'status': 'error'}
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("Dumping Clipboard")
        return print_n_send_error_response(request, "Error Dumping Clipboard", True)

# AJAX


def touch(request):
    """Sending Touch Events"""
    logger.info("Sending Touch Events")
    try:
        data = {}
        if (request.method == 'POST') and (is_number(request.POST['x'])) and (is_number(request.POST['y'])):
            x_axis = request.POST['x']
            y_axis = request.POST['y']
            adb = getADB()
            args = ["input",
                    "tap",
                    x_axis,
                    y_axis]
            data = {'status': 'success'}
            try:
                adb_command(args, True)
            except:
                data = {'status': 'error'}
                PrintException("Performing Touch Action")
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("Sending Touch Events")
        return print_n_send_error_response(request, "Error Sending Touch Events", True)
# AJAX


def execute_adb(request):
    """Execute ADB Commands"""
    logger.info("Executing ADB Commands")
    try:
        if request.method == 'POST':
            data = {}
            cmd = request.POST['cmd']
            resp = "error"
            try:
                resp = adb_command(cmd.split(' '))
            except:
                PrintException("Executing ADB Commands")
            data = {'cmd': 'yes', 'resp': resp.decode("utf8", "ignore")}
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("Executing ADB Commands")
        return print_n_send_error_response(request, "Error running ADB commands", True)

# AJAX


def mobsf_ca(request):
    """Install and Remove MobSF Proxy RootCA"""
    try:
        if request.method == 'POST':
            data = {}
            act = request.POST['action']
            rootca = get_ca_dir()
            adb = getADB()
            if act == "install":
                logger.info("Installing MobSF RootCA")
                adb_command(
                    ["push", rootca, "/data/local/tmp/" + settings.ROOT_CA])
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                    # For some reason, avd emulator does not have cp binary
                    adb_command(["/data/local/tmp/busybox", "cp",
                                 "/data/local/tmp/" + settings.ROOT_CA,
                                 "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                    adb_command(["chmod", "644",
                                 "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                else:
                    adb_command(["su",
                                 "-c",
                                 "cp",
                                 "/data/local/tmp/" + settings.ROOT_CA,
                                 "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                    adb_command(["su",
                                 "-c",
                                 "chmod",
                                 "644",
                                 "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                adb_command(
                    ["rm", "/data/local/tmp/" + settings.ROOT_CA], True)
                data = {'ca': 'installed'}
            elif act == "remove":
                logger.info("Removing MobSF RootCA")
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                    adb_command(
                        ["rm", "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                else:
                    adb_command(["su",
                                 "-c",
                                 "rm",
                                 "/system/etc/security/cacerts/" + settings.ROOT_CA], True)
                data = {'ca': 'removed'}
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("MobSF RootCA Handler")
        return print_n_send_error_response(request, "Error in RootCA Handler", True)

# AJAX


def final_test(request):
    """Collecting Data and Cleanup"""
    global TCP_SERVER_MODE
    logger.info("Collecting Data and Cleaning Up")
    try:
        if request.method == 'POST':
            data = {}
            md5_hash = request.POST['md5']
            package = request.POST['pkg']
            if re.findall(r";|\$\(|\|\||&&", package):
                return print_n_send_error_response(request, "Possible RCE Attack", True)
            if re.match('^[0-9a-f]{32}$', md5_hash):
                # Stop ScreenCast Client if it is running
                TCP_SERVER_MODE = "off"
                base_dir = settings.BASE_DIR
                apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                adb = getADB()
                # Change to check output of subprocess when analysis is done
                # Can't RCE
                os.system(adb + ' -s ' + get_identifier() +
                          ' logcat -d dalvikvm:W ActivityManager:I > "' + apk_dir + 'logcat.txt"')
                logger.info("Downloading Logcat logs")
                adb_command(["pull", "/data/data/de.robv.android.xposed.installer/log/error.log",
                             apk_dir + "x_logcat.txt"])

                logger.info("Downloading Droidmon API Monitor Logcat logs")
                # Can't RCE
                os.system(adb + ' -s ' + get_identifier() +
                          ' shell dumpsys > "' + apk_dir + 'dump.txt"')
                logger.info("Downloading Dumpsys logs")

                adb_command(["am", "force-stop", package], True)
                logger.info("Stopping Application")

                adb_command(
                    ["am", "force-stop", "opensecurity.screencast"], True)
                logger.info("Stopping ScreenCast Service")

                data = {'final': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash", True)
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("Data Collection & Clean Up")
        return print_n_send_error_response(request, "Data Collection & Clean Up failed", True)
# AJAX


def dump_data(request):
    """Downloading Application Data from Device"""
    logger.info("Downloading Application Data from Device")
    try:
        if request.method == 'POST':
            data = {}
            package = request.POST['pkg']
            md5_hash = request.POST['md5']
            if re.match('^[0-9a-f]{32}$', md5_hash):
                if re.findall(r";|\$\(|\|\||&&", package):
                    return print_n_send_error_response(request, "Possible RCE Attack", True)
                base_dir = settings.BASE_DIR
                apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                # Let's try to close Proxy a bit early as we don't have much
                # control on the order of thread execution
                stop_capfuzz(settings.PORT)
                logger.info("Deleting Dump Status File")
                adb_command(["rm", "/sdcard/mobsec_status"], True)
                logger.info("Creating TAR of Application Files.")
                adb_command(["am", "startservice", "-a", package,
                             "opensecurity.ajin.datapusher/.GetPackageLocation"], True)
                logger.info("Waiting for TAR dump to complete...")
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
                    timeout = settings.DEVICE_TIMEOUT
                else:
                    timeout = settings.VM_TIMEOUT
                start_time = time.time()
                while True:
                    current_time = time.time()
                    if b"MOBSEC-TAR-CREATED" in adb_command(["cat", "/sdcard/mobsec_status"], shell=True):
                        break
                    if (current_time - start_time) > timeout:
                        logger.error(
                            "TAR Generation Failed. Process timed out.")
                        break
                logger.info("Dumping Application Files from Device/VM")
                adb_command(["pull", "/data/local/" + package +
                             ".tar", apk_dir + package + ".tar"])
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                    logger.info("Removing package")
                    adb_command(["uninstall", package])
                    stop_avd()
                logger.info("Stopping ADB")
                adb_command(["kill-server"])
                data = {'dump': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash", True)
        else:
            return print_n_send_error_response(request, "Only POST allowed", True)
    except:
        PrintException("Downloading Application Data from Device")
        return print_n_send_error_response(request, "Application Data Dump from Device failed", True)

# AJAX


def exported_activity_tester(request):
    """Exported Activity Tester"""
    logger.info("Exported Activity Tester")
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r";|\$\(|\|\||&&", package):
                return print_n_send_error_response(request, "Possible RCE Attack", True)
            if request.method == 'POST':
                base_dir = settings.BASE_DIR
                app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                screen_dir = os.path.join(app_dir, 'screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                data = {}
                adb = getADB()

                static_android_db = StaticAnalyzerAndroid.objects.filter(
                    MD5=md5_hash)
                if static_android_db.exists():
                    logger.info("Fetching Exported Activity List from DB")
                    exported_act = python_list(
                        static_android_db[0].EXPORTED_ACT)
                    if exported_act:
                        exp_act_no = 0
                        logger.info("Starting Exported Activity Tester...")
                        logger.info("" + str(len(exported_act)) +
                                    " Exported Activities Identified")
                        for line in exported_act:
                            try:
                                exp_act_no += 1
                                logger.info("Launching Exported Activity - " +
                                            str(exp_act_no) + ". " + line)
                                adb_command(
                                    ["am", "start", "-n", package + "/" + line], True)
                                # AVD is much slower, it should get extra time
                                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                                    wait(8)
                                else:
                                    wait(4)
                                adb_command(
                                    ["screencap", "-p", "/data/local/screen.png"], True)
                                #? get appended from Air :-() if activity names are used
                                adb_command(["pull", "/data/local/screen.png",
                                             screen_dir + "expact-" + str(exp_act_no) + ".png"])
                                logger.info("Activity Screenshot Taken")
                                adb_command(
                                    ["am", "force-stop", package], True)
                                logger.info("Stopping App")
                            except:
                                PrintException(
                                    "Exported Activity Tester")
                        data = {'expacttest': 'done'}
                    else:
                        logger.info(
                            "Exported Activity Tester - No Activity Found!")
                        data = {'expacttest': 'noact'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
                else:
                    return print_n_send_error_response(request, "Entry does not exist in DB", True)
            else:
                return print_n_send_error_response(request, "Only POST allowed", True)
        else:
            return print_n_send_error_response(request, "Invalid Scan Hash", True)
    except:
        PrintException("ERROR] Exported Activity Tester")
        return print_n_send_error_response(request, "Error Running Exported Activity Tests", True)

# AJAX


def activity_tester(request):
    """Activity Tester"""
    logger.info("Activity Tester")
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r";|\$\(|\|\||&&", package):
                return print_n_send_error_response(request, "Possible RCE Attack", True)
            if request.method == 'POST':
                base_dir = settings.BASE_DIR
                app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                screen_dir = os.path.join(app_dir, 'screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                data = {}
                adb = getADB()
                static_android_db = StaticAnalyzerAndroid.objects.filter(
                    MD5=md5_hash)
                if static_android_db.exists():
                    logger.info("Fetching Activity List from DB")
                    activities = python_list(static_android_db[0].ACTIVITIES)
                    if activities:
                        act_no = 0
                        logger.info("Starting Activity Tester...")
                        logger.info("" + str(len(activities)) +
                                    " Activities Identified")
                        for line in activities:
                            try:
                                act_no += 1
                                logger.info("Launching Activity - " +
                                            str(act_no) + ". " + line)
                                adb_command(
                                    ["am", "start", "-n", package + "/" + line], True)
                                # AVD is much slower, it should get extra time
                                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                                    wait(8)
                                else:
                                    wait(4)
                                adb_command(
                                    ["screencap", "-p", "/data/local/screen.png"], True)
                                #? get appended from Air :-() if activity names are used
                                adb_command(["pull", "/data/local/screen.png",
                                             screen_dir + "act-" + str(act_no) + ".png"])
                                logger.info("Activity Screenshot Taken")
                                adb_command(
                                    ["am", "force-stop", package], True)
                                logger.info("Stopping App")
                            except:
                                PrintException("Activity Tester")
                        data = {'acttest': 'done'}
                    else:
                        logger.info("Activity Tester - No Activity Found!")
                        data = {'acttest': 'noact'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
                else:
                    return print_n_send_error_response(request, "Entry does not exist in DB", True)
            else:
                return print_n_send_error_response(request, "Only POST allowed", True)
        else:
            return print_n_send_error_response(request, "Invalid Scan Hash", True)
    except:
        PrintException("Activity Tester")
        return print_n_send_error_response(request, "Error Running Activity Tester", True)


def report(request):
    """Dynamic Analysis Report Generation"""
    logger.info("Dynamic Analysis Report Generation")
    try:
        if request.method == 'GET':
            md5_hash = request.GET['md5']
            package = request.GET['pkg']
            if re.findall(r";|\$\(|\|\||&&", package):
                return print_n_send_error_response(request, "Possible RCE Attack")
            if re.match('^[0-9a-f]{32}$', md5_hash):
                app_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/')  # APP DIRECTORY
                download_dir = settings.DWD_DIR
                droidmon_api_loc = os.path.join(app_dir, 'x_logcat.txt')
                api_analysis_result = api_analysis(package, droidmon_api_loc)
                analysis_result = run_analysis(app_dir, md5_hash, package)
                download(md5_hash, download_dir, app_dir, package)
                # Only After Download Process is Done
                imgs = []
                act_imgs = []
                act = {}
                expact_imgs = []
                exp_act = {}
                if os.path.exists(os.path.join(download_dir, md5_hash + "-screenshots-apk/")):
                    try:
                        imp_path = os.path.join(
                            download_dir, md5_hash + "-screenshots-apk/")
                        for img in os.listdir(imp_path):
                            if img.endswith(".png"):
                                if img.startswith("act"):
                                    act_imgs.append(img)
                                elif img.startswith("expact"):
                                    expact_imgs.append(img)
                                else:
                                    imgs.append(img)
                        static_android_db = StaticAnalyzerAndroid.objects.filter(
                            MD5=md5_hash)
                        if static_android_db.exists():
                            logger.info(
                                "\nFetching Exported Activity & Activity List from DB")
                            exported_act = python_list(
                                static_android_db[0].EXPORTED_ACT)
                            act_desc = python_list(
                                static_android_db[0].ACTIVITIES)
                            if act_imgs:
                                if len(act_imgs) == len(act_desc):
                                    act = dict(list(zip(act_imgs, act_desc)))
                            if expact_imgs:
                                if len(expact_imgs) == len(exported_act):
                                    exp_act = dict(
                                        list(zip(expact_imgs, exported_act)))
                        else:
                            logger.warning("Entry does not exists in the DB.")
                    except:
                        PrintException("Screenshot Sorting")
                context = {'md5': md5_hash,
                           'emails': analysis_result["emails"],
                           'urls': analysis_result["urls"],
                           'domains': analysis_result["domains"],
                           'clipboard': analysis_result["clipboard"],
                           'http': analysis_result["web_data"],
                           'xml': analysis_result["xmlfiles"],
                           'sqlite': analysis_result["sqlite_db"],
                           'others': analysis_result["other_files"],
                           'imgs': imgs,
                           'acttest': act,
                           'expacttest': exp_act,
                           'net': api_analysis_result["api_net"],
                           'base64': api_analysis_result["api_base64"],
                           'crypto': api_analysis_result["api_crypto"],
                           'fileio': api_analysis_result["api_fileio"],
                           'binder': api_analysis_result["api_binder"],
                           'divinfo': api_analysis_result["api_deviceinfo"],
                           'cntval': api_analysis_result["api_cntvl"],
                           'sms': api_analysis_result["api_sms"],
                           'sysprop': api_analysis_result["api_sysprop"],
                           'dexload': api_analysis_result["api_dexloader"],
                           'reflect': api_analysis_result["api_reflect"],
                           'sysman': api_analysis_result["api_acntmnger"],
                           'process': api_analysis_result["api_cmd"],
                           'pkg': package,
                           'title': 'Dynamic Analysis'}
                template = "dynamic_analysis/dynamic_analysis.html"
                return render(request, template, context)
            else:
                return print_n_send_error_response(request, "Invalid Scan Hash")
        else:
            return print_n_send_error_response(request, "Only GET allowed")
    except:
        PrintException("Dynamic Analysis Report Generation")
        return print_n_send_error_response(request, "Error Geneating Dynamic Analysis Report")


def handle_sqlite(sfile):
    """SQLite Dump - Readable Text"""
    logger.info("SQLite DB Extraction")
    try:
        data = ''
        con = sq.connect(sfile)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cur.fetchall()
        for table in tables:
            data += "\nTABLE: " + table[0] + \
                " \n=====================================================\n"
            cur.execute("PRAGMA table_info('%s')" % table)
            rows = cur.fetchall()
            head = ''
            for sq_row in rows:
                elm_data = sq_row[1]
                head += elm_data + " | "
            data += head + " \n============================================" + \
                "=========================\n"
            cur.execute("SELECT * FROM '%s'" % table)
            rows = cur.fetchall()
            for sq_row in rows:
                dat = ''
                for each_row in sq_row:
                    dat += str(each_row) + " | "
                data += dat + "\n"
        return data
    except:
        PrintException("SQLite DB Extraction")


def view(request):
    """View File"""
    logger.info("Viewing File")
    try:
        typ = ''
        fil = ''
        rtyp = ''
        dat = ''
        if re.match('^[0-9a-f]{32}$', request.GET['md5']):
            fil = request.GET['file']
            md5_hash = request.GET['md5']
            typ = request.GET['type']
            src = os.path.join(settings.UPLD_DIR,
                               md5_hash + '/DYNAMIC_DeviceData/')
            sfile = os.path.join(src, fil)
            # Prevent Directory Traversal Attacks
            if ("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil):
                return print_n_send_error_response(request, "Path Traversal Attack Detected")
            else:
                with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as flip:
                    dat = flip.read()
                if (fil.endswith('.xml')) and (typ == 'xml'):
                    rtyp = 'xml'
                elif typ == 'db':
                    dat = handle_sqlite(sfile)
                    rtyp = 'asciidoc'
                elif typ == 'others':
                    rtyp = 'asciidoc'
                else:
                    return print_n_send_error_response(request, "File Type not supported")
                context = {'title': escape(ntpath.basename(fil)), 'file': escape(
                    ntpath.basename(fil)), 'dat': dat, 'type': rtyp, }
                template = "general/view.html"
                return render(request, template, context)
        else:
            return print_n_send_error_response(request, "Invalid Scan Hash")
    except:
        PrintException("Viewing File")
        return print_n_send_error_response(request, "ERROR Viewing File")


def capfuzz_start(request):
    """Start CapFuzz UI"""
    logger.info("Starting CapFuzz Web UI")
    try:
        stop_capfuzz(settings.PORT)
        start_fuzz_ui(settings.PORT)
        time.sleep(3)
        logger.info("CapFuzz UI Started")
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ""
        return HttpResponseRedirect('http://localhost:' + str(settings.PORT) + "/dashboard/" + project)
    except:
        PrintException("Starting CapFuzz Web UI")
        return print_n_send_error_response(request, "Error Starting CapFuzz UI")


def screencast_service():
    """Start or Stop ScreenCast Services"""
    global TCP_SERVER_MODE
    logger.info("ScreenCast Service Status: " + TCP_SERVER_MODE)
    try:
        screen_dir = settings.SCREEN_DIR
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)

        screen_socket = socket.socket()
        if TCP_SERVER_MODE == "on":
            screen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_AVD":
                addr = ('127.0.0.1', settings.SCREEN_PORT)
            else:
                addr = (settings.SCREEN_IP, settings.SCREEN_PORT)
            screen_socket.bind(addr)
            screen_socket.listen(10)
            while TCP_SERVER_MODE == "on":
                screens, address = screen_socket.accept()
                logger.info("Got Connection from: %s", address[0])
                if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
                    ip_address = settings.DEVICE_IP
                else:
                    ip_address = settings.VM_IP
                if address[0] in [ip_address, '127.0.0.1']:
                    # Very Basic Check to ensure that only MobSF VM/Device/Emulator
                    # is allowed to connect to MobSF ScreenCast Service.
                    with open(screen_dir + 'screen.png', 'wb') as flip:
                        while True:
                            data = screens.recv(1024)
                            if not data:
                                break
                            flip.write(data)
                else:
                    logger.warning("\n[ATTACK] An unknown client :" + address[0] + " is trying " +
                                "to make a connection with MobSF ScreenCast Service!")
        elif TCP_SERVER_MODE == "off":
            screen_socket.close()
    except:
        screen_socket.close()
        PrintException("ScreenCast Server")
