# -*- coding: utf_8 -*-
import subprocess
import os
import re
import shutil
import tarfile
import ntpath
import io
import json
import random
import time
import unicodedata
import socket
import threading
import base64
import sqlite3 as sq
import platform
import io

from django.shortcuts import render
from django.conf import settings
from django.template.defaulttags import register
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.html import escape

from StaticAnalyzer.models import StaticAnalyzerAndroid
from DynamicAnalyzer.pyWebProxy.pywebproxy import *
from MobSF.utils import PrintException, is_number, python_list, isBase64, isFileExists, getADB
from MalwareAnalyzer.views import MalwareCheck

#===================================
# Dynamic Analyzer Calls begins here!
#===================================
'''
Need to improve RCE Detection on Framework, audit all subprocess calls
TCP Connnection to screenshot service needs to be secured.
Globals!
'''
tcp_server_mode = "off"  # ScreenCast TCP Service Status


@register.filter
def key(d, key_name):
    return d.get(key_name)

def stopAVD(adb):
    print "\n[INFO] Stopping MobSF Emulator"
    try:
        # adb -s emulator-xxxx emu kill
        args = [adb, '-s', getIdentifier(), 'emu', 'kill']
        subprocess.call(args)
    except:
        PrintException("[ERROR] Stopping MobSF Emulator")


def deleteAVD(avd_path, avd_name):
    print "\n[INFO] Deleting emulator files"
    try:
        config_file = os.path.join(avd_path, avd_name + '.ini')
        if os.path.exists(config_file):
            os.remove(config_file)

        # TODO: Sometimes there is an error here because of the locks that avd does - check this out
        avd_folder = os.path.join(avd_path, avd_name + '.avd')
        if os.path.isdir(avd_folder):
            shutil.rmtree(avd_folder)
    except:
        PrintException("[ERROR] Deleting emulator files")


def duplicateAVD(avd_path, reference_name, dup_name):
    print "\n[INFO] Duplicating MobSF Emulator"
    try:
        reference_ini = os.path.join(avd_path, reference_name + '.ini')
        dup_ini       = os.path.join(avd_path, dup_name + '.ini')
        reference_avd = os.path.join(avd_path, reference_name + '.avd')
        dup_avd       = os.path.join(avd_path, dup_name + '.avd')

        # Copy the files from the referenve avd to the one-time analysis avd
        shutil.copyfile(reference_ini, dup_ini)
        shutil.copytree(reference_avd, dup_avd)

        # Replacing every occuration of the reference avd name to the dup one
        for path_to_update in [
            dup_ini,
            os.path.join(dup_avd, 'hardware-qemu.ini'),
            os.path.join(dup_avd, 'config.ini')
        ]:
            with io.open(path_to_update, 'r') as fd:
                replaced_file = fd.read()
                replaced_file = replaced_file.replace(reference_name, dup_name)
            with io.open(path_to_update, 'w') as fd:
                fd.write(replaced_file)
    except:
        PrintException("[ERROR] Duplicating MobSF Emulator")


def startAVD(emulator, avd_name, emulator_port):
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
            # There is a strage error in mac with the dyld one in a while.. this should fix it..
            if 'DYLD_FALLBACK_LIBRARY_PATH' in os.environ.keys():
                del os.environ['DYLD_FALLBACK_LIBRARY_PATH']

        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        PrintException("[ERROR] Starting MobSF Emulator")


def refreshAVD(adb, avd_path, reference_name, dup_name, emulator):
    print "\n[INFO] Refreshing MobSF Emulator"
    try:
        # Stop existing emulator on the spesified port
        stopAVD(adb)

        # Delete old emulator
        deleteAVD(avd_path, dup_name)

        # Copy and replace the contents of the reference machine
        duplicateAVD(avd_path, reference_name, dup_name)

        #Start emulator
        startAVD(emulator, dup_name, settings.AVD_ADB_PORT)
    except:
        PrintException("[ERROR] Refreshing MobSF VM")


def avd_load_wait(adb):
    try:
        emulator = getIdentifier()

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
                result =  subprocess.check_output(args)
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
                result =  subprocess.check_output(args)
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
                result =  subprocess.check_output(args)
            except:
                result = None
            if result is not None and result.strip() == "stopped":
                break
            else:
                time.sleep(1)
        time.sleep(5)
        return True
    except:
        PrintException("[ERROR] emulator did not boot properly")
        return False

def refreshAVD(adb, avd_path, reference_name, dup_name, emulator):
    print "\n[INFO] Refreshing MobSF Emulator"
    try:
        # Stop existing emulator on the spesified port
        stopAVD(adb)

        # Delete old emulator
        deleteAVD(avd_path, dup_name)

        # Copy and replace the contents of the reference machine
        duplicateAVD(avd_path, reference_name, dup_name)

        #Start emulator
        startAVD(emulator, dup_name, settings.AVD_ADB_PORT)
    except:
        PrintException("[ERROR] Refreshing MobSF VM")


def DynamicAnalyzer(request):

    print "\n[INFO] Dynamic Analysis Started"
    try:
        if request.method == 'POST':
            MD5 = request.POST['md5']
            PKG = request.POST['pkg']
            LNCH = request.POST['lng']
            if re.findall(";|\$\(|\|\||&&", PKG) or re.findall(";|\$\(|\|\||&&", LNCH):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                # Delete ScreenCast Cache
                SCREEN_FILE = os.path.join(settings.SCREEN_DIR, 'screen.png')
                if os.path.exists(SCREEN_FILE):
                    os.remove(SCREEN_FILE)
                # Delete Contents of Screenshot Dir
                SCRDIR = os.path.join(
                    settings.UPLD_DIR, MD5 + '/screenshots-apk/')
                if os.path.isdir(SCRDIR):
                    shutil.rmtree(SCRDIR)
                # Start DM
                Proxy("", "", "", "")
                TOOLS_DIR = os.path.join(settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                adb = getADB(TOOLS_DIR)
                if settings.REAL_DEVICE:
                    print "\n[INFO] MobSF will perform Dynamic Analysis on real Android Device"
                elif settings.AVD:
                    #adb, avd_path, reference_name, dup_name, emulator
                    refreshAVD(adb, settings.AVD_PATH, settings.AVD_REFERENCE_NAME, settings.AVD_DUP_NAME, settings.AVD_EMULATOR)
                else:
                    # Refersh VM
                    RefreshVM(settings.UUID, settings.SUUID, settings.VBOX)
                context = {'md5': MD5,
                           'pkg': PKG,
                           'lng': LNCH,
                           'title': 'Start Testing', }
                template = "dynamic_analysis/start_test.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] DynamicAnalyzer")
        return HttpResponseRedirect('/error/')

# AJAX


def GetEnv(request):

    print "\n[INFO] Setting up Dynamic Analysis Environment"
    try:
        if request.method == 'POST':
            data = {}
            MD5 = request.POST['md5']
            PKG = request.POST['pkg']
            LNCH = request.POST['lng']
            if re.findall(";|\$\(|\|\||&&", PKG) or re.findall(";|\$\(|\|\||&&", LNCH):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                DIR = settings.BASE_DIR
                APP_DIR = os.path.join(
                    settings.UPLD_DIR, MD5 + '/')  # APP DIRECTORY
                APP_FILE = MD5 + '.apk'  # NEW FILENAME
                APP_PATH = APP_DIR + APP_FILE  # APP PATH
                TOOLS_DIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                adb = getADB(TOOLS_DIR)
                DWD_DIR = settings.DWD_DIR
                if settings.AVD:
                    PROXY_IP = '127.0.0.1'
                else:
                    PROXY_IP = settings.PROXY_IP  # Proxy IP
                PORT = str(settings.PORT)  # Proxy Port
                WebProxy(APP_DIR, PROXY_IP, PORT)
                # AVD only needs to wait, vm needs the connect function
                if settings.AVD:
                    if not avd_load_wait(adb):
                        return HttpResponseRedirect('/error/')
                else:
                    Connect(TOOLS_DIR)
                # Change True to support non-activity components
                InstallRun(TOOLS_DIR, APP_PATH, PKG, LNCH, True)
                SCREEN_WIDTH, SCREEN_HEIGHT = GetRes()
                data = {'ready': 'yes',
                        'screen_witdth': SCREEN_WIDTH,
                        'screen_height': SCREEN_HEIGHT, }
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Setting up Dynamic Analysis Environment")
        return HttpResponseRedirect('/error/')
# AJAX


def TakeScreenShot(request):
    print "\n[INFO] Taking Screenshot"
    try:
        if request.method == 'POST':
            MD5 = request.POST['md5']
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                data = {}
                r = random.randint(1, 1000000)
                DIR = settings.BASE_DIR
                # make sure that list only png from this directory
                SCRDIR = os.path.join(
                    settings.UPLD_DIR, MD5 + '/screenshots-apk/')
                TOOLSDIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                adb = getADB(TOOLSDIR)
                subprocess.call([adb, "-s", getIdentifier(), "shell",
                                 "screencap", "-p", "/data/local/screen.png"])
                subprocess.call([adb, "-s", getIdentifier(), "pull",
                                 "/data/local/screen.png", SCRDIR + "screenshot-" + str(r) + ".png"])
                print "\n[INFO] Screenshot Taken"
                data = {'screenshot': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Taking Screenshot")
        return HttpResponseRedirect('/error/')
# AJAX


def ScreenCast(request):
    print "\n[INFO] Invoking ScreenCast Service in VM/Device"
    try:
        global tcp_server_mode
        data = {}
        if (request.method == 'POST'):
            mode = request.POST['mode']
            TOOLSDIR = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
            adb = getADB(TOOLSDIR)
            if settings.AVD:
                IP = '10.0.2.2'
            else:
                IP = settings.SCREEN_IP
            PORT = str(settings.SCREEN_PORT)
            if mode == "on":
                args = [adb, "-s", getIdentifier(), "shell", "am", "startservice",
                        "-a", IP + ":" + PORT, "opensecurity.screencast/.StartScreenCast"]
                data = {'status': 'on'}
                tcp_server_mode = "on"
            elif mode == "off":
                args = [adb, "-s", getIdentifier(), "shell", "am",
                        "force-stop", "opensecurity.screencast"]
                data = {'status': 'off'}
                tcp_server_mode = "off"
            if (mode in ["on", "off"]):
                try:
                    subprocess.call(args)
                    t = threading.Thread(target=ScreenCastService)
                    t.setDaemon(True)
                    t.start()
                except:
                    PrintException("[ERROR] Casting Screen")
                    data = {'status': 'error'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                data = {'status': 'failed'}
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("[ERROR] Casting Screen")
        return HttpResponseRedirect('/error/')

# AJAX


def clip_dump(request):
    """
    Dump Android ClipBoard
    """
    print "\n[INFO] Starting Clipboard Dump Service in VM/Device"
    try:
        data = {}
        if request.method == 'POST':
            tools_dir = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
            adb = getADB(tools_dir)
            args = [adb, "-s", getIdentifier(), "shell", "am", "startservice",
                         "opensecurity.clipdump/.ClipDumper"]
            try:
                subprocess.call(args)
                data = {'status': 'success'}
            except:
                PrintException("[ERROR] Dumping Clipboard")
                data = {'status': 'error'}
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("[ERROR] Dumping Clipboard")
        return HttpResponseRedirect('/error/')

# AJAX


def Touch(request):
    print "\n[INFO] Sending Touch Events"
    try:
        data = {}
        if (request.method == 'POST') and (is_number(request.POST['x'])) and (is_number(request.POST['y'])):
            x_axis = request.POST['x']
            y_axis = request.POST['y']
            TOOLSDIR = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
            adb = getADB(TOOLSDIR)
            args = [adb, "-s", getIdentifier(), "shell", "input",
                    "tap", x_axis, y_axis]
            data = {'status': 'success'}
            try:
                subprocess.call(args)
            except:
                data = {'status': 'error'}
                PrintException("[ERROR] Performing Touch Action")
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    except:
        PrintException("[ERROR] Sending Touch Events")
        return HttpResponseRedirect('/error/')
# AJAX


def ExecuteADB(request):
    print "\n[INFO] Executing ADB Commands"
    try:
        if request.method == 'POST':
            data = {}
            CMD = request.POST['cmd']
            '''
            #Allow it Since it's functional
            if re.findall(";|\$\(|\|\||&&",CMD):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            '''
            TOOLSDIR = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
            adb = getADB(TOOLSDIR)
            args = [adb, "-s", getIdentifier()] + CMD.split(' ')
            resp = "error"
            try:
                resp = subprocess.check_output(args)
            except:
                PrintException("[ERROR] Executing ADB Commands")
            data = {'cmd': 'yes', 'resp': resp}
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Executing ADB Commands")
        return HttpResponseRedirect('/error/')

# AJAX


def MobSFCA(request):
    try:
        if request.method == 'POST':
            data = {}
            act = request.POST['action']
            TOOLSDIR = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
            ROOTCA = os.path.join(
                settings.BASE_DIR, 'DynamicAnalyzer/pyWebProxy/ca.crt')
            adb = getADB(TOOLSDIR)
            if act == "install":
                print "\n[INFO] Installing MobSF RootCA"
                subprocess.call([adb, "-s", getIdentifier(), "push",
                                 ROOTCA, "/data/local/tmp/" + settings.ROOT_CA])
                subprocess.call([adb, "-s", getIdentifier(), "shell", "su", "-c", "cp", "/data/local/tmp/" +
                                 settings.ROOT_CA, "/system/etc/security/cacerts/" + settings.ROOT_CA])
                subprocess.call([adb, "-s", getIdentifier(), "shell", "su", "-c",
                                 "chmod", "644", "/system/etc/security/cacerts/" + settings.ROOT_CA])
                subprocess.call([adb, "-s", getIdentifier(), "shell",
                                 "rm", "/data/local/tmp/" + settings.ROOT_CA])
                data = {'ca': 'installed'}
            elif act == "remove":
                print "\n[INFO] Removing MobSF RootCA"
                subprocess.call([adb, "-s", getIdentifier(), "shell", "su", "-c",
                                 "rm", "/system/etc/security/cacerts/" + settings.ROOT_CA])
                data = {'ca': 'removed'}
            return HttpResponse(json.dumps(data), content_type='application/json')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] MobSF RootCA Handler")
        return HttpResponseRedirect('/error/')

# AJAX


def FinalTest(request):
    # Closing Services in VM/Device
    global tcp_server_mode
    print "\n[INFO] Collecting Data and Cleaning Up"
    try:
        if request.method == 'POST':
            data = {}
            MD5 = request.POST['md5']
            PACKAGE = request.POST['pkg']
            if re.findall(";|\$\(|\|\||&&", PACKAGE):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                # Stop ScreenCast Client if it is running
                tcp_server_mode = "off"
                DIR = settings.BASE_DIR
                APKDIR = os.path.join(settings.UPLD_DIR, MD5 + '/')
                TOOLSDIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                adb = getADB(TOOLSDIR)
                # Change to check output of subprocess when analysis is done
                # Can't RCE
                os.system(adb + ' -s ' + getIdentifier() +
                          ' logcat -d dalvikvm:W ActivityManager:I > "' + APKDIR + 'logcat.txt"')
                print "\n[INFO] Downloading Logcat logs"
                #os.system(adb+' -s '+getIdentifier()+' logcat -d Xposed:I *:S > "'+APKDIR + 'x_logcat.txt"')
                subprocess.call([adb, "-s", getIdentifier(), "pull",
                                 "/data/data/de.robv.android.xposed.installer/log/error.log", APKDIR + "x_logcat.txt"])

                print "\n[INFO] Downloading Droidmon API Monitor Logcat logs"
                # Can't RCE
                os.system(adb + ' -s ' + getIdentifier() +
                          ' shell dumpsys > "' + APKDIR + 'dump.txt"')
                print "\n[INFO] Downloading Dumpsys logs"
                subprocess.call([adb, "-s", getIdentifier(),
                                 "shell", "am", "force-stop", PACKAGE])
                print "\n[INFO] Stopping Application"

                subprocess.call([adb, "-s", getIdentifier(), "shell",
                                 "am", "force-stop", "opensecurity.screencast"])
                print "\n[INFO] Stopping ScreenCast Service"

                data = {'final': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Clean Up")
        return HttpResponseRedirect('/error/')
# AJAX


def DumpData(request):
    # Closing External Services and Dumping data
    print "\n[INFO] Device Data Dump"
    try:
        if request.method == 'POST':
            data = {}
            PACKAGE = request.POST['pkg']
            MD5 = request.POST['md5']
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                if re.findall(";|\$\(|\|\||&&", PACKAGE):
                    print "[ATTACK] Possible RCE"
                    return HttpResponseRedirect('/error/')
                DIR = settings.BASE_DIR
                APKDIR = os.path.join(settings.UPLD_DIR, MD5 + '/')
                TOOLSDIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                adb = getADB(TOOLSDIR)
                # Let's try to close Proxy a bit early as we don't have much
                # control on the order of thread execution
                Proxy("", "", "", "")
                print "\n[INFO] Deleting Dump Status File"
                subprocess.call([adb, "-s", getIdentifier(),
                                 "shell", "rm", "/sdcard/mobsec_status"])
                print "\n[INFO] Creating TAR of Application Files."
                if settings.AVD:
                    #" tar -cvf /data/local/"+pkg+".tar /data/data/"+pkg+"/",
                    subprocess.call([adb, "-s", getIdentifier(), "shell", "/data/local/tmp/tar.sh", PACKAGE])
                else:
                    subprocess.call([adb, "-s", getIdentifier(), "shell", "am", "startservice",
                                     "-a", PACKAGE, "opensecurity.ajin.datapusher/.GetPackageLocation"])
                print "\n[INFO] Waiting for TAR dump to complete..."
                if settings.REAL_DEVICE:
                    timeout = settings.DEVICE_TIMEOUT
                else:
                    timeout = settings.VM_TIMEOUT
                start_time = time.time()
                while True:
                    current_time = time.time()
                    if "MOBSEC-TAR-CREATED" in subprocess.check_output([adb, "-s", getIdentifier(), "shell", "cat", "/sdcard/mobsec_status"]):
                        break
                    if (current_time - start_time) > timeout:
                        print "\n[ERROR] TAR Generation Failed. Process timed out."
                        break
                print "\n[INFO] Dumping Application Files from Device/VM"
                subprocess.call([adb, "-s", getIdentifier(), "pull",
                                 "/data/local/" + PACKAGE + ".tar", APKDIR + PACKAGE + ".tar"])
                print "\n[INFO] Stopping ADB"
                subprocess.call([adb, "-s", getIdentifier(), "kill-server"])
                data = {'dump': 'yes'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Device Data Dump")
        return HttpResponseRedirect('/error/')
# AJAX


def ExportedActivityTester(request):
    print "\n[INFO] Exported Activity Tester"
    try:
        MD5 = request.POST['md5']
        PKG = request.POST['pkg']
        m = re.match('^[0-9a-f]{32}$', MD5)
        if m:
            if re.findall(";|\$\(|\|\||&&", PKG):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            if request.method == 'POST':
                DIR = settings.BASE_DIR
                APP_DIR = os.path.join(settings.UPLD_DIR, MD5 + '/')
                TOOLS_DIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                SCRDIR = os.path.join(APP_DIR, 'screenshots-apk/')
                data = {}
                adb = getADB(TOOLS_DIR)

                DB = StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists():
                    print "\n[INFO] Fetching Exported Activity List from DB"
                    EXPORTED_ACT = python_list(DB[0].EXPORTED_ACT)
                    if EXPORTED_ACT:
                        n = 0
                        print "\n[INFO] Starting Exported Activity Tester..."
                        print "\n[INFO] " + str(len(EXPORTED_ACT)) + " Exported Activities Identified"
                        for line in EXPORTED_ACT:
                            try:
                                n += 1
                                print "\n[INFO] Launching Exported Activity - " + str(n) + ". " + line
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "am", "start", "-n", PKG + "/" + line])
                                Wait(4)
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "screencap", "-p", "/data/local/screen.png"])
                                #? get appended from Air :-() if activity names are used
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "pull", "/data/local/screen.png", SCRDIR + "expact-" + str(n) + ".png"])
                                print "\n[INFO] Activity Screenshot Taken"
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "am", "force-stop", PKG])
                                print "\n[INFO] Stopping App"
                            except:
                                PrintException(
                                    "[ERROR] Exported Activity Tester")
                        data = {'expacttest': 'done'}
                    else:
                        print "\n[INFO] Exported Activity Tester - No Activity Found!"
                        data = {'expacttest': 'noact'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
                else:
                    print "\n[ERROR] Entry does not exist in DB."
                    return HttpResponseRedirect('/error/')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("ERROR] Exported Activity Tester")
        return HttpResponseRedirect('/error/')

# AJAX


def ActivityTester(request):
    print "\n[INFO] Activity Tester"
    try:
        MD5 = request.POST['md5']
        PKG = request.POST['pkg']
        m = re.match('^[0-9a-f]{32}$', MD5)
        if m:
            if re.findall(";|\$\(|\|\||&&", PKG):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            if request.method == 'POST':
                DIR = settings.BASE_DIR
                APP_DIR = os.path.join(settings.UPLD_DIR, MD5 + '/')
                TOOLS_DIR = os.path.join(
                    DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
                SCRDIR = os.path.join(APP_DIR, 'screenshots-apk/')
                data = {}
                adb = getADB(TOOLS_DIR)
                DB = StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists():
                    print "\n[INFO] Fetching Activity List from DB"
                    ACTIVITIES = python_list(DB[0].ACTIVITIES)
                    if ACTIVITIES:
                        n = 0
                        print "\n[INFO] Starting Activity Tester..."
                        print "\n[INFO] " + str(len(ACTIVITIES)) + " Activities Identified"
                        for line in ACTIVITIES:
                            try:
                                n += 1
                                print "\n[INFO] Launching Activity - " + str(n) + ". " + line
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "am", "start", "-n", PKG + "/" + line])
                                # AVD is much slower, it should get extra time
                                if settings.AVD:
                                    Wait(6)
                                else:
                                    Wait(4)
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "screencap", "-p", "/data/local/screen.png"])
                                #? get appended from Air :-() if activity names are used
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "pull", "/data/local/screen.png", SCRDIR + "act-" + str(n) + ".png"])
                                print "\n[INFO] Activity Screenshot Taken"
                                subprocess.call(
                                    [adb, "-s", getIdentifier(), "shell", "am", "force-stop", PKG])
                                print "\n[INFO] Stopping App"
                            except:
                                PrintException("Activity Tester")
                        data = {'acttest': 'done'}
                    else:
                        print "\n[INFO] Activity Tester - No Activity Found!"
                        data = {'acttest': 'noact'}
                    return HttpResponse(json.dumps(data), content_type='application/json')
                else:
                    print "\n[ERROR] Entry does not exist in DB."
                    return HttpResponseRedirect('/error/')
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Activity Tester")
        return HttpResponseRedirect('/error/')


def Wait(sec):
    print "\n[INFO] Waiting for " + str(sec) + " seconds..."
    time.sleep(sec)


def Report(request):
    print "\n[INFO] Dynamic Analysis Report Generation"
    try:
        if request.method == 'GET':
            MD5 = request.GET['md5']
            PKG = request.GET['pkg']
            if re.findall(";|\$\(|\|\||&&", PKG):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            m = re.match('^[0-9a-f]{32}$', MD5)
            if m:
                DIR = settings.BASE_DIR
                APP_DIR = os.path.join(
                    settings.UPLD_DIR, MD5 + '/')  # APP DIRECTORY
                DWD_DIR = settings.DWD_DIR
                DRDMONAPISLOC = os.path.join(APP_DIR, 'x_logcat.txt')
                API_NET, API_BASE64, API_FILEIO, API_BINDER, API_CRYPTO, API_DEVICEINFO, API_CNTVL, API_SMS, API_SYSPROP, API_DEXLOADER, API_RELECT, API_ACNTMNGER, API_CMD = APIAnalysis(
                    PKG, DRDMONAPISLOC)
                URL, DOMAINS, EMAIL, CLIPBOARD, HTTP, XML, SQLiteDB, OtherFiles = RunAnalysis(
                    APP_DIR, MD5, PKG)
                Download(MD5, DWD_DIR, APP_DIR, PKG)
                # Only After Download Process is Done
                IMGS = []
                ACTIMGS = []
                ACT = {}
                EXPACTIMGS = []
                EXPACT = {}
                if os.path.exists(os.path.join(DWD_DIR, MD5 + "-screenshots-apk/")):
                    try:
                        for img in os.listdir(os.path.join(DWD_DIR, MD5 + "-screenshots-apk/")):
                            if img.endswith(".png"):
                                if img.startswith("act"):
                                    ACTIMGS.append(img)
                                elif img.startswith("expact"):
                                    EXPACTIMGS.append(img)
                                else:
                                    IMGS.append(img)
                        DB = StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                        if DB.exists():
                            print "\n[INFO] Fetching Exported Activity & Activity List from DB"
                            EXPORTED_ACT = python_list(DB[0].EXPORTED_ACT)
                            ACTDESC = python_list(DB[0].ACTIVITIES)
                            if ACTIMGS:
                                if len(ACTIMGS) == len(ACTDESC):
                                    ACT = dict(zip(ACTIMGS, ACTDESC))
                            if EXPACTIMGS:
                                if len(EXPACTIMGS) == len(EXPORTED_ACT):
                                    EXPACT = dict(
                                        zip(EXPACTIMGS, EXPORTED_ACT))
                        else:
                            print "\n[WARNING] Entry does not exists in the DB."
                    except:
                        PrintException("[ERROR] Screenshot Sorting")

                context = {'emails': EMAIL,
                           'urls': URL,
                           'domains': DOMAINS,
                           'clipboard': CLIPBOARD,
                           'md5': MD5,
                           'http': HTTP,
                           'xml': XML,
                           'sqlite': SQLiteDB,
                           'others': OtherFiles,
                           'imgs': IMGS,
                           'acttest': ACT,
                           'expacttest': EXPACT,
                           'net': API_NET,
                           'base64': API_BASE64,
                           'crypto': API_CRYPTO,
                           'fileio': API_FILEIO,
                           'binder': API_BINDER,
                           'divinfo': API_DEVICEINFO,
                           'cntval': API_CNTVL,
                           'sms': API_SMS,
                           'sysprop': API_SYSPROP,
                           'dexload': API_DEXLOADER,
                           'reflect': API_RELECT,
                           'sysman': API_ACNTMNGER,
                           'process': API_CMD,
                           'pkg': PKG,
                           'title': 'Dynamic Analysis'}
                template = "dynamic_analysis/dynamic_analysis.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Dynamic Analysis Report Generation")
        return HttpResponseRedirect('/error/')


def RefreshVM(uuid, snapshot_uuid, vbox_exe):
    print "\n[INFO] Refreshing MobSF VM"
    try:
        # Close VM
        args = [vbox_exe, 'controlvm', uuid, 'poweroff']
        subprocess.call(args)
        print "\n[INFO] VM Closed"
        # Restore Snapshot
        args = [vbox_exe, 'snapshot', uuid, 'restore', snapshot_uuid]
        subprocess.call(args)
        print "\n[INFO] VM Restore Snapshot"
        # Start Fresh VM
        args = [vbox_exe, 'startvm', uuid]
        subprocess.call(args)
        print "\n[INFO] VM Starting"
    except:
        PrintException("[ERROR] Refreshing MobSF VM")


def WebProxy(APKDIR, ip, port):
    print "\n[INFO] Starting Web Proxy"
    try:
        Proxy(ip, port, APKDIR, "on")
    except:
        PrintException("[ERROR] Starting Web Proxy")


def Connect(TOOLSDIR):
    print "\n[INFO] Connecting to VM/Device"
    try:
        adb = getADB(TOOLSDIR)
        subprocess.call([adb, "kill-server"])
        subprocess.call([adb, "start-server"])
        print "\n[INFO] ADB Started"
        Wait(5)
        print "\n[INFO] Connecting to VM/Device"
        subprocess.call([adb, "connect", getIdentifier()])
        subprocess.call([adb, "-s", getIdentifier(), "wait-for-device"])
        print "\n[INFO] Mounting"
        if settings.REAL_DEVICE:
            subprocess.call([adb, "-s", getIdentifier(), "shell",
                             "su", "-c", "mount", "-o", "rw,remount,rw", "/system"])
        else:
            subprocess.call([adb, "-s", getIdentifier(), "shell",
                             "su", "-c", "mount", "-o", "rw,remount,rw", "/system"])
            # This may not work for VMs other than the default MobSF VM
            subprocess.call([adb, "-s", getIdentifier(), "shell", "mount",
                             "-o", "rw,remount", "-t", "rfs", "/dev/block/sda6", "/system"])
    except:
        PrintException("[ERROR]  Connecting to VM/Device")


def InstallRun(TOOLSDIR, APKPATH, PACKAGE, LAUNCH, isACT):
    print "\n[INFO] Starting App for Dynamic Analysis"
    try:
        adb = getADB(TOOLSDIR)
        print "\n[INFO] Installing APK"
        subprocess.call([adb, "-s", getIdentifier(), "install", "-r", APKPATH])
        if isACT:
            runApp = PACKAGE + "/" + LAUNCH
            print "\n[INFO] Launching APK Main Activity"
            subprocess.call([adb, "-s", getIdentifier(),
                             "shell", "am", "start", "-n", runApp])
        else:
            print "\n[INFO] App Doesn't have a Main Activity"
            # Handle Service or Give Choice to Select in Future.
            pass
        print "[INFO] Testing Environment is Ready!"
    except:
        PrintException("[ERROR]  Starting App for Dynamic Analysis")


def HandleSqlite(SFile):
    print "\n[INFO] SQLite DB Extraction"
    try:
        data = ''
        con = sq.connect(SFile)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cur.fetchall()
        for table in tables:
            data += "\nTABLE: " + str(table[0]).decode('utf8', 'ignore') + \
                " \n=====================================================\n"
            cur.execute("PRAGMA table_info('%s')" % table)
            rows = cur.fetchall()
            head = ''
            for r in rows:
                z = r[1]
                if type(z) is unicode:
                    z = unicodedata.normalize(
                        'NFKD', z).encode('ascii', 'ignore')
                head += str(z).decode('utf8', 'ignore') + " | "
            data += head + " \n=====================================================================\n"
            cur.execute("SELECT * FROM '%s'" % table)
            rows = cur.fetchall()
            for r in rows:
                dat = ''
                for x in r:
                    if type(x) is unicode:
                        x = unicodedata.normalize(
                            'NFKD', x).encode('ascii', 'ignore')
                    dat += str(x).decode('utf8', 'ignore') + " | "
                data += dat + "\n"
        return data
    except:
        PrintException("[ERROR] SQLite DB Extraction")
        pass


def APIAnalysis(PKG, LOCATION):
    print "\n[INFO] Dynamic API Analysis"
    dat = ""
    API_BASE64 = []
    API_FILEIO = []
    API_RELECT = []
    API_SYSPROP = []
    API_CNTRSLVR = []
    API_CNTVAL = []
    API_BINDER = []
    API_CRYPTO = []
    API_ACNTMNGER = []
    API_DEVICEINFO = []
    API_NET = []
    API_DEXLOADER = []
    API_CMD = []
    API_SMS = []
    try:
        with open(LOCATION, "r") as f:
            dat = f.readlines()
        ID = "Droidmon-apimonitor-" + PKG + ":"
        for line in dat:
            line = line.decode('utf8', 'ignore')
            if (ID) in line:
                # print "LINE: " + line
                param, value = line.split(ID, 1)
                # print "PARAM is :" + param
                # print "Value is :"+ value
                try:
                    APIs = json.loads(value, strict=False)
                    RET = ''
                    CLS = ''
                    MTD = ''
                    ARGS = ''
                    MTD = str(APIs["method"])
                    CLS = str(APIs["class"])
                    # print "Called Class: " + CLS
                    # print "Called Method: " + MTD
                    if APIs.get('return'):
                        RET = str(APIs["return"])
                        # print "Return Data: " + RET
                    else:
                        # print "No Return Data"
                        RET = "No Return Data"
                    if APIs.get('args'):
                        ARGS = str(APIs["args"])
                        # print "Passed Arguments" + ARGS
                    else:
                        # print "No Arguments Passed"
                        ARGS = "No Arguments Passed"
                    # XSS Safe
                    D = "</br>METHOD: " + \
                        escape(MTD) + "</br>ARGUMENTS: " + escape(ARGS) + \
                        "</br>RETURN DATA: " + escape(RET)

                    if re.findall("android.util.Base64", CLS):
                        # Base64 Decode
                        if ("decode" in MTD):
                            args_list = python_list(ARGS)
                            if isBase64(args_list[0]):
                                D += '</br><span class="label label-info">Decoded String:</span> ' + \
                                    escape(base64.b64decode(args_list[0]))
                        API_BASE64.append(D)
                    if re.findall('libcore.io|android.app.SharedPreferencesImpl$EditorImpl', CLS):
                        API_FILEIO.append(D)
                    if re.findall('java.lang.reflect', CLS):
                        API_RELECT.append(D)
                    if re.findall('android.content.ContentResolver|android.location.Location|android.media.AudioRecord|android.media.MediaRecorder|android.os.SystemProperties', CLS):
                        API_SYSPROP.append(D)
                    if re.findall('android.app.Activity|android.app.ContextImpl|android.app.ActivityThread', CLS):
                        API_BINDER.append(D)
                    if re.findall('javax.crypto.spec.SecretKeySpec|javax.crypto.Cipher|javax.crypto.Mac', CLS):
                        API_CRYPTO.append(D)
                    if re.findall('android.accounts.AccountManager|android.app.ApplicationPackageManager|android.app.NotificationManager|android.net.ConnectivityManager|android.content.BroadcastReceiver', CLS):
                        API_ACNTMNGER.append(D)
                    if re.findall('android.telephony.TelephonyManager|android.net.wifi.WifiInfo|android.os.Debug', CLS):
                        API_DEVICEINFO.append(D)
                    if re.findall('dalvik.system.BaseDexClassLoader|dalvik.system.DexFile|dalvik.system.DexClassLoader|dalvik.system.PathClassLoader', CLS):
                        API_DEXLOADER.append(D)
                    if re.findall('java.lang.Runtime|java.lang.ProcessBuilder|java.io.FileOutputStream|java.io.FileInputStream|android.os.Process', CLS):
                        API_CMD.append(D)
                    if re.findall('android.content.ContentValues', CLS):
                        API_CNTVAL.append(D)
                    if re.findall('android.telephony.SmsManager', CLS):
                        API_SMS.append(D)
                    if re.findall('java.net.URL|org.apache.http.impl.client.AbstractHttpClient', CLS):
                        API_NET.append(D)
                except:
                    PrintException("[ERROR] Parsing JSON Failed for: " + value)
    except:
        PrintException("[ERROR] Dynamic API Analysis")
        pass
    return list(set(API_NET)), list(set(API_BASE64)), list(set(API_FILEIO)), list(set(API_BINDER)), list(set(API_CRYPTO)), list(set(API_DEVICEINFO)), list(set(API_CNTVAL)), list(set(API_SMS)), list(set(API_SYSPROP)), list(set(API_DEXLOADER)), list(set(API_RELECT)), list(set(API_ACNTMNGER)), list(set(API_CMD))


def Download(MD5, DWDDIR, APKDIR, PKG):
    print "\n[INFO] Generating Downloads"
    try:
        Logcat = os.path.join(APKDIR, 'logcat.txt')
        xLogcat = os.path.join(APKDIR, 'x_logcat.txt')
        Dumpsys = os.path.join(APKDIR, 'dump.txt')
        Sshot = os.path.join(APKDIR, 'screenshots-apk/')
        Web = os.path.join(APKDIR, 'WebTraffic.txt')
        Star = os.path.join(APKDIR, PKG + '.tar')

        DLogcat = os.path.join(DWDDIR, MD5 + '-logcat.txt')
        DxLogcat = os.path.join(DWDDIR, MD5 + '-x_logcat.txt')
        DDumpsys = os.path.join(DWDDIR, MD5 + '-dump.txt')
        DSshot = os.path.join(DWDDIR, MD5 + '-screenshots-apk/')
        DWeb = os.path.join(DWDDIR, MD5 + '-WebTraffic.txt')
        DStar = os.path.join(DWDDIR, MD5 + '-AppData.tar')

        # Delete existing data
        dellist = [DLogcat, DxLogcat, DDumpsys, DSshot, DWeb, DStar]
        for item in dellist:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
        # Copy new data
        shutil.copyfile(Logcat, DLogcat)
        shutil.copyfile(xLogcat, DxLogcat)
        shutil.copyfile(Dumpsys, DDumpsys)
        try:
            shutil.copytree(Sshot, DSshot)
        except:
            pass
        try:
            shutil.copyfile(Web, DWeb)
        except:
            pass
        try:
            shutil.copyfile(Star, DStar)
        except:
            pass
    except:
        PrintException("[ERROR] Generating Downloads")


def RunAnalysis(APKDIR, MD5, PACKAGE):
    print "\n[INFO] Dynamic File Analysis"
    Web = os.path.join(APKDIR, 'WebTraffic.txt')
    Logcat = os.path.join(APKDIR, 'logcat.txt')
    xLogcat = os.path.join(APKDIR, 'x_logcat.txt')
    traffic = ''
    wb = ''
    xlg = ''
    DOMAINS = {}
    logcat_data = []
    CLIPBOARD = []
    CLIP_TAG = "I/CLIPDUMP-INFO-LOG"
    try:
        with io.open(Web, mode='r', encoding="utf8", errors="ignore") as f:
            wb = f.read()
    except:
        pass

    with io.open(Logcat, mode='r', encoding="utf8", errors="ignore") as f:
        logcat_data = f.readlines()
        traffic = ''.join(logcat_data)
    with io.open(xLogcat, mode='r', encoding="utf8", errors="ignore") as f:
        xlg = f.read()
    traffic = wb + traffic + xlg
    for log_line in logcat_data:
        if log_line.startswith(CLIP_TAG):
            CLIPBOARD.append(log_line.replace(CLIP_TAG, "Process ID "))
    URLS = []
    # URLs My Custom regex
    p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
    urllist = re.findall(p, traffic.lower())
    # Domain Extraction and Malware Check
    print "[INFO] Performing Malware Check on extracted Domains"
    DOMAINS = MalwareCheck(urllist)
    for url in urllist:
        if url not in URLS:
            URLS.append(url)

    # Email Etraction Regex
    EMAILS = []
    regex = re.compile(("[\w.-]+@[\w-]+\.[\w.]+"))
    for email in regex.findall(traffic.lower()):
        if ((email not in EMAILS) and (not email.startswith('//'))):
            if email == "yodleebanglore@gmail.com":
                pass
            else:
                EMAILS.append(email)
    # Extract Device Data
    try:
        TARLOC = os.path.join(APKDIR, PACKAGE + '.tar')
        UNTAR_DIR = os.path.join(APKDIR, 'DYNAMIC_DeviceData/')
        if not os.path.exists(UNTAR_DIR):
            os.makedirs(UNTAR_DIR)
        with tarfile.open(TARLOC) as tar:
            try:
                tar.extractall(UNTAR_DIR)
            except:
                pass
    except:
        PrintException("[ERROR] TAR EXTRACTION FAILED")
    # Do Static Analysis on Data from Device
    xmlfiles = ''
    SQLiteDB = ''
    OtherFiles = ''
    typ = ''
    UNTAR_DIR = os.path.join(APKDIR, 'DYNAMIC_DeviceData/')
    if not os.path.exists(UNTAR_DIR):
        os.makedirs(UNTAR_DIR)
    try:
        for dirName, subDir, files in os.walk(UNTAR_DIR):
            for jfile in files:
                file_path = os.path.join(UNTAR_DIR, dirName, jfile)
                if "+" in file_path:
                    shutil.move(file_path, file_path.replace("+", "x"))
                    file_path = file_path.replace("+", "x")
                fileparam = file_path.replace(UNTAR_DIR, '')
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        typ = 'xml'
                        xmlfiles += "<tr><td><a href='../View/?file=" + \
                            escape(fileparam) + "&md5=" + MD5 + "&type=" + \
                            typ + "'>" + escape(fileparam) + "</a></td><tr>"
                    else:
                        with io.open(file_path, mode='r', encoding="utf8", errors="ignore") as f:
                            b = f.read(6)
                        if b == "SQLite":
                            typ = 'db'
                            SQLiteDB += "<tr><td><a href='../View/?file=" + \
                                escape(fileparam) + "&md5=" + MD5 + "&type=" + \
                                typ + "'>" + \
                                escape(fileparam) + "</a></td><tr>"
                        elif not jfile.endswith('.DS_Store'):
                            typ = 'others'
                            OtherFiles += "<tr><td><a href='../View/?file=" + \
                                escape(fileparam) + "&md5=" + MD5 + "&type=" + \
                                typ + "'>" + \
                                escape(fileparam) + "</a></td><tr>"
    except:
        PrintException("[ERROR] Dynamic File Analysis")
        pass
    return URLS, DOMAINS, EMAILS, CLIPBOARD, wb, xmlfiles, SQLiteDB, OtherFiles


def View(request):
    print "\n[INFO] Viewing File"
    try:
        typ = ''
        fil = ''
        rtyp = ''
        dat = ''
        m = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if m:
            fil = request.GET['file']
            MD5 = request.GET['md5']
            typ = request.GET['type']
            SRC = os.path.join(settings.UPLD_DIR, MD5 + '/DYNAMIC_DeviceData/')
            sfile = os.path.join(SRC, fil)
            # Prevent Directory Traversal Attacks
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as f:
                    dat = f.read()
                if ((fil.endswith('.xml')) and (typ == 'xml')):
                    rtyp = 'xml'
                elif typ == 'db':
                    dat = HandleSqlite(sfile)
                    rtyp = 'plain'
                elif typ == 'others':
                    rtyp = 'plain'
                else:
                    return HttpResponseRedirect('/error/')
                context = {'title': escape(ntpath.basename(fil)), 'file': escape(
                    ntpath.basename(fil)), 'dat': dat, 'type': rtyp, }
                template = "general/view.html"
                return render(request, template, context)

        else:
            return HttpResponseRedirect('/error/')
    except:
        PrintException("[ERROR] Viewing File")
        return HttpResponseRedirect('/error/')


def ScreenCastService():
    global tcp_server_mode
    print "\n[INFO] ScreenCast Service Status: " + tcp_server_mode
    try:
        SCREEN_DIR = settings.SCREEN_DIR
        if not os.path.exists(SCREEN_DIR):
            os.makedirs(SCREEN_DIR)

        s = socket.socket()
        if tcp_server_mode == "on":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if settings.AVD:
                ADDR = ('127.0.0.1', settings.SCREEN_PORT)
            else:
                ADDR = (settings.SCREEN_IP, settings.SCREEN_PORT)
            s.bind(ADDR)
            s.listen(10)
            while (tcp_server_mode == "on"):
                ss, address = s.accept()
                print "Got Connection from: ", address[0]
                if settings.REAL_DEVICE:
                    IP = settings.DEVICE_IP
                else:
                    IP = settings.VM_IP
                if address[0] in [IP, '127.0.0.1']:
                    '''
                    Very Basic Check to ensure that only MobSF VM/Device is allowed to connect
                    to MobSF ScreenCast Service.
                    '''
                    with open(SCREEN_DIR + 'screen.png', 'wb') as f:
                        while True:
                            data = ss.recv(1024)
                            if not data:
                                break
                            f.write(data)
                else:
                    print "\n[ATTACK] An unknown client :" + address[0] + " is trying to make a connection with MobSF ScreenCast Service!"
        elif tcp_server_mode == "off":
            s.close()
    except:
        s.close()
        PrintException("[ERROR] ScreenCast Server")
        pass


def GetRes():
    print "\n[INFO] Getting Screen Resolution"
    try:
        TOOLSDIR = os.path.join(
            settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
        adb = getADB(TOOLSDIR)
        resp = subprocess.check_output(
            [adb, "-s", getIdentifier(), "shell", "dumpsys", "window"])
        resp = resp.split("\n")
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
            #width, height
        return "", ""
    except:
        PrintException("[ERROR] Getting Screen Resolution")
        return "", ""


# Helper Functions
def getIdentifier():
    try:
        if settings.REAL_DEVICE:
            return settings.DEVICE_IP + ":" + str(settings.DEVICE_ADB_PORT)
        elif settings.AVD:
            return 'emulator-' + str(settings.AVD_ADB_PORT)
        else:
            return settings.VM_IP + ":" + str(settings.VM_ADB_PORT)
    except:
        PrintException(
            "[ERROR] Getting ADB Connection Identifier for Device/VM")
