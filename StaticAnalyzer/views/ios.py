# -*- coding: utf_8 -*-
"""
iOS Static Code Analysis
"""
import sqlite3 as sq
import io
import re
import os
import subprocess
import ntpath
import shutil
import plistlib
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape
from django.utils.encoding import smart_text
from StaticAnalyzer.views.shared_func import FileSize, HashGen, Unzip

from StaticAnalyzer.models import StaticAnalyzerIPA, StaticAnalyzerIOSZIP
from MobSF.utils import PrintException, python_list, python_dict, isDirExists, isFileExists
from StaticAnalyzer.tools.strings import strings

from MalwareAnalyzer.views import MalwareCheck
try:
    import xhtml2pdf.pisa as pisa
except:
    PrintException(
        "[ERROR] xhtml2pdf is not installed. Cannot generate PDF reports")
try:
    import StringIO
    StringIO = StringIO.StringIO
except Exception:
    from io import StringIO

##############################################################
# Code to support iOS Static Code Anlysis
##############################################################
# iOS Support Functions


def StaticAnalyzer_iOS(request):
    try:
        # Input validation
        print "[INFO] iOS Static Analysis Started"
        TYP = request.GET['type']
        RESCAN = str(request.GET.get('rescan', 0))
        m = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if ((m) and (request.GET['name'].lower().endswith('.ipa') or request.GET['name'].lower().endswith('.zip')) and (TYP in ['ipa', 'ios'])):
            DIR = settings.BASE_DIR  # BASE DIR
            APP_NAME = request.GET['name']  # APP ORGINAL NAME
            MD5 = request.GET['checksum']  # MD5
            APP_DIR = os.path.join(
                settings.UPLD_DIR, MD5 + '/')  # APP DIRECTORY
            TOOLS_DIR = os.path.join(
                DIR, 'StaticAnalyzer/tools/mac/')  # TOOLS DIR
            if TYP == 'ipa':
                # DB
                DB = StaticAnalyzerIPA.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title': DB[0].TITLE,
                        'name': DB[0].APPNAMEX,
                        'size': DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1': DB[0].SHA1,
                        'sha256': DB[0].SHA256,
                        'plist': DB[0].INFOPLIST,
                        'bin_name': DB[0].BINNAME,
                        'id': DB[0].IDF,
                        'ver': DB[0].VERSION,
                        'sdk': DB[0].SDK,
                        'pltfm': DB[0].PLTFM,
                        'min': DB[0].MINX,
                        'bin_anal': DB[0].BIN_ANAL,
                        'libs': DB[0].LIBS,
                        'files': python_list(DB[0].FILES),
                        'file_analysis': DB[0].SFILESX,
                        'strings': python_list(DB[0].STRINGS),
                        'permissions': python_list(DB[0].PERMISSIONS)
                    }
                else:
                    print "[INFO] iOS Binary (IPA) Analysis Started"
                    APP_FILE = MD5 + '.ipa'  # NEW FILENAME
                    APP_PATH = APP_DIR + APP_FILE  # APP PATH
                    BIN_DIR = os.path.join(APP_DIR, "Payload/")
                    # ANALYSIS BEGINS
                    SIZE = str(FileSize(APP_PATH)) + 'MB'  # FILE SIZE
                    SHA1, SHA256 = HashGen(APP_PATH)  # SHA1 & SHA256 HASHES
                    print "[INFO] Extracting IPA"
                    Unzip(APP_PATH, APP_DIR)  # EXTRACT IPA
                    # Get Files, normalize + to x, and convert binary plist ->
                    # xml
                    FILES, SFILES = iOS_ListFiles(BIN_DIR, MD5, True, 'ipa')
                    INFO_PLIST, BIN_NAME, ID, VER, SDK, PLTFM, MIN, LIBS, BIN_ANAL, STRINGS, PERMISSIONS = BinaryAnalysis(
                        BIN_DIR, TOOLS_DIR, APP_DIR)
                    # Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if RESCAN == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerIPA.objects.filter(MD5=MD5).update(TITLE='Static Analysis', APPNAMEX=APP_NAME, SIZE=SIZE, MD5=MD5, SHA1=SHA1, SHA256=SHA256, INFOPLIST=INFO_PLIST,
                                                                         BINNAME=BIN_NAME, IDF=ID, VERSION=VER, SDK=SDK, PLTFM=PLTFM, MINX=MIN, BIN_ANAL=BIN_ANAL, LIBS=LIBS, FILES=FILES, SFILESX=SFILES, STRINGS=STRINGS, PERMISSIONS=python_list(PERMISSIONS))
                    elif RESCAN == '0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB = StaticAnalyzerIPA(TITLE='Static Analysis', APPNAMEX=APP_NAME, SIZE=SIZE, MD5=MD5, SHA1=SHA1, SHA256=SHA256, INFOPLIST=INFO_PLIST,
                                                      BINNAME=BIN_NAME, IDF=ID, VERSION=VER, SDK=SDK, PLTFM=PLTFM, MINX=MIN, BIN_ANAL=BIN_ANAL, LIBS=LIBS, FILES=FILES, SFILESX=SFILES, STRINGS=STRINGS, PERMISSIONS=python_list(PERMISSIONS))
                        STATIC_DB.save()
                    context = {
                        'title': 'Static Analysis',
                        'name': APP_NAME,
                        'size': SIZE,
                        'md5': MD5,
                        'sha1': SHA1,
                        'sha256': SHA256,
                        'plist': INFO_PLIST,
                        'bin_name': BIN_NAME,
                        'id': ID,
                        'ver': VER,
                        'sdk': SDK,
                        'pltfm': PLTFM,
                        'min': MIN,
                        'bin_anal': BIN_ANAL,
                        'libs': LIBS,
                        'files': FILES,
                        'file_analysis': SFILES,
                        'strings': STRINGS,
                        'permissions': PERMISSIONS
                    }
                template = "static_analysis/ios_binary_analysis.html"
                return render(request, template, context)
            elif TYP == 'ios':
                DB = StaticAnalyzerIOSZIP.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title': DB[0].TITLE,
                        'name': DB[0].APPNAMEX,
                        'size': DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1': DB[0].SHA1,
                        'sha256': DB[0].SHA256,
                        'plist': DB[0].INFOPLIST,
                        'bin_name': DB[0].BINNAME,
                        'id': DB[0].IDF,
                        'ver': DB[0].VERSION,
                        'sdk': DB[0].SDK,
                        'pltfm': DB[0].PLTFM,
                        'min': DB[0].MINX,
                        'bin_anal': DB[0].BIN_ANAL,
                        'libs': DB[0].LIBS,
                        'files': python_list(DB[0].FILES),
                        'file_analysis': DB[0].SFILESX,
                        'api': DB[0].HTML,
                        'insecure': DB[0].CODEANAL,
                        'urls': DB[0].URLnFile,
                        'domains': python_dict(DB[0].DOMAINS),
                        'emails': DB[0].EmailnFile,
                        'permissions': python_list(DB[0].PERMISSIONS),
                    }
                else:
                    print "[INFO] iOS Source Code Analysis Started"
                    APP_FILE = MD5 + '.zip'  # NEW FILENAME
                    APP_PATH = APP_DIR + APP_FILE  # APP PATH
                    # ANALYSIS BEGINS - Already Unzipped
                    print "[INFO] ZIP Already Extracted"
                    SIZE = str(FileSize(APP_PATH)) + 'MB'  # FILE SIZE
                    SHA1, SHA256 = HashGen(APP_PATH)  # SHA1 & SHA256 HASHES
                    FILES, SFILES = iOS_ListFiles(APP_DIR, MD5, False, 'ios')
                    HTML, CODEANAL, URLnFile, DOMAINS, EmailnFile, INFO_PLIST, BIN_NAME, ID, VER, SDK, PLTFM, MIN, PERMISSIONS = iOS_Source_Analysis(
                        APP_DIR, MD5)
                    LIBS, BIN_ANAL = '', ''
                    # Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if RESCAN == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerIOSZIP.objects.filter(MD5=MD5).update(TITLE='Static Analysis',
                                                                            APPNAMEX=APP_NAME,
                                                                            SIZE=SIZE,
                                                                            MD5=MD5,
                                                                            SHA1=SHA1,
                                                                            SHA256=SHA256,
                                                                            INFOPLIST=INFO_PLIST,
                                                                            BINNAME=BIN_NAME,
                                                                            IDF=ID,
                                                                            VERSION=VER,
                                                                            SDK=SDK,
                                                                            PLTFM=PLTFM,
                                                                            MINX=MIN,
                                                                            BIN_ANAL=BIN_ANAL,
                                                                            LIBS=LIBS,
                                                                            FILES=FILES,
                                                                            SFILESX=SFILES,
                                                                            HTML=HTML,
                                                                            CODEANAL=CODEANAL,
                                                                            URLnFile=URLnFile,
                                                                            DOMAINS=DOMAINS,
                                                                            EmailnFile=EmailnFile,
                                                                            PERMISSIONS=PERMISSIONS)
                    elif RESCAN == '0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB = StaticAnalyzerIOSZIP(TITLE='Static Analysis',
                                                         APPNAMEX=APP_NAME,
                                                         SIZE=SIZE,
                                                         MD5=MD5,
                                                         SHA1=SHA1,
                                                         SHA256=SHA256,
                                                         INFOPLIST=INFO_PLIST,
                                                         BINNAME=BIN_NAME,
                                                         IDF=ID,
                                                         VERSION=VER,
                                                         SDK=SDK,
                                                         PLTFM=PLTFM,
                                                         MINX=MIN,
                                                         BIN_ANAL=BIN_ANAL,
                                                         LIBS=LIBS,
                                                         FILES=FILES,
                                                         SFILESX=SFILES,
                                                         HTML=HTML,
                                                         CODEANAL=CODEANAL,
                                                         URLnFile=URLnFile,
                                                         DOMAINS=DOMAINS,
                                                         EmailnFile=EmailnFile,
                                                         PERMISSIONS=PERMISSIONS)
                        STATIC_DB.save()
                    context = {
                        'title': 'Static Analysis',
                        'name': APP_NAME,
                        'size': SIZE,
                        'md5': MD5,
                        'sha1': SHA1,
                        'sha256': SHA256,
                        'plist': INFO_PLIST,
                        'bin_name': BIN_NAME,
                        'id': ID,
                        'ver': VER,
                        'sdk': SDK,
                        'pltfm': PLTFM,
                        'min': MIN,
                        'bin_anal': BIN_ANAL,
                        'libs': LIBS,
                        'files': FILES,
                        'file_analysis': SFILES,
                        'api': HTML,
                        'insecure': CODEANAL,
                        'urls': URLnFile,
                        'domains': DOMAINS,
                        'emails': EmailnFile,
                        'permissions': PERMISSIONS,
                    }
                template = "static_analysis/ios_source_analysis.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except Exception as exp:
        PrintException("[ERROR] Static Analyzer iOS")
        context = {
            'title': 'Error',
            'exp': exp.message,
            'doc': exp.__doc__
        }
        template = "general/error.html"
        return render(request, template, context)


def ViewFile(request):
    try:
        print "[INFO] View iOS Files"
        fil = request.GET['file']
        typ = request.GET['type']
        MD5 = request.GET['md5']
        mode = request.GET['mode']
        m = re.match('^[0-9a-f]{32}$', MD5)
        ext = fil.split('.')[-1]
        f = re.search("plist|db|sqlitedb|sqlite|txt|m", ext)
        if m and f and re.findall('xml|db|txt|m', typ) and re.findall('ios|ipa', mode):
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                if mode == 'ipa':
                    SRC = os.path.join(settings.UPLD_DIR, MD5 + '/Payload/')
                elif mode == 'ios':
                    SRC = os.path.join(settings.UPLD_DIR, MD5 + '/')
                sfile = os.path.join(SRC, fil)
                dat = ''
                if typ == 'm':
                    format = 'cpp'
                    with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as f:
                        dat = f.read()
                elif typ == 'xml':
                    format = 'xml'
                    with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as f:
                        dat = f.read()
                elif typ == 'db':
                    format = 'plain'
                    dat = HandleSqlite(sfile)
                elif typ == 'txt':
                    format = 'plain'
                    APP_DIR = os.path.join(settings.UPLD_DIR, MD5 + '/')
                    FILE = os.path.join(APP_DIR, "classdump.txt")
                    with io.open(FILE, mode='r', encoding="utf8", errors="ignore") as f:
                        dat = f.read()
        else:
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'type': format,
                   'dat': dat}
        template = "general/view.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] View iOS File")
        return HttpResponseRedirect('/error/')


def readBinXML(FILE):
    try:
        args = ['plutil', '-convert', 'xml1', FILE]
        dat = subprocess.check_output(args)
        with io.open(FILE, mode='r', encoding="utf8", errors="ignore") as f:
            dat = f.read()
        return dat
    except:
        PrintException("[ERROR] Converting Binary XML to Readable XML")


def HandleSqlite(SFile):
    try:
        print "[INFO] Dumping SQLITE Database"
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
                head += str(r[1]).decode('utf8', 'ignore') + " | "
            data += head + " \n=====================================================================\n"
            cur.execute("SELECT * FROM '%s'" % table)
            rows = cur.fetchall()
            for r in rows:
                dat = ''
                for x in r:
                    dat += str(x).decode('utf8', 'ignore') + " | "
                data += dat + "\n"
        return data
    except:
        PrintException("[ERROR] Dumping SQLITE Database")


def iOS_ListFiles(SRC, MD5, BIN, MODE):
    try:
        print "[INFO] Get Files, BIN Plist -> XML, and Normalize"
        # Multi function, Get Files, BIN Plist -> XML, normalize + to x
        filez = []
        certz = ''
        sfiles = ''
        db = ''
        plist = ''
        certz = ''
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if not jfile.endswith(".DS_Store"):
                    file_path = os.path.join(SRC, dirName, jfile)
                    if "+" in jfile:
                        plus2x = os.path.join(
                            SRC, dirName, jfile.replace("+", "x"))
                        shutil.move(file_path, plus2x)
                        file_path = plus2x
                    fileparam = file_path.replace(SRC, '')
                    filez.append(fileparam)
                    ext = jfile.split('.')[-1]
                    if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                        certz += escape(file_path.replace(SRC, '')) + "</br>"
                    if re.search("db|sqlitedb|sqlite", ext):
                        db += "<a href='../ViewFile/?file=" + \
                            escape(fileparam) + "&type=db&mode=" + MODE + "&md5=" + \
                            MD5 + "''> " + escape(fileparam) + " </a></br>"
                    if jfile.endswith(".plist"):
                        if BIN:
                            readBinXML(file_path)
                        plist += "<a href='../ViewFile/?file=" + \
                            escape(fileparam) + "&type=xml&mode=" + MODE + "&md5=" + \
                            MD5 + "''> " + escape(fileparam) + " </a></br>"
        if len(db) > 1:
            db = "<tr><td>SQLite Files</td><td>" + db + "</td></tr>"
            sfiles += db
        if len(plist) > 1:
            plist = "<tr><td>Plist Files</td><td>" + plist + "</td></tr>"
            sfiles += plist
        if len(certz) > 1:
            certz = "<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>" + \
                certz + "</td><tr>"
            sfiles += certz
        return filez, sfiles
    except:
        PrintException("[ERROR] iOS List Files")


def __check_permissions(p_list):
    '''Check the permissions the app requests.'''
    # List taken from
    # https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
    print "[INFO] Checking Permissions"
    permissions = []
    if "NSAppleMusicUsageDescription" in p_list:
        permissions.append(
            (
                "NSAppleMusicUsageDescription",
                "Access Apple Media Library.",
                p_list["NSAppleMusicUsageDescription"]
            )
        )
    if "NSBluetoothPeripheralUsageDescription" in p_list:
        permissions.append(
            (
                "NSBluetoothPeripheralUsageDescription",
                "Access Bluetooth Interface.",
                p_list["NSBluetoothPeripheralUsageDescription"]
            )
        )
    if "NSCalendarsUsageDescription" in p_list:
        permissions.append(
            (
                "NSCalendarsUsageDescription",
                "Access Calendars.",
                p_list["NSCalendarsUsageDescription"]
            )
        )
    if "NSCameraUsageDescription" in p_list:
        permissions.append(
            (
                "NSCameraUsageDescription",
                "Access the Camera.",
                p_list["NSCameraUsageDescription"]
            )
        )
    if "NSContactsUsageDescription" in p_list:
        permissions.append(
            (
                "NSContactsUsageDescription",
                "Access Contacts.",
                p_list["NSContactsUsageDescription"]
            )
        )
    if "NSHealthShareUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthShareUsageDescription",
                "Read Health Data.",
                p_list["NSHealthShareUsageDescription"]
            )
        )
    if "NSHealthUpdateUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthUpdateUsageDescription",
                "Write Health Data.",
                p_list["NSHealthUpdateUsageDescription"]
            )
        )
    if "NSHomeKitUsageDescription" in p_list:
        permissions.append(
            (
                "NSHomeKitUsageDescription",
                "Access HomeKit configuration data.",
                p_list["NSHomeKitUsageDescription"]
            )
        )
    if "NSLocationAlwaysUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationAlwaysUsageDescription",
                "Access location information at all times.",
                p_list["NSLocationAlwaysUsageDescription"]
            )
        )
    if "NSLocationUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationUsageDescription",
                "Access location information at all times (< iOS 8).",
                p_list["NSLocationUsageDescription"]
            )
        )
    if "NSLocationWhenInUseUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationWhenInUseUsageDescription",
                "Access location information when app is in the foreground.",
                p_list["NSLocationWhenInUseUsageDescription"]
            )
        )
    if "NSMicrophoneUsageDescription" in p_list:
        permissions.append(
            (
                "NSMicrophoneUsageDescription",
                "Access microphone.",
                p_list["NSMicrophoneUsageDescription"]
            )
        )
    if "NSMotionUsageDescription" in p_list:
        permissions.append(
            (
                "NSMotionUsageDescription",
                "Access the device’s accelerometer.",
                p_list["NSMotionUsageDescription"]
            )
        )
    if "NSPhotoLibraryUsageDescription" in p_list:
        permissions.append(
            (
                "NSPhotoLibraryUsageDescription",
                "Access the user’s photo library.",
                p_list["NSPhotoLibraryUsageDescription"]
            )
        )
    if "NSRemindersUsageDescription" in p_list:
        permissions.append(
            (
                "NSRemindersUsageDescription",
                "Access the user’s reminders.",
                p_list["NSRemindersUsageDescription"]
            )
        )
    if "NSVideoSubscriberAccountUsageDescription" in p_list:
        permissions.append(
            (
                "NSVideoSubscriberAccountUsageDescription",
                "Access the user’s TV provider account.",
                p_list["NSVideoSubscriberAccountUsageDescription"]
            )
        )

    return permissions


def BinaryAnalysis(SRC, TOOLS_DIR, APP_DIR):
    try:
        print "[INFO] Starting Binary Analysis"
        dirs = os.listdir(SRC)
        for d in dirs:
            if d.endswith(".app"):
                break

        BIN_DIR = os.path.join(SRC, d)  # Full Dir/Payload/x.app
        XML_FILE = os.path.join(BIN_DIR, "Info.plist")
        BIN = d.replace(".app", "")
        BIN_NAME = BIN
        ID = ""
        VER = ""
        SDK = ""
        PLTFM = ""
        MIN = ""
        XML = ""

        try:
            print "[INFO] Reading Info.plist"
            XML = readBinXML(XML_FILE)
            if isinstance(XML, unicode):
                XML = XML.encode("utf-8", "replace")
            p = plistlib.readPlistFromString(XML)
            BIN_NAME = BIN = ID = VER = SDK = PLTFM = MIN = ""
            if "CFBundleDisplayName" in p:
                BIN_NAME = p["CFBundleDisplayName"]
            if "CFBundleExecutable" in p:
                BIN = p["CFBundleExecutable"]
            if "CFBundleIdentifier" in p:
                ID = p["CFBundleIdentifier"]
            if "CFBundleVersion" in p:
                VER = p["CFBundleVersion"]
            if "DTSDKName" in p:
                SDK = p["DTSDKName"]
            if "DTPlatformVersion" in p:
                PLTFM = p["DTPlatformVersion"]
            if "MinimumOSVersion" in p:
                MIN = p["MinimumOSVersion"]

            # Check possible app-permissions
            PERMISSIONS = __check_permissions(p)

        except:
            PrintException("[ERROR] - Reading from Info.plist")

        BIN_PATH = os.path.join(BIN_DIR, BIN)  # Full Dir/Payload/x.app/x
        print "[INFO] iOS Binary : " + BIN
        print "[INFO] Running otool against the Binary"
        # Libs Used
        LIBS = ''
        if len(settings.OTOOL_BINARY) > 0 and isFileExists(settings.OTOOL_BINARY):
            OTOOL = settings.OTOOL_BINARY
        else:
            OTOOL = "otool"
        args = [OTOOL, '-L', BIN_PATH]
        dat = unicode(subprocess.check_output(args), 'utf-8')
        dat = smart_text(escape(dat.replace(BIN_DIR + "/", "")))
        LIBS = dat.replace("\n", "</br>")
        # PIE
        args = [OTOOL, '-hv', BIN_PATH]
        dat = subprocess.check_output(args)
        if "PIE" in dat:
            PIE = "<tr><td><strong>fPIE -pie</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Position Independent Executable (PIE) flag. This enables Address Space Layout Randomization (ASLR), a memory protection mechanism for exploit mitigation.</td></tr>"
        else:
            PIE = "<tr><td><strong>fPIE -pie</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Position Independent Executable (PIE) flag. So Address Space Layout Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation.</td></tr>"
        # Stack Smashing Protection & ARC
        args = [OTOOL, '-Iv', BIN_PATH]
        dat = subprocess.check_output(args)
        if "stack_chk_guard" in dat:
            SSMASH = "<tr><td><strong>fstack-protector-all</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Stack Smashing Protector (SSP) flag and is having protection against Stack Overflows/Stack Smashing Attacks.</td></tr>"
        else:
            SSMASH = "<tr><td><strong>fstack-protector-all</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to Stack Overflows/Stack Smashing Attacks.</td></tr>"
        # ARC
        if "_objc_release" in dat:
            ARC = "<tr><td><strong>fobjc-arc</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.</td></tr>"
        else:
            ARC = "<tr><td><strong>fobjc-arc</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and protects from memory corruption vulnerabilities.</td></tr>"
        ##########
        BANNED_API = ''
        x = re.findall("alloca|gets|memcpy|printf|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            BANNED_API = "<tr><td>Binary make use of banned API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may contain the following banned API(s) </br><strong>" + str(
                x) + "</strong>.</td></tr>"
        WEAK_CRYPTO = ''
        x = re.findall(
            "kCCAlgorithmDES|kCCAlgorithm3DES||kCCAlgorithmRC2|kCCAlgorithmRC4|kCCOptionECBMode|kCCOptionCBCMode", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            WEAK_CRYPTO = "<tr><td>Binary make use of some Weak Crypto API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak crypto API(s)</br><strong>" + str(
                x) + "</strong>.</td></tr>"
        CRYPTO = ''
        x = re.findall("CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|SecTrustSetVerifyDate|SecCertificateRef|SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            CRYPTO = "<tr><td>Binary make use of the following Crypto API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following crypto API(s)</br><strong>" + str(
                x) + "</strong>.</td></tr>"
        WEAK_HASH = ''
        x = re.findall("CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            WEAK_HASH = "<tr><td>Binary make use of the following Weak HASH API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak hash API(s)</br><strong>" + str(
                x) + "</strong>.</td></tr>"
        HASH = ''
        x = re.findall("CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            HASH = "<tr><td>Binary make use of the following HASH API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following hash API(s)</br><strong>" + str(
                x) + "</strong>.</td></tr>"
        RAND = ''
        x = re.findall("srand|random", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            RAND = "<tr><td>Binary make use of the insecure Random Function(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following insecure Random Function(s)</br><strong>" + str(
                x) + "</strong>.</td></tr>"
        LOG = ''
        x = re.findall("NSLog", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            LOG = "<tr><td>Binary make use of Logging Function</td><td><span class='label label-info'>Info</span></td><td>The binary may use <strong>NSLog</strong> function for logging.</td></tr>"
        MALL = ''
        x = re.findall("malloc", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            MALL = "<tr><td>Binary make use of <strong>malloc</strong> Function</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use <strong>malloc</strong> function instead of <strong>calloc</strong>.</td></tr>"
        DBG = ''
        x = re.findall("ptrace", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            DBG = "<tr><td>Binary calls <strong>ptrace</strong> Function for anti-debugging.</td><td><span class='label label-warning'>warning</span></td><td>The binary may use <strong>ptrace</strong> function. It can be used to detect and prevent debuggers. Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. </td></tr>"
        CDUMP = ''
        WVIEW = ''
        try:
            print "[INFO] Running class-dump-z against the Binary"
            if len(settings.CLASSDUMPZ_BINARY) > 0 and isFileExists(settings.CLASSDUMPZ_BINARY):
                CLASSDUMPZ_BIN = settings.CLASSDUMPZ_BINARY
            else:
                CLASSDUMPZ_BIN = os.path.join(TOOLS_DIR, 'class-dump-z')
            subprocess.call(["chmod", "777", CLASSDUMPZ_BIN])
            dat = subprocess.check_output([CLASSDUMPZ_BIN, BIN_PATH])
            CDUMP = dat
            FILE = os.path.join(APP_DIR, "classdump.txt")
            with open(FILE, "w") as f:
                f.write(CDUMP)
            if "UIWebView" in CDUMP:
                WVIEW = "<tr><td>Binary uses WebView Component.</td><td><span class='label label-info'>Info</span></td><td>The binary may use WebView Component.</td></tr>"

        except:
            PrintException("[ERROR] - Cannot perform class dump")
        BIN_RES = PIE + SSMASH + ARC + BANNED_API + WEAK_CRYPTO + \
            CRYPTO + WEAK_HASH + HASH + RAND + LOG + MALL + DBG + WVIEW
        # classdump

        # strings
        print "[INFO] Running strings against the Binary"
        STRINGS = ""
        sl = list(strings(BIN_PATH))
        sl = set(sl)  # Make unique
        sl = [s if isinstance(s, unicode) else unicode(
            s, encoding="utf-8", errors="replace") for s in sl]
        sl = [escape(s) for s in sl]  # Escape evil strings
        STRINGS = sl

        return XML, BIN_NAME, ID, VER, SDK, PLTFM, MIN, LIBS, BIN_RES, STRINGS, PERMISSIONS
    except:
        PrintException("[ERROR] iOS Binary Analysis")


def iOS_Source_Analysis(SRC, MD5):
    try:
        print "[INFO] Starting iOS Source Code and PLIST Analysis"
        ALLURLSLST = list()
        DOMAINS = dict()
        APP = ''
        InfoP = ''
        BIN_NAME = ''
        BIN = ''
        ID = ''
        VER = ''
        SDK = ''
        PLTFM = ''
        MIN = ''
        XML = ''

        for f in os.listdir(SRC):
            if f.endswith(".xcodeproj"):
                APP = f.replace(".xcodeproj", "")
        PlistFile = APP + "-Info.plist"
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if PlistFile in jfile:
                    InfoP = os.path.join(SRC, dirName, jfile)
                    break
        if isFileExists(InfoP):
            with io.open(InfoP, mode='r', encoding="utf8", errors="ignore") as f:
                XML = f.read()
        if XML:
            p = plistlib.readPlistFromString(XML)
            BIN_NAME = p["CFBundleDisplayName"]
            BIN = p["CFBundleExecutable"]
            ID = p["CFBundleIdentifier"]
            VER = p["CFBundleVersion"]
            SDK = ''  # p["DTSDKName"]
            PLTFM = ''  # p["DTPlatformVersion"]
            MIN = ''  # p["MinimumOSVersion"]
            PERMISSIONS = __check_permissions(p)

        # Code Analysis
        EmailnFile = ''
        URLnFile = ''
        c = {key: [] for key in ('i_buf', 'webv', 'i_log', 'net', 'i_sqlite',
                                 'fileio', 'ssl_bypass', 'ssl_uiwebview', 'path_traversal')}
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if jfile.endswith(".m"):

                    jfile_path = os.path.join(SRC, dirName, jfile)
                    if "+" in jfile:
                        p2 = os.path.join(
                            SRC, dirName, jfile.replace("+", "x"))
                        shutil.move(jfile_path, p2)
                        jfile_path = p2
                    repath = dirName.replace(SRC, '')
                    dat = ''
                    with io.open(jfile_path, mode='r', encoding="utf8", errors="ignore") as f:
                        dat = f.read()

                    URLS = []
                    EMAILS = []

                    # API
                    if (re.findall("NSURL|CFStream|NSStream", dat)):
                        c['net'].append(jfile_path.replace(SRC, ''))
                    if (re.findall("Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete", dat)):
                        c['fileio'].append(jfile_path.replace(SRC, ''))
                    if (re.findall("WebView|UIWebView", dat)):
                        c['webv'].append(jfile_path.replace(SRC, ''))

                    # SECURITY ANALYSIS
                    if (re.findall("strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets", dat)):
                        c['i_buf'].append(jfile_path.replace(SRC, ''))
                    if (re.findall("NSLog", dat)):
                        c['i_log'].append(jfile_path.replace(SRC, ''))
                    if (re.findall("sqlite3_exec", dat)):
                        c['i_sqlite'].append(jfile_path.replace(SRC, ''))
                    if re.findall('canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|allowInvalidCertificates\s*=\s*(YES|yes)', dat):
                        c['ssl_bypass'].append(jfile_path.replace(SRC, ''))
                    if re.findall('setAllowsAnyHTTPSCertificate:\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)', dat):
                        c['ssl_uiwebview'].append(jfile_path.replace(SRC, ''))
                    if "NSTemporaryDirectory()," in dat:
                        c['path_traversal'].append(jfile_path.replace(SRC, ''))

                    fl = jfile_path.replace(SRC, '')
                    base_fl = ntpath.basename(fl)
                    # URLs My Custom regex
                    p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
                    urllist = re.findall(p, dat.lower())
                    ALLURLSLST.extend(urllist)
                    uflag = 0
                    for url in urllist:
                        if url not in URLS:
                            URLS.append(url)
                            uflag = 1
                    if uflag == 1:
                        URLnFile += "<tr><td>" + "<br>".join(URLS) + "</td><td><a href='../ViewFile/?file=" + escape(
                            fl) + "&type=m&mode=ios&md5=" + MD5 + "'>" + escape(base_fl) + "</a></td></tr>"
                    # Email Etraction Regex

                    regex = re.compile("[\w.-]+@[\w-]+\.[\w.]+")
                    eflag = 0
                    for email in regex.findall(dat.lower()):
                        if ((email not in EMAILS) and (not email.startswith('//'))):
                            EMAILS.append(email)
                            eflag = 1
                    if eflag == 1:
                        EmailnFile += "<tr><td>" + "<br>".join(EMAILS) + "</td><td><a href='../ViewFile/?file=" + escape(
                            fl) + "&type=m&mode=ios&md5=" + MD5 + "'>" + escape(base_fl) + "</a></td></tr>"
        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        DOMAINS = MalwareCheck(ALLURLSLST)
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        dc = {'webv': 'WebView Component',
              'net': 'Network Calls',
              'fileio': 'Local File I/O Operations.',
              }
        html = ''
        for ky in dc:
            if c[ky]:
                link = ''
                hd = "<tr><td>" + dc[ky] + "</td><td>"
                for l in c[ky]:
                    link += "<a href='../ViewFile/?file=" + \
                        escape(l) + "&type=m&mode=ios&md5=" + MD5 + \
                        "'>" + escape(ntpath.basename(l)) + "</a> "
                html += hd + link + "</td></tr>"
        dg = {'i_buf': 'The App may contain banned API(s). These API(s) are insecure and must not be used.',
              'i_log': 'The App logs information. Sensitive information should never be logged.',
              'i_sqlite': 'App uses SQLite Database. Sensitive Information should be encrypted.',
              'ssl_bypass': 'App allows self signed or invalid SSL certificates. App is vulnerable to MITM attacks.',
              'ssl_uiwebview': 'UIWebView in App ignore SSL errors and accept any SSL Certificate. App is vulnerable to MITM attacks.',
              'path_traversal': 'Untrusted user input to "NSTemporaryDirectory()"" will result in path traversal vulnerability.',
              }
        dang = ''
        spn_dang = '<span class="label label-danger">high</span>'
        spn_info = '<span class="label label-info">info</span>'
        spn_sec = '<span class="label label-success">secure</span>'
        spn_warn = '<span class="label label-warning">warning</span>'
        for k in dg:
            if c[k]:
                link = ''
                if (re.findall('i_sqlite', k)):
                    hd = '<tr><td>' + dg[k] + \
                        '</td><td>' + spn_info + '</td><td>'
                elif (re.findall('path_traversal', k)):
                    hd = '<tr><td>' + dg[k] + \
                        '</td><td>' + spn_warn + '</td><td>'
                else:
                    hd = '<tr><td>' + dg[k] + \
                        '</td><td>' + spn_dang + '</td><td>'
                for ll in c[k]:
                    link += "<a href='../ViewFile/?file=" + \
                        escape(ll) + "&type=m&mode=ios&md5=" + MD5 + \
                        "'>" + escape(ntpath.basename(ll)) + "</a> "

                dang += hd + link + "</td></tr>"

        return html, dang, URLnFile, DOMAINS, EmailnFile, XML, BIN_NAME, ID, VER, SDK, PLTFM, MIN, PERMISSIONS
    except:
        PrintException("[ERROR] iOS Source Code Analysis")
