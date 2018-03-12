"""
Perform Analysis on Dynamic Analysis Data
"""
import os
import io
import re
import json
import base64
import tarfile
import shutil

from pathlib import Path

from django.utils.html import escape

from MalwareAnalyzer.views import malware_check
from MobSF.utils import (
    python_list,
    isBase64,
    PrintException
)

def api_analysis(package, location):
    """API Analysis"""
    api_analysis_result = {}
    print("\n[INFO] Dynamic API Analysis")
    dat = ""
    api_base64 = []
    api_fileio = []
    api_reflect = []
    api_sysprop = []
    api_cntvl = []
    api_binder = []
    api_crypto = []
    api_acntmnger = []
    api_deviceinfo = []
    api_net = []
    api_dexloader = []
    api_cmd = []
    api_sms = []
    try:
        with open(location, "r") as flip:
            dat = flip.readlines()
        res_id = "Droidmon-apimonitor-" + package + ":"
        for line in dat:
            if res_id in line:
                # print "LINE: " + line
                _, value = line.split(res_id, 1)
                # print "PARAM is :" + param
                # print "Value is :"+ value
                try:
                    apis = json.loads(value, strict=False)
                    ret = ''
                    args = ''
                    mtd = str(apis["method"])
                    clss = str(apis["class"])
                    # print "Called Class: " + CLS
                    # print "Called Method: " + MTD
                    if apis.get('return'):
                        ret = str(apis["return"])
                        # print "Return Data: " + RET
                    else:
                        # print "No Return Data"
                        ret = "No Return Data"
                    if apis.get('args'):
                        args = str(apis["args"])
                        # print "Passed Arguments" + ARGS
                    else:
                        # print "No Arguments Passed"
                        args = "No Arguments Passed"
                    # XSS Safe
                    call_data = "</br>METHOD: " + \
                        escape(mtd) + "</br>ARGUMENTS: " + escape(args) + \
                        "</br>RETURN DATA: " + escape(ret)

                    if re.findall("android.util.Base64", clss):
                        # Base64 Decode
                        if "decode" in mtd:
                            args_list = python_list(args)
                            if isBase64(args_list[0]):
                                call_data += '</br><span class="label label-info">' +\
                                    'Decoded String:</span> ' + \
                                    escape(base64.b64decode(args_list[0]))
                        api_base64.append(call_data)
                    if re.findall('libcore.io|android.app.SharedPreferencesImpl\$EditorImpl', clss):
                        api_fileio.append(call_data)
                    if re.findall('java.lang.reflect', clss):
                        api_reflect.append(call_data)
                    if re.findall('android.content.ContentResolver|android.location.Location|android.media.AudioRecord|android.media.MediaRecorder|android.os.SystemProperties', clss):
                        api_sysprop.append(call_data)
                    if re.findall('android.app.Activity|android.app.ContextImpl|android.app.ActivityThread', clss):
                        api_binder.append(call_data)
                    if re.findall('javax.crypto.spec.SecretKeySpec|javax.crypto.Cipher|javax.crypto.Mac', clss):
                        api_crypto.append(call_data)
                    if re.findall('android.accounts.AccountManager|android.app.ApplicationPackageManager|android.app.NotificationManager|android.net.ConnectivityManager|android.content.BroadcastReceiver', clss):
                        api_acntmnger.append(call_data)
                    if re.findall('android.telephony.TelephonyManager|android.net.wifi.WifiInfo|android.os.Debug', clss):
                        api_deviceinfo.append(call_data)
                    if re.findall('dalvik.system.BaseDexClassLoader|dalvik.system.DexFile|dalvik.system.DexClassLoader|dalvik.system.PathClassLoader', clss):
                        api_dexloader.append(call_data)
                    if re.findall('java.lang.Runtime|java.lang.ProcessBuilder|java.io.FileOutputStream|java.io.FileInputStream|android.os.Process', clss):
                        api_cmd.append(call_data)
                    if re.findall('android.content.ContentValues', clss):
                        api_cntvl.append(call_data)
                    if re.findall('android.telephony.SmsManager', clss):
                        api_sms.append(call_data)
                    if re.findall('java.net.URL|org.apache.http.impl.client.AbstractHttpClient', clss):
                        api_net.append(call_data)
                except:
                    PrintException("[ERROR] Parsing JSON Failed for: " + value)
    except:
        PrintException("[ERROR] Dynamic API Analysis")
    api_analysis_result["api_net"] = list(set(api_net))
    api_analysis_result["api_base64"] = list(set(api_base64))
    api_analysis_result["api_fileio"] = list(set(api_fileio))
    api_analysis_result["api_binder"] = list(set(api_binder))
    api_analysis_result["api_crypto"] = list(set(api_crypto))
    api_analysis_result["api_deviceinfo"] = list(set(api_deviceinfo))
    api_analysis_result["api_cntvl"] = list(set(api_cntvl))
    api_analysis_result["api_sms"] = list(set(api_sms))
    api_analysis_result["api_sysprop"] = list(set(api_sysprop))
    api_analysis_result["api_dexloader"] = list(set(api_dexloader))
    api_analysis_result["api_reflect"] = list(set(api_reflect))
    api_analysis_result["api_acntmnger"] = list(set(api_acntmnger))
    api_analysis_result["api_cmd"] = list(set(api_cmd))
    return api_analysis_result

def run_analysis(apk_dir, md5_hash, package):
    """Run Dynamic File Analysis"""
    analysis_result = {}
    print("\n[INFO] Dynamic File Analysis")
    capfuzz_home = os.path.join(str(Path.home()), ".capfuzz")
    web = os.path.join(capfuzz_home, 'flows', package + ".flows.txt")
    logcat = os.path.join(apk_dir, 'logcat.txt')
    xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
    traffic = ''
    web_data = ''
    xlg = ''
    domains = {}
    logcat_data = []
    clipboard = []
    clip_tag = "I/CLIPDUMP-INFO-LOG"
    try:
        with io.open(web, mode='r', encoding="utf8", errors="ignore") as flip:
            web_data = flip.read()
    except:
        pass
    with io.open(logcat, mode='r', encoding="utf8", errors="ignore") as flip:
        logcat_data = flip.readlines()
        traffic = ''.join(logcat_data)
    with io.open(xlogcat, mode='r', encoding="utf8", errors="ignore") as flip:
        xlg = flip.read()
    traffic = web_data + traffic + xlg
    for log_line in logcat_data:
        if log_line.startswith(clip_tag):
            clipboard.append(log_line.replace(clip_tag, "Process ID "))
    urls = []
    # URLs My Custom regex
    url_pattern = re.compile(r'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
    urllist = re.findall(url_pattern, traffic.lower())
    # Domain Extraction and Malware Check
    print("[INFO] Performing Malware Check on extracted Domains")
    domains = malware_check(urllist)
    for url in urllist:
        if url not in urls:
            urls.append(url)

    # Email Etraction Regex
    emails = []
    regex = re.compile(r"[\w.-]+@[\w-]+\.[\w.]+")
    for email in regex.findall(traffic.lower()):
        if (email not in emails) and (not email.startswith('//')):
            if email == "yodleebanglore@gmail.com":
                pass
            else:
                emails.append(email)
    # Extract Device Data
    try:
        tar_loc = os.path.join(apk_dir, package + '.tar')
        untar_dir = os.path.join(apk_dir, 'DYNAMIC_DeviceData/')
        if not os.path.exists(untar_dir):
            os.makedirs(untar_dir)
        with tarfile.open(tar_loc) as tar:
            try:
                tar.extractall(untar_dir)
            except:
                pass
    except:
        PrintException("[ERROR] TAR EXTRACTION FAILED")
    # Do Static Analysis on Data from Device
    xmlfiles = ''
    sqlite_db = ''
    other_files = ''
    typ = ''
    untar_dir = os.path.join(apk_dir, 'DYNAMIC_DeviceData/')
    if not os.path.exists(untar_dir):
        os.makedirs(untar_dir)
    try:
        for dir_name, _, files in os.walk(untar_dir):
            for jfile in files:
                file_path = os.path.join(untar_dir, dir_name, jfile)
                if "+" in file_path:
                    shutil.move(file_path, file_path.replace("+", "x"))
                    file_path = file_path.replace("+", "x")
                fileparam = file_path.replace(untar_dir, '')
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        typ = 'xml'
                        xmlfiles += "<tr><td><a href='../View/?file=" + \
                            escape(fileparam) + "&md5=" + md5_hash + "&type=" + \
                            typ + "'>" + escape(fileparam) + "</a></td><tr>"
                    else:
                        with io.open(file_path, mode='r', encoding="utf8", errors="ignore") as flip:
                            file_cnt_sig = flip.read(6)
                        if file_cnt_sig == "SQLite":
                            typ = 'db'
                            sqlite_db += "<tr><td><a href='../View/?file=" + \
                                escape(fileparam) + "&md5=" + md5_hash + "&type=" + \
                                typ + "'>" + \
                                escape(fileparam) + "</a></td><tr>"
                        elif not jfile.endswith('.DS_Store'):
                            typ = 'others'
                            other_files += "<tr><td><a href='../View/?file=" + \
                                escape(fileparam) + "&md5=" + md5_hash + "&type=" + \
                                typ + "'>" + \
                                escape(fileparam) + "</a></td><tr>"
    except:
        PrintException("[ERROR] Dynamic File Analysis")
    analysis_result["urls"] = urls
    analysis_result["domains"] = domains
    analysis_result["emails"] = emails
    analysis_result["clipboard"] = clipboard
    analysis_result["web_data"] = web_data
    analysis_result["xmlfiles"] = xmlfiles
    analysis_result["sqlite_db"] = sqlite_db
    analysis_result["other_files"] = other_files
    return analysis_result

def download(md5_hash, download_dir, apk_dir, package):
    """Generating Downloads"""
    print("\n[INFO] Generating Downloads")
    try:

        capfuzz_home = os.path.join(str(Path.home()), ".capfuzz")
        logcat = os.path.join(apk_dir, 'logcat.txt')
        xlogcat = os.path.join(apk_dir, 'x_logcat.txt')
        dumpsys = os.path.join(apk_dir, 'dump.txt')
        sshot = os.path.join(apk_dir, 'screenshots-apk/')
        web = os.path.join(capfuzz_home, 'flows', package + ".flows.txt")
        star = os.path.join(apk_dir, package + '.tar')

        dlogcat = os.path.join(download_dir, md5_hash + '-logcat.txt')
        dxlogcat = os.path.join(download_dir, md5_hash + '-x_logcat.txt')
        ddumpsys = os.path.join(download_dir, md5_hash + '-dump.txt')
        dsshot = os.path.join(download_dir, md5_hash + '-screenshots-apk/')
        dweb = os.path.join(download_dir, md5_hash + '-WebTraffic.txt')
        dstar = os.path.join(download_dir, md5_hash + '-AppData.tar')

        # Delete existing data
        dellist = [dlogcat, dxlogcat, ddumpsys, dsshot, dweb, dstar]
        for item in dellist:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
        # Copy new data
        shutil.copyfile(logcat, dlogcat)
        shutil.copyfile(xlogcat, dxlogcat)
        shutil.copyfile(dumpsys, ddumpsys)
        try:
            shutil.copytree(sshot, dsshot)
        except:
            pass
        try:
            shutil.copyfile(web, dweb)
        except:
            pass
        try:
            shutil.copyfile(star, dstar)
        except:
            pass
    except:
        PrintException("[ERROR] Generating Downloads")
