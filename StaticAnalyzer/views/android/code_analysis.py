# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import io
import ntpath
import shutil
import re
import os

from django.conf import settings
from django.utils.html import escape

from MalwareAnalyzer.views import MalwareCheck

from MobSF.utils import (
    PrintException
)


def code_analysis(app_dir, md5, perms, typ):
    """Perform the code analysis."""
    try:
        print "[INFO] Static Android Code Analysis Started"
        code = {
            key: [] for key in (
                'inf_act',
                'inf_ser',
                'inf_bro',
                'log',
                'fileio',
                'rand',
                'd_hcode',
                'd_app_tamper',
                'dex_cert',
                'dex_tamper',
                'd_rootcheck',
                'd_root',
                'd_ssl_pin',
                'dex_root',
                'dex_debug_key',
                'dex_debug',
                'dex_debug_con',
                'dex_emulator',
                'd_prevent_screenshot',
                # Esteve 16.09.2016 - begin - Tap jacking prevention
                'd_prevent_tapjacking',
                # Esteve 16.09.2016 - end
                'd_webviewdisablessl',
                'd_webviewdebug',
                'd_sensitive',
                'd_ssl',
                'd_sqlite',
                'd_con_world_readable',
                'd_con_world_writable',
                'd_con_private',
                'd_extstorage',
                'd_tmpfile',
                'd_jsenabled',
                'gps',
                'crypto',
                'exec',
                'server_socket',
                'socket',
                'datagramp',
                'datagrams',
                'ipc',
                'msg',
                'webview_addjs',
                'webview',
                'webviewget',
                'webviewpost',
                'httpcon',
                'urlcon',
                'jurl',
                'httpsurl',
                'nurl',
                'httpclient',
                'notify',
                'cellinfo',
                'cellloc',
                'subid',
                'devid',
                'softver',
                'simserial',
                'simop',
                'opname',
                'contentq',
                'refmethod',
                'obf',
                'gs',
                'bencode',
                'bdecode',
                'dex',
                'mdigest',
                'sqlc_password',
                'd_sql_cipher',
                'd_con_world_rw',
                'ecb',
                'rsa_no_pad',
                'weak_iv'
            )
        }
        crypto = False
        obfus = False
        reflect = False
        dynamic = False
        native = False
        email_n_file = ''
        url_n_file = ''
        url_list = list()
        domains = dict()
        if typ == "apk":
            java_src = os.path.join(app_dir, 'java_source/')
        elif typ == "studio":
            java_src = os.path.join(app_dir, 'app/src/main/java/')
        elif typ == "eclipse":
            java_src = os.path.join(app_dir, 'src/')
        print "[INFO] Code Analysis Started on - " + java_src
        # pylint: disable=unused-variable
        # Needed by os.walk
        for dir_name, sub_dir, files in os.walk(java_src):
            for jfile in files:
                jfile_path = os.path.join(java_src, dir_name, jfile)
                if "+" in jfile:
                    p_2 = os.path.join(java_src, dir_name,
                                       jfile.replace("+", "x"))
                    shutil.move(jfile_path, p_2)
                    jfile_path = p_2
                repath = dir_name.replace(java_src, '')
                if (
                        jfile.endswith('.java') and
                        any(cls in repath for cls in settings.SKIP_CLASSES) is False
                ):
                    dat = ''
                    with io.open(
                        jfile_path,
                        mode='r',
                        encoding="utf8",
                        errors="ignore"
                    ) as file_pointer:
                        dat = file_pointer.read()
                    # Initialize
                    urls = []
                    emails = []
                    # Code Analysis
                    # print "[INFO] Doing Code Analysis on - " + jfile_path
                    #==========================Android Security Code Review ===
                    if (
                            re.findall(r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE', dat) or
                            re.findall(
                                r'openFileOutput\(\s*".+"\s*,\s*1\s*\)', dat)
                    ):
                        code['d_con_world_readable'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            re.findall(r'MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE', dat) or
                            re.findall(
                                r'openFileOutput\(\s*".+"\s*,\s*2\s*\)', dat)
                    ):
                        code['d_con_world_writable'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(r'openFileOutput\(\s*".+"\s*,\s*3\s*\)', dat):
                        code['d_con_world_rw'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(r'MODE_PRIVATE|Context\.MODE_PRIVATE', dat):
                        code['d_con_private'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            any("WRITE_EXTERNAL_STORAGE" in perm for perm in perms) and
                            (
                                '.getExternalStorage' in dat or
                                '.getExternalFilesDir(' in dat
                            )
                    ):
                        code['d_extstorage'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            any("WRITE_EXTERNAL_STORAGE" in perm for perm in perms) and
                            '.createTempFile(' in dat
                    ):
                        code['d_tmpfile'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'setJavaScriptEnabled(true)' in dat and
                            '.addJavascriptInterface(' in dat
                    ):
                        code['d_jsenabled'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            '.setWebContentsDebuggingEnabled(true)' in dat and
                            'WebView' in dat
                    ):
                        code['d_webviewdebug'].append(
                            jfile_path.replace(java_src, ''))
                    if 'onReceivedSslError(WebView' in dat and '.proceed();' in dat:
                        code['d_webviewdisablessl'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                'rawQuery(' in dat or
                                'execSQL(' in dat
                            ) and 'android.database.sqlite' in dat
                    ):
                        code['d_sqlite'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                ('javax.net.ssl') in dat
                            ) and (
                                ('TrustAllSSLSocket-Factory') in dat or
                                ('AllTrustSSLSocketFactory') in dat or
                                ('NonValidatingSSLSocketFactory') in dat or
                                ('ALLOW_ALL_HOSTNAME_VERIFIER') in dat or
                                ('.setDefaultHostnameVerifier(') in dat or
                                ('NullHostnameVerifier(') in dat
                            )
                    ):
                        code['d_ssl'].append(jfile_path.replace(java_src, ''))
                    if (
                            'password = "' in dat.lower() or
                            'secret = "' in dat.lower() or
                            'username = "' in dat.lower() or
                            'key = "' in dat.lower()
                    ):
                        code['d_sensitive'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'import dexguard.util' in dat and
                            'DebugDetector.isDebuggable' in dat
                    ):
                        code['dex_debug'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'import dexguard.util' in dat and
                            'DebugDetector.isDebuggerConnected' in dat
                    ):
                        code['dex_debug_con'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            ('import dexguard.util') in dat and
                            ('EmulatorDetector.isRunningInEmulator') in dat
                    ):
                        code['dex_emulator'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            ('import dexguard.util') in dat and
                            ('DebugDetector.isSignedWithDebugKey') in dat
                    ):
                        code['dex_debug_key'].append(
                            jfile_path.replace(java_src, ''))
                    if 'import dexguard.util' in dat and 'RootDetector.isDeviceRooted' in dat:
                        code['dex_root'].append(
                            jfile_path.replace(java_src, ''))
                    if 'import dexguard.util' in dat and 'TamperDetector.checkApk' in dat:
                        code['dex_tamper'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'import dexguard.util' in dat and
                            'CertificateChecker.checkCertificate' in dat
                    ):
                        code['dex_cert'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'org.thoughtcrime.ssl.pinning' in dat and (
                                'PinningHelper.getPinnedHttpsURLConnection' in dat or
                                'PinningHelper.getPinnedHttpClient' in dat or
                                'PinningSSLSocketFactory(' in dat
                            )
                    ):
                        code['d_ssl_pin'].append(
                            jfile_path.replace(java_src, ''))
                    if ('PackageManager.GET_SIGNATURES' in dat) and ('getPackageName(' in dat):
                        code['d_app_tamper'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            'com.noshufou.android.su' in dat or
                            'com.thirdparty.superuser' in dat or
                            'eu.chainfire.supersu' in dat or
                            'com.koushikdutta.superuser' in dat or
                            'eu.chainfire.' in dat
                    ):
                        code['d_root'].append(jfile_path.replace(java_src, ''))
                    if (
                            ('.contains("test-keys")') in dat or
                            ('/system/app/Superuser.apk') in dat or
                            ('isDeviceRooted()') in dat or
                            ('/system/bin/failsafe/su') in dat or
                            ('/system/sd/xbin/su') in dat or
                            ('"/system/xbin/which", "su"') in dat or
                            ('RootTools.isAccessGiven()') in dat
                    ):
                        code['d_rootcheck'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(r'java\.util\.Random', dat):
                        code['rand'].append(jfile_path.replace(java_src, ''))
                    if re.findall(r'Log\.(v|d|i|w|e|f|s)|System\.out\.print', dat):
                        code['log'].append(jfile_path.replace(java_src, ''))
                    if ".hashCode()" in dat:
                        code['d_hcode'].append(
                            jfile_path.replace(java_src, ''))
                    # Esteve 16.09.2016 - begin - Check optimisation - Both
                    # setFlags and addFlags can be used to assign values to
                    # flags
                    if ((("getWindow().setFlags(" in dat) or ("getWindow().addFlags(" in dat)) and
                            (".FLAG_SECURE" in dat)
                       ):
                        code['d_prevent_screenshot'].append(
                            jfile_path.replace(java_src, ''))
                    # Esteve 16.09.2016 - end
                    # Esteve 16.09.2016 - begin - Tap jacking prevention
                    if "setFilterTouchesWhenObscured(true)" in dat:
                        code['d_prevent_tapjacking'].append(
                            jfile_path.replace(java_src, ''))
                    # Esteve 16.09.2016 - end
                    if "SQLiteOpenHelper.getWritableDatabase(" in dat:
                        code['sqlc_password'].append(
                            jfile_path.replace(java_src, ''))
                    if "SQLiteDatabase.loadLibs(" in dat and "net.sqlcipher." in dat:
                        code['d_sql_cipher'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(r'Cipher\.getInstance\(\s*"\s*AES\/ECB', dat):
                        code['ecb'].append(jfile_path.replace(java_src, ''))
                    if re.findall(r'cipher\.getinstance\(\s*"rsa/.+/nopadding', dat.lower()):
                        code['rsa_no_pad'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" in dat or
                            "0x01,0x02,0x03,0x04,0x05,0x06,0x07" in dat
                    ):
                        code['weak_iv'].append(
                            jfile_path.replace(java_src, ''))

                    # Inorder to Add rule to Code Analysis, add identifier to c, add rule here and
                    # define identifier description and severity the bottom of this function.
                    #=========================Android API Analysis ============
                    # API Check

                    if re.findall(r"System.loadLibrary\(|System.load\(", dat):
                        native = True
                    if (
                            re.findall(
                                (
                                    r'dalvik.system.DexClassLoader|java.security.ClassLoader|'
                                    r'java.net.URLClassLoader|java.security.SecureClassLoader'
                                ),
                                dat
                            )
                    ):
                        dynamic = True
                    if (
                            re.findall(
                                'java.lang.reflect.Method|java.lang.reflect.Field|Class.forName',
                                dat
                            )
                    ):
                        reflect = True
                    if re.findall('javax.crypto|kalium.crypto|bouncycastle.crypto', dat):
                        crypto = True
                        code['crypto'].append(jfile_path.replace(java_src, ''))
                    if 'utils.AESObfuscator' in dat and 'getObfuscator' in dat:
                        code['obf'].append(jfile_path.replace(java_src, ''))
                        obfus = True

                    if 'getRuntime().exec(' in dat and 'getRuntime(' in dat:
                        code['exec'].append(jfile_path.replace(java_src, ''))
                    if 'ServerSocket' in dat and 'net.ServerSocket' in dat:
                        code['server_socket'].append(
                            jfile_path.replace(java_src, ''))
                    if 'Socket' in dat and 'net.Socket' in dat:
                        code['socket'].append(jfile_path.replace(java_src, ''))
                    if 'DatagramPacket' in dat and 'net.DatagramPacket' in dat:
                        code['datagramp'].append(
                            jfile_path.replace(java_src, ''))
                    if 'DatagramSocket' in dat and 'net.DatagramSocket' in dat:
                        code['datagrams'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall('IRemoteService|IRemoteService.Stub|IBinder|Intent', dat):
                        code['ipc'].append(jfile_path.replace(java_src, ''))
                    if (
                            (
                                'sendMultipartTextMessage' in dat or
                                'sendTextMessage' in dat or
                                'vnd.android-dir/mms-sms' in dat
                            ) and (
                                'telephony.SmsManager' in dat
                            )
                    ):
                        code['msg'].append(jfile_path.replace(java_src, ''))
                    if (
                            'addJavascriptInterface' in dat and
                            'WebView' in dat and
                            'android.webkit' in dat
                    ):
                        code['webview_addjs'].append(
                            jfile_path.replace(java_src, ''))
                    if 'WebView' in dat and 'loadData' in dat and 'android.webkit' in dat:
                        code['webviewget'].append(
                            jfile_path.replace(java_src, ''))
                    if 'WebView' in dat and 'postUrl' in dat and 'android.webkit' in dat:
                        code['webviewpost'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                'HttpURLConnection' in dat or
                                'org.apache.http' in dat
                            ) and (
                                'openConnection' in dat or
                                'connect' in dat or
                                'HttpRequest' in dat
                            )
                    ):
                        code['httpcon'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                'net.URLConnection' in dat
                            ) and (
                                'connect' in dat or
                                'openConnection' in dat or
                                'openStream' in dat
                            )
                    ):
                        code['urlcon'].append(jfile_path.replace(java_src, ''))
                    if (
                            (
                                'net.JarURLConnection' in dat
                            ) and (
                                'JarURLConnection' in dat or
                                'jar:' in dat
                            )
                    ):
                        code['jurl'].append(jfile_path.replace(java_src, ''))
                    if (
                            (
                                'javax.net.ssl.HttpsURLConnection' in dat
                            ) and (
                                'HttpsURLConnection' in dat or
                                'connect' in dat
                            )
                    ):
                        code['httpsurl'].append(
                            jfile_path.replace(java_src, ''))
                    if (('net.URL') and ('openConnection' or 'openStream')) in dat:
                        code['nurl'].append(jfile_path.replace(java_src, ''))
                    if (
                            re.findall(
                                (
                                    'http.client.HttpClient|net.http.AndroidHttpClient|'
                                    'http.impl.client.AbstractHttpClient'
                                ),
                                dat
                            )
                    ):
                        code['httpclient'].append(
                            jfile_path.replace(java_src, ''))
                    if 'app.NotificationManager' in dat and 'notify' in dat:
                        code['notify'].append(jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getAllCellInfo' in dat:
                        code['cellinfo'].append(
                            jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getCellLocation' in dat:
                        code['cellloc'].append(
                            jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSubscriberId' in dat:
                        code['subid'].append(jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getDeviceId' in dat:
                        code['devid'].append(jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getDeviceSoftwareVersion' in dat:
                        code['softver'].append(
                            jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimSerialNumber' in dat:
                        code['simserial'].append(
                            jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimOperator' in dat:
                        code['simop'].append(jfile_path.replace(java_src, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimOperatorName' in dat:
                        code['opname'].append(jfile_path.replace(java_src, ''))
                    if 'content.ContentResolver' in dat and 'query' in dat:
                        code['contentq'].append(
                            jfile_path.replace(java_src, ''))
                    if 'java.lang.reflect.Method' in dat and 'invoke' in dat:
                        code['refmethod'].append(
                            jfile_path.replace(java_src, ''))
                    if 'getSystemService' in dat:
                        code['gs'].append(jfile_path.replace(java_src, ''))
                    if (
                            (
                                'android.util.Base64' in dat
                            ) and (
                                '.encodeToString' in dat or
                                '.encode' in dat
                            )
                    ):
                        code['bencode'].append(
                            jfile_path.replace(java_src, ''))
                    if 'android.util.Base64' in dat and '.decode' in dat:
                        code['bdecode'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                'dalvik.system.PathClassLoader' in dat or
                                'dalvik.system.DexFile' in dat or
                                'dalvik.system.DexPathList' in dat or
                                'dalvik.system.DexClassLoader' in dat
                            ) and (
                                'loadDex' in dat or
                                'loadClass' in dat or
                                'DexClassLoader' in dat or
                                'loadDexFile' in dat
                            )
                    ):
                        code['dex'].append(jfile_path.replace(java_src, ''))
                    if (
                        (
                            'java.security.MessageDigest' in dat
                        ) and (
                            'MessageDigestSpi' in dat or
                            'MessageDigest' in dat
                        )
                    ):
                        code['mdigest'].append(
                            jfile_path.replace(java_src, ''))
                    if (
                            (
                                'android.location' in dat
                            )and (
                                ('getLastKnownLocation(') in dat or
                                'requestLocationUpdates(' in dat or
                                ('getLatitude(') in dat or
                                'getLongitude(' in dat
                            )
                    ):
                        code['gps'].append(jfile_path.replace(java_src, ''))
                    if re.findall(
                            (
                                'OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|'
                                'getCacheDir|getExternalStorageState|openOrCreateDatabase'
                            ),
                            dat
                    ):
                        code['fileio'].append(jfile_path.replace(java_src, ''))
                    if re.findall(r'startActivity\(|startActivityForResult\(', dat):
                        code['inf_act'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(r'startService\(|bindService\(', dat):
                        code['inf_ser'].append(
                            jfile_path.replace(java_src, ''))
                    if re.findall(
                            r'sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(', dat
                    ):
                        code['inf_bro'].append(
                            jfile_path.replace(java_src, ''))

                    j_file = jfile_path.replace(java_src, '')
                    base_fl = ntpath.basename(j_file)

                    # URLs My Custom regex
                    pattern = re.compile(
                        (
                            ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])'
                            ur'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
                        ),
                        re.UNICODE
                    )

                    urllist = re.findall(pattern, dat.lower())
                    url_list.extend(urllist)
                    uflag = 0
                    for url in urllist:
                        if url not in urls:
                            urls.append(url)
                            uflag = 1
                    if uflag == 1:
                        url_n_file += (
                            "<tr><td>" + "<br>".join(urls) +
                            "</td><td><a href='../ViewSource/?file=" + escape(j_file) +
                            "&md5=" + md5 + "&type=" + typ + "'>" + escape(base_fl) +
                            "</a></td></tr>"
                        )

                    # Email Etraction Regex
                    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w.]+')
                    eflag = 0
                    for email in regex.findall(dat.lower()):
                        if (email not in emails) and (not email.startswith('//')):
                            emails.append(email)
                            eflag = 1
                    if eflag == 1:
                        email_n_file += (
                            "<tr><td>" + "<br>".join(emails) +
                            "</td><td><a href='../ViewSource/?file=" + escape(j_file) +
                            "&md5=" + md5 + "&type=" + typ + "'>" + escape(base_fl) +
                            "</a></td></tr>"
                        )

        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        domains = MalwareCheck(url_list)
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        # API Description
        api_desc = {
            'gps': 'GPS Location',
            'crypto': 'Crypto ',
            'exec': 'Execute System Command ',
            'server_socket': 'TCP Server Socket ',
            'socket': 'TCP Socket ',
            'datagramp': 'UDP Datagram Packet ',
            'datagrams': 'UDP Datagram Socket ',
            'ipc': 'Inter Process Communication ',
            'msg': 'Send SMS ',
            'webview_addjs': 'WebView JavaScript Interface ',
            'webview': 'WebView Load HTML/JavaScript ',
            'webviewget': 'WebView GET Request ',
            'webviewpost': 'WebView POST Request ',
            'httpcon': 'HTTP Connection ',
            'urlcon': 'URL Connection to file/http/https/ftp/jar ',
            'jurl': 'JAR URL Connection ',
            'httpsurl': 'HTTPS Connection ',
            'nurl': 'URL Connection supports file,http,https,ftp and jar ',
            'httpclient': 'HTTP Requests, Connections and Sessions ',
            'notify': 'Android Notifications ',
            'cellinfo': 'Get Cell Information ',
            'cellloc': 'Get Cell Location ',
            'subid': 'Get Subscriber ID ',
            'devid': 'Get Device ID, IMEI,MEID/ESN etc. ',
            'softver': 'Get Software Version, IMEI/SV etc. ',
            'simserial': 'Get SIM Serial Number ',
            'simop': 'Get SIM Provider Details ',
            'opname': 'Get SIM Operator Name ',
            'contentq': 'Query Database of SMS, Contacts etc. ',
            'refmethod': 'Java Reflection Method Invocation ',
            'obf': 'Obfuscation ',
            'gs': 'Get System Service ',
            'bencode': 'Base64 Encode ',
            'bdecode': 'Base64 Decode ',
            'dex': 'Load and Manipulate Dex Files ',
            'mdigest': 'Message Digest ',
            'fileio': 'Local File I/O Operations',
            'inf_act': 'Starting Activity',
            'inf_ser': 'Starting Service',
            'inf_bro': 'Sending Broadcast'
        }
        html = ''
        for api_key in api_desc:
            if code[api_key]:
                link = ''
                # TODO(No idea what hd means here..)
                h_d = "<tr><td>" + api_desc[api_key] + "</td><td>"
                for elem in code[api_key]:
                    link += (
                        "<a href='../ViewSource/?file=" + escape(elem) + "&md5=" + md5 + "&type=" +
                        typ + "'>" + escape(ntpath.basename(elem)) + "</a> "
                    )
                html += h_d + link + "</td></tr>"

        # Security Code Review Description
        desc = {
            'd_sensitive':
                (
                    'Files may contain hardcoded sensitive informations like '
                    'usernames, passwords, keys etc.'
                ),
            'd_ssl':
                (
                    'Insecure Implementation of SSL. Trusting all the certificates or accepting '
                    'self signed certificates is a critical Security Hole. This application is '
                    'vulnerable to MITM attacks'
                ),
            'd_sqlite':
                (
                    'App uses SQLite Database and execute raw SQL query. Untrusted user input in '
                    'raw SQL queries can cause SQL Injection. Also sensitive information should be '
                    'encrypted and written to the database.'
                ),
            'd_con_world_readable':
                (
                    'The file is World Readable. Any App can read from the file'
                ),
            'd_con_world_writable':
                (
                    'The file is World Writable. Any App can write to the file'
                ),
            'd_con_world_rw':
                (
                    'The file is World Readable and Writable. Any App can read/write to the file'
                ),
            'd_con_private':
                (
                    'App can write to App Directory. Sensitive Information should be encrypted.'
                ),
            'd_extstorage':
                (
                    'App can read/write to External Storage. Any App can read data written to '
                    'External Storage.'
                ),
            'd_tmpfile':
                (
                    'App creates temp file. Sensitive information should never be written into a '
                    'temp file.'
                ),
            'd_jsenabled':
                (
                    'Insecure WebView Implementation. Execution of user controlled code in WebView '
                    'is a critical Security Hole.'
                ),
            'd_webviewdisablessl':
                (
                    'Insecure WebView Implementation. WebView ignores SSL Certificate errors and '
                    'accept any SSL Certificate. This application is vulnerable to MITM attacks'
                ),
            'd_webviewdebug':
                (
                    'Remote WebView debugging is enabled.'
                ),
            'dex_debug':
                (
                    'DexGuard Debug Detection code to detect wheather an App is debuggable or not '
                    'is identified.'
                ),
            'dex_debug_con':
                (
                    'DexGuard Debugger Detection code is identified.'
                ),
            'dex_debug_key':
                (
                    'DecGuard code to detect wheather the App is signed with a debug key or not '
                    'is identified.'
                ),
            'dex_emulator':
                (
                    'DexGuard Emulator Detection code is identified.'
                ),
            'dex_root':
                (
                    'DexGuard Root Detection code is identified.'
                ),
            'dex_tamper':
                (
                    'DexGuard App Tamper Detection code is identified.'
                ),
            'dex_cert':
                (
                    'DexGuard Signer Certificate Tamper Detection code is identified.'
                ),
            'd_ssl_pin':
                (
                    ' This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to '
                    'prevent MITM attacks in secure communication channel.'
                ),
            'd_root':
                (
                    'This App may request root (Super User) privileges.'
                ),
            'd_rootcheck':
                (
                    'This App may have root detection capabilities.'
                ),
            'd_hcode':
                (
                    'This App uses Java Hash Code. It\'s a weak hash function and should never be '
                    'used in Secure Crypto Implementation.'
                ),
            'rand':
                (
                    'The App uses an insecure Random Number Generator.'
                ),
            'log':
                (
                    'The App logs information. Sensitive information should never be logged.'
                ),
            'd_app_tamper':
                (
                    'The App may use package signature for tamper detection.'
                ),
            'd_prevent_screenshot':
                (
                    'This App has capabilities to prevent against Screenshots from Recent Task '
                    'History/ Now On Tap etc.'
                ),
            # Esteve 16.09.2016 - begin - Tap jacking prevention
            'd_prevent_tapjacking' :
                (
                    'This app has capabilities to prevent tapjacking attacks.'
                ),
            # Esteve 16.09.2016 - end
            'd_sql_cipher':
                (
                    'This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite '
                    'database files.'
                ),
            'sqlc_password':
                (
                    'This App uses SQL Cipher. But the secret may be hardcoded.'
                ),
            'ecb':
                (
                    'The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is '
                    'known to be weak as it results in the same ciphertext for identical blocks '
                    'of plaintext.'
                ),
            'rsa_no_pad':
                (
                    'This App uses RSA Crypto without OAEP padding. The purpose of the padding '
                    'scheme is to prevent a number of attacks on RSA that only work when the '
                    'encryption is performed without padding.'
                ),
            'weak_iv':
                (
                    'The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or '
                    '"0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the '
                    'resulting ciphertext much more predictable and susceptible to a dictionary '
                    'attack.'
                ),
        }

        dang = ''
        spn_dang = '<span class="label label-danger">high</span>'
        spn_info = '<span class="label label-info">info</span>'
        spn_sec = '<span class="label label-success">secure</span>'
        spn_warn = '<span class="label label-warning">warning</span>'

        for k in desc:
            if code[k]:
                link = ''
                if re.findall('d_con_private|log', k):
                    h_d = '<tr><td>' + desc[k] + \
                        '</td><td>' + spn_info + '</td><td>'
                # Esteve 16.09.2016 - begin - Tap jacking prevention - add d_prevent_tapjacking
                elif re.findall(
                        (
                            'd_sql_cipher|d_prevent_screenshot|d_prevent_tapjacking|d_app_tamper|'
                            'd_rootcheck|dex_cert|dex_tamper|dex_debug|dex_debug_con|dex_debug_key|'
                            'dex_emulator|dex_root|d_ssl_pin'
                        ),
                        k
                ):
                # Esteve 16.09.2016 - end
                    h_d = '<tr><td>' + desc[k] + \
                        '</td><td>' + spn_sec + '</td><td>'
                elif re.findall('d_jsenabled', k):
                    h_d = '<tr><td>' + desc[k] + \
                        '</td><td>' + spn_warn + '</td><td>'
                else:
                    h_d = '<tr><td>' + desc[k] + \
                        '</td><td>' + spn_dang + '</td><td>'

                for elem in code[k]:
                    link += (
                        "<a href='../ViewSource/?file=" + escape(elem) + "&md5=" + md5 + "&type=" +
                        typ + "'>" + escape(ntpath.basename(elem)) + "</a> "
                    )

                dang += h_d + link + "</td></tr>"

        code_an_dic = {
            'api': html,
            'dang': dang,
            'urls': url_n_file,
            'domains': domains,
            'emails': email_n_file,
            'crypto': crypto,
            'obfus': obfus,
            'reflect': reflect,
            'dynamic': dynamic,
            'native': native
        }

        return code_an_dic
    except:
        PrintException("[ERROR] Performing Code Analysis")
