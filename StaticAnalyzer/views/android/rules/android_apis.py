# -*- coding: utf_8 -*-
"""Android Code Analysis API Rules."""

from StaticAnalyzer.views.sast_core.matchers import (
    InputCase,
    RegexAnd,
    SingleRegex,
    SingleString,
    StringAnd,
    StringAndOr,
)
APIS = [
    {
        'desc': 'Loading Native Code (Shared Library) ',
        'type': SingleRegex.__name__,
        'match': r'System\.loadLibrary\(|System\.load\(',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get System Service',
        'type': SingleRegex.__name__,
        'match': r'getSystemService',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Dynamic Class and Dexloading',
        'type': SingleRegex.__name__,
        'match': (r'dalvik\.system\.DexClassLoader|'
                  r'java\.security\.ClassLoader|'
                  r'java\.net\.URLClassLoader|'
                  r'java\.security\.SecureClassLoader'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Java Reflection',
        'type': SingleRegex.__name__,
        'match': (r'java\.lang\.reflect\.Method|'
                  r'java\.lang\.reflect\.Field|Class\.forName'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Crypto',
        'type': SingleRegex.__name__,
        'match': r'javax\.crypto|kalium\.crypto|bouncycastle\.crypto',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Starting Activity',
        'type': SingleRegex.__name__,
        'match': r'startActivity\(|startActivityForResult\(',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Starting Service',
        'type': SingleRegex.__name__,
        'match': r'startService\(|bindService\(',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Sending Broadcast',
        'type': SingleRegex.__name__,
        'match': (r'sendBroadcast\(|'
                  r'sendOrderedBroadcast\(|sendStickyBroadcast\('),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Local File I/O Operations',
        'type': SingleRegex.__name__,
        'match': (r'OpenFileOutput|getSharedPreferences|'
                  r'SharedPreferences\.Editor|getCacheDir|'
                  r'getExternalStorageState|openOrCreateDatabase'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Inter Process Communication',
        'type': SingleRegex.__name__,
        'match': r'IRemoteService|IRemoteService\.Stub|IBinder|Intent',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'HTTP Requests, Connections and Sessions',
        'type': SingleRegex.__name__,
        'match': (r'http\.client\.HttpClient|net\.http\.AndroidHttpClient|'
                  r'http\.impl\.client\.AbstractHttpClient'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'HTTP Connection',
        'type': RegexAnd.__name__,
        'match': [r'HttpURLConnection|org\.apache\.http',
                  r'openConnection|connect|HttpRequest'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Load and Manipulate Dex Files',
        'type': RegexAnd.__name__,
        'match': [(r'dalvik\.system\.PathClassLoader|'
                   r'dalvik\.system\.DexFile|dalvik\.system\.DexPathList'),
                  r'loadDex|loadClass|DexClassLoader|loadDexFile'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Content Provider',
        'type': SingleString.__name__,
        'match': 'android.content.ContentProvider',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Obfuscation',
        'type': StringAnd.__name__,
        'match': ['utils.AESObfuscator', 'getObfuscator'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Execute OS Command',
        'type': StringAnd.__name__,
        'match': ['getRuntime().exec(', 'getRuntime('],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Android Keystore',
        'type': StringAnd.__name__,
        'match': ['security.KeyStore', 'Keystore.getInstance('],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'TCP Server Socket',
        'type': StringAnd.__name__,
        'match': ['ServerSocket', 'net.ServerSocket'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'TCP Socket',
        'type': StringAnd.__name__,
        'match': ['Socket', 'net.Socket'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UDP Datagram Packet',
        'type': StringAnd.__name__,
        'match': ['DatagramPacket', 'net.DatagramPacket'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UDP Datagram Socket',
        'type': StringAnd.__name__,
        'match': ['DatagramSocket', 'net.DatagramSocket'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView JavaScript Interface',
        'type': StringAnd.__name__,
        'match': ['addJavascriptInterface', 'WebView', 'android.webkit'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView GET Request',
        'type': StringAnd.__name__,
        'match': ['WebView', 'loadData', 'android.webkit'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView POST Request',
        'type': StringAnd.__name__,
        'match': ['WebView', 'postUrl', 'android.webkit'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Android Notifications',
        'type': StringAnd.__name__,
        'match': ['app.NotificationManager', 'notify'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get Cell Information',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getAllCellInfo'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get Cell Location',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getCellLocation'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get Subscriber ID',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getSubscriberId'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get Device ID, IMEI,MEID/ESN etc.',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getDeviceId'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get Software Version, IMEI/SV etc.',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getDeviceSoftwareVersion'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get SIM Serial Number',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getSimSerialNumber'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get SIM Provider Details',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getSimOperator'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Get SIM Operator Name',
        'type': StringAnd.__name__,
        'match': ['telephony.TelephonyManager', 'getSimOperatorName'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Query Database of SMS, Contacts etc.',
        'type': StringAnd.__name__,
        'match': ['content.ContentResolver', 'query'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Query Database of SMS, Contacts etc.',
        'type': StringAnd.__name__,
        'match': ['content.ContentResolver', 'query'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Base64 Decode',
        'type': StringAnd.__name__,
        'match': ['android.util.Base64', '.decode'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Send SMS',
        'type': StringAndOr.__name__,
        'match': ['telephony.SmsManager',
                  ['sendMultipartTextMessage',
                   'sendTextMessage', 'vnd.android-dir/mms-sms']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'URL Connection to file/http/https/ftp/jar',
        'type': StringAndOr.__name__,
        'match': ['net.URLConnection',
                  ['openConnection', 'connect', 'openStream']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'JAR URL Connection',
        'type': StringAndOr.__name__,
        'match': ['net.JarURLConnection', ['JarURLConnection', 'jar:']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'HTTPS Connection',
        'type': StringAndOr.__name__,
        'match': ['javax.net.ssl.HttpsURLConnection',
                  ['HttpsURLConnection', 'connect']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'URL Connection supports file,http,https,ftp and jar',
        'type': StringAndOr.__name__,
        'match': ['net.URL', ['openConnection', 'openStream']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Set or Read Clipboard data',
        'type': StringAndOr.__name__,
        'match': ['content.ClipboardManager',
                  ['CLIPBOARD_SERVICE', 'ClipboardManager']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Base64 Encode',
        'type': StringAndOr.__name__,
        'match': ['android.util.Base64', ['.encodeToString', '.encode']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Base64 Encode',
        'type': StringAndOr.__name__,
        'match': ['android.util.Base64', ['.encodeToString', '.encode']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Message Digest',
        'type': StringAndOr.__name__,
        'match': ['java.security.MessageDigest',
                  ['MessageDigestSpi', 'MessageDigest']],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'GPS Location',
        'type': StringAndOr.__name__,
        'match': ['android.location',
                  ['getLastKnownLocation(', 'requestLocationUpdates(',
                   'getLatitude(', 'getLongitude(']],
        'input_case': InputCase.exact,
    },
]
