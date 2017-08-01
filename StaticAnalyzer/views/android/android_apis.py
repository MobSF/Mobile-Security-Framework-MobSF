"""
Rule Format

1. desc - Description of the findings

2. type
   a. string
   b. regex

3. match
   a. single_regex - if re.findall(regex1, input)
   b .regex_and - if re.findall(regex1, input) and re.findall(regex2, input)
   c. regex_or - if re.findall(regex1, input) or re.findall(regex2, input)
   d. regex_and_perm - if re.findall(regex, input) and (permission in permission_list_from_manifest)
   e. single_string - if string1 in input
   f. string_and - if (string1 in input) and (string2 in input)
   g. string_or - if (string1 in input) or (string2 in input)
   h. string_and_or -  if (string1 in input) and ((string2 in input) or (string3 in input))
   i. string_or_and - if (string1 in input) or ((string2 in input) and (string3 in input))
   j. string_and_perm - if (string1 in input) and (permission in permission_list_from_manifest)
   k. string_or_and_perm - if ((string1 in input) or (string2 in input)) and (permission in permission_list_from_manifest)

4. input_case
   a. upper
   b. lower
   c. exact

5. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3
   c. perm - Permission

"""
APIS = [
    {
        'desc': 'Loading Native Code (Shared Library) ',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'System\.loadLibrary\(|System\.load\(',
        'input_case': 'exact'
    },
    {
        'desc': 'Get System Service',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'getSystemService',
        'input_case': 'exact'
    },
    {
        'desc': 'Dynamic Class and Dexloading',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'dalvik\.system\.DexClassLoader|java\.security\.ClassLoader|java\.net\.URLClassLoader|java\.security\.SecureClassLoader',
        'input_case': 'exact'
    },
    {
        'desc': 'Java Reflection',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'java\.lang\.reflect\.Method|java\.lang\.reflect\.Field|Class\.forName',
        'input_case': 'exact'
    },
    {
        'desc': 'Crypto',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'javax\.crypto|kalium\.crypto|bouncycastle\.crypto',
        'input_case': 'exact'
    },
    {
        'desc': 'Starting Activity',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'startActivity\(|startActivityForResult\(',
        'input_case': 'exact'
    },
    {
        'desc': 'Starting Service',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'startService\(|bindService\(',
        'input_case': 'exact'
    },
    {
        'desc': 'Sending Broadcast',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(',
        'input_case': 'exact'
    },
    {
        'desc': 'Local File I/O Operations',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'OpenFileOutput|getSharedPreferences|SharedPreferences\.Editor|getCacheDir|getExternalStorageState|openOrCreateDatabase',
        'input_case': 'exact'
    },
    {
        'desc': 'Inter Process Communication',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'IRemoteService|IRemoteService\.Stub|IBinder|Intent',
        'input_case': 'exact'
    },
    {
        'desc': 'HTTP Requests, Connections and Sessions',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'http\.client\.HttpClient|net\.http\.AndroidHttpClient|http\.impl\.client\.AbstractHttpClient',
        'input_case': 'exact'
    },
    {
        'desc': 'HTTP Connection',
        'type': 'regex',
        'match': 'regex_and',
        'regex1': r'HttpURLConnection|org\.apache\.http',
        'regex2': r'openConnection|connect|HttpRequest',
        'input_case': 'exact'
    },
    {
        'desc': 'Load and Manipulate Dex Files',
        'type': 'regex',
        'match': 'regex_and',
        'regex1': r'dalvik\.system\.PathClassLoader|dalvik\.system\.DexFile|dalvik\.system\.DexPathList',
        'regex2': r'loadDex|loadClass|DexClassLoader|loadDexFile',
        'input_case': 'exact'
    },
    {
        'desc': 'Content Provider',
        'type': 'string',
        'match': 'single_string',
        'string1': 'android.content.ContentProvider',
        'input_case': 'exact'
    },
    {
        'desc': 'Obfuscation',
        'type': 'string',
        'match': 'string_and',
        'string1': 'utils.AESObfuscator',
        'string2': 'getObfuscator',
        'input_case': 'exact'
    },
    {
        'desc': 'Execute OS Command',
        'type': 'string',
        'match': 'string_and',
        'string1': 'getRuntime().exec(',
        'string2': 'getRuntime(',
        'input_case': 'exact'
    },
    {
        'desc': 'Android Keystore',
        'type': 'string',
        'match': 'string_and',
        'string1': 'security.KeyStore',
        'string2': 'Keystore.getInstance(',
        'input_case': 'exact'
    },
    
    {
        'desc': 'TCP Server Socket',
        'type': 'string',
        'match': 'string_and',
        'string1': 'ServerSocket',
        'string2': 'net.ServerSocket',
        'input_case': 'exact'
    },
    {
        'desc': 'TCP Socket',
        'type': 'string',
        'match': 'string_and',
        'string1': 'Socket',
        'string2': 'net.Socket',
        'input_case': 'exact'
    },
    {
        'desc': 'UDP Datagram Packet',
        'type': 'string',
        'match': 'string_and',
        'string1': 'DatagramPacket',
        'string2': 'net.DatagramPacket',
        'input_case': 'exact'
    },
    {
        'desc': 'UDP Datagram Socket',
        'type': 'string',
        'match': 'string_and',
        'string1': 'DatagramSocket',
        'string2': 'net.DatagramSocket',
        'input_case': 'exact'
    },
    {
        'desc': 'WebView JavaScript Interface',
        'type': 'string',
        'match': 'string_and',
        'string1': 'addJavascriptInterface',
        'string2': 'WebView',
        'string3': 'android.webkit',
        'input_case': 'exact'
    },
    {
        'desc': 'WebView GET Request',
        'type': 'string',
        'match': 'string_and',
        'string1': 'WebView',
        'string2': 'loadData',
        'string3': 'android.webkit',
        'input_case': 'exact'
    },
    {
        'desc': 'WebView POST Request',
        'type': 'string',
        'match': 'string_and',
        'string1': 'WebView',
        'string2': 'postUrl',
        'string3': 'android.webkit',
        'input_case': 'exact'
    },
    {
        'desc': 'Android Notifications',
        'type': 'string',
        'match': 'string_and',
        'string1': 'app.NotificationManager',
        'string2': 'notify',
        'input_case': 'exact'
    },
    {
        'desc': 'Get Cell Information',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getAllCellInfo',
        'input_case': 'exact'
    },
    {
        'desc': 'Get Cell Location',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getCellLocation',
        'input_case': 'exact'
    },
    {
        'desc': 'Get Subscriber ID',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getSubscriberId',
        'input_case': 'exact'
    },
    {
        'desc': 'Get Device ID, IMEI,MEID/ESN etc.',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getDeviceId',
        'input_case': 'exact'
    },
    {
        'desc': 'Get Software Version, IMEI/SV etc.',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getDeviceSoftwareVersion',
        'input_case': 'exact'
    },
    {
        'desc': 'Get SIM Serial Number',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getSimSerialNumber',
        'input_case': 'exact'
    },
    {
        'desc': 'Get SIM Provider Details',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getSimOperator',
        'input_case': 'exact'
    },
    {
        'desc': 'Get SIM Operator Name',
        'type': 'string',
        'match': 'string_and',
        'string1': 'telephony.TelephonyManager',
        'string2': 'getSimOperatorName',
        'input_case': 'exact'
    },
    {
        'desc': 'Query Database of SMS, Contacts etc.',
        'type': 'string',
        'match': 'string_and',
        'string1': 'content.ContentResolver',
        'string2': 'query',
        'input_case': 'exact'
    },
    {
        'desc': 'Query Database of SMS, Contacts etc.',
        'type': 'string',
        'match': 'string_and',
        'string1': 'content.ContentResolver',
        'string2': 'query',
        'input_case': 'exact'
    },
    {
        'desc': 'Base64 Decode',
        'type': 'string',
        'match': 'string_and',
        'string1': 'android.util.Base64',
        'string2': '.decode',
        'input_case': 'exact'
    },
    {
        'desc': 'Send SMS',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'telephony.SmsManager',
        'string_or1': 'sendMultipartTextMessage',
        'string_or2': 'sendTextMessage',
        'string_or3': 'vnd.android-dir/mms-sms',
        'input_case': 'exact'
    },
    {
        'desc': 'URL Connection to file/http/https/ftp/jar',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'net.URLConnection',
        'string_or1': 'openConnection',
        'string_or2': 'connect',
        'string_or3': 'openStream',
        'input_case': 'exact'
    },
    {
        'desc': 'JAR URL Connection',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'net.JarURLConnection',
        'string_or1': 'JarURLConnection',
        'string_or2': 'jar:',
        'input_case': 'exact'
    },
    {
        'desc': 'HTTPS Connection',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'javax.net.ssl.HttpsURLConnection',
        'string_or1': 'HttpsURLConnection',
        'string_or2': 'connect',
        'input_case': 'exact'
    },
    {
        'desc': 'URL Connection supports file,http,https,ftp and jar',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'net.URL',
        'string_or1': 'openConnection',
        'string_or2': 'openStream',
        'input_case': 'exact'
    },
    {
        'desc': 'Set or Read Clipboard data',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'content.ClipboardManager',
        'string_or1': 'CLIPBOARD_SERVICE',
        'string_or2': 'ClipboardManager',
        'input_case': 'exact'
    },
    {
        'desc': 'Base64 Encode',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'android.util.Base64',
        'string_or1': '.encodeToString',
        'string_or2': '.encode',
        'input_case': 'exact'
    },
    {
        'desc': 'Base64 Encode',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'android.util.Base64',
        'string_or1': '.encodeToString',
        'string_or2': '.encode',
        'input_case': 'exact'
    },
    {
        'desc': 'Message Digest',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'java.security.MessageDigest',
        'string_or1': 'MessageDigestSpi',
        'string_or2': 'MessageDigest',
        'input_case': 'exact'
    },
    {
        'desc': 'GPS Location',
        'type': 'string',
        'match': 'string_and_or',
        'string1': 'android.location',
        'string_or1': 'getLastKnownLocation(',
        'string_or2': 'requestLocationUpdates(',
        'string_or3': 'getLatitude(',
        'string_or4': 'getLongitude(',
        'input_case': 'exact'
    },
]
