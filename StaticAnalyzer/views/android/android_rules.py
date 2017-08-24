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
   h. string_and_or -  if (string1 in input) and ((string_or1 in input) or (string_or2 in input))
   i. string_or_and - if (string1 in input) or ((string_and1 in input) and (string_and2 in input))
   j. string_and_perm - if (string1 in input) and (permission in permission_list_from_manifest)
   k. string_or_and_perm - if ((string1 in input) or (string2 in input)) and (permission in permission_list_from_manifest)

4. level
   a. high
   b. warning
   c. info
   d. good

5. input_case
   a. upper
   b. lower
   c. exact

6. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3
   c. perm - Permission

"""
RULES = [
    {
        'desc': 'Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.',
        'type': 'regex',
        'regex1': r'''(password\s*=\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*['|"].+['|"]\s{0,5})|(username\s*=\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*['|"].+['|"]\s{0,5})|(key\s*=\s*['|"].+['|"]\s{0,5})''',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'lower'
    },
    {
        'desc': 'IP Address disclosure',
        'type': 'regex',
        'regex1': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'Hidden elements in view can be used to hide data from user. But this data can be leaked',
        'type': 'regex',
        'regex1': r'setVisibility\(View\.GONE\)|setVisibility\(View\.INVISIBLE\)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is known to be weak as it results in the same ciphertext for identical blocks of plaintext.',
        'type': 'regex',
        'regex1': r'Cipher\.getInstance\(\s*"\s*AES\/ECB',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses RSA Crypto without OAEP padding. The purpose of the padding scheme is to prevent a number of attacks on RSA that only work when the encryption is performed without padding.',
        'type': 'regex',
        'regex1': r'cipher\.getinstance\(\s*"rsa/.+/nopadding',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'lower'
    },
    {
        'desc': 'Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks',
        'type': 'regex',
        'regex1': r'javax\.net\.ssl',
        'regex2': r'TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\(',
        'level': 'high',
        'match': 'regex_and',
        'input_case': 'exact'
    },
    {
        'desc': 'WebView load files from external storage. Files in external storage can be modified by any application.',
        'type': 'regex',
        'regex1': r'\.loadUrl\(.*getExternalStorageDirectory\(',
        'regex2': r'webkit\.WebView',
        'level': 'high',
        'match': 'regex_and',
        'input_case': 'exact'
    },
    {
        'desc': 'The file is World Readable. Any App can read from the file',
        'type': 'regex',
        'regex1': r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE',
        'regex2': r'openFileOutput\(\s*".+"\s*,\s*1\s*\)',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact'
    },
    {
        'desc': 'The file is World Writable. Any App can write to the file',
        'type': 'regex',
        'regex1': r'MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE',
        'regex2': r'openFileOutput\(\s*".+"\s*,\s*2\s*\)',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact'
    },
    {
        'desc': 'The file is World Readable and Writable. Any App can read/write to the file',
        'type': 'regex',
        'regex1': r'openFileOutput\(\s*".+"\s*,\s*3\s*\)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'Weak Hash algorithm used',
        'type': 'regex',
        'regex1': r'getInstance(\"md4\")|getInstance(\"rc2\")|getInstance(\"rc4\")|getInstance(\"RC4\")|getInstance(\"RC2\")|getInstance(\"MD4\")',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'MessageDigest\.getInstance\(\"*MD5\"*\)|MessageDigest\.getInstance\(\"*md5\"*\)|DigestUtils\.md5\(',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'SHA-1 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'MessageDigest\.getInstance\(\"*SHA-1\"*\)|MessageDigest\.getInstance\(\"*sha-1\"*\)|DigestUtils\.sha\(',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'App can write to App Directory. Sensitive Information should be encrypted.',
        'type': 'regex',
        'regex1': r'MODE_PRIVATE|Context\.MODE_PRIVATE',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'The App uses an insecure Random Number Generator.',
        'type': 'regex',
        'regex1': r'java\.util\.Random',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'The App logs information. Sensitive information should never be logged.',
        'type': 'regex',
        'regex1': r'Log\.(v|d|i|w|e|f|s)|System\.out\.print|System\.err\.print',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses Java Hash Code. It\'s a weak hash function and should never be used in Secure Crypto Implementation.',
        'type': 'string',
        'string1': '.hashCode()',
        'level': 'high',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'These activities prevent screenshot when they go to background.',
        'type': 'string',
        'string1': 'LayoutParams.FLAG_SECURE',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses SQL Cipher. But the secret may be hardcoded.',
        'type': 'string',
        'string1': 'SQLiteOpenHelper.getWritableDatabase(',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'This app has capabilities to prevent tapjacking attacks.',
        'type': 'string',
        'string1': 'setFilterTouchesWhenObscured(true)',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'App can read/write to External Storage. Any App can read data written to External Storage.',
        'perm': 'android.permission.WRITE_EXTERNAL_STORAGE',
        'type': 'string',
        'string1': '.getExternalStorage',
        'string2': '.getExternalFilesDir(',
        'level': 'high',
        'match': 'string_or_and_perm',
        'input_case': 'exact'
    },
    {
        'desc': 'App creates temp file. Sensitive information should never be written into a temp file.',
        'perm': 'android.permission.WRITE_EXTERNAL_STORAGE',
        'type': 'string',
        'string1': '.createTempFile(',
        'level': 'high',
        'match': 'string_and_perm',
        'input_case': 'exact'
    },
    {
        'desc': 'Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole.',
        'type': 'string',
        'string1': 'setJavaScriptEnabled(true)',
        'string2': '.addJavascriptInterface(',
        'level': 'warning',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite database files.',
        'type': 'string',
        'string1': 'SQLiteDatabase.loadLibs(',
        'string2': 'net.sqlcipher.',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App download files using Android Download Manager',
        'type': 'string',
        'string1': 'android.app.DownloadManager',
        'string2': 'getSystemService(DOWNLOAD_SERVICE)',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App use Realm Database with encryption.',
        'type': 'string',
        'string1': 'io.realm.Realm',
        'string2': '.encryptionKey(',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or "0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the resulting ciphertext much more predictable and susceptible to a dictionary attack.',
        'type': 'string',
        'string1': '0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00',
        'string2': '0x01,0x02,0x03,0x04,0x05,0x06,0x07',
        'level': 'high',
        'match': 'string_or',
        'input_case': 'exact'
    },
    {
        'desc': 'Remote WebView debugging is enabled.',
        'type': 'string',
        'string1': '.setWebContentsDebuggingEnabled(true)',
        'string2': 'WebView',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.',
        'type': 'string',
        'string1': 'content.ClipboardManager',
        'string2': 'OnPrimaryClipChangedListener',
        'level': 'warning',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App copies data to clipboard. Sensitive data should not be copied to clipboard as other applications can access it.',
        'type': 'string',
        'string1': 'content.ClipboardManager',
        'string2': 'setPrimaryClip(',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'Insecure WebView Implementation. WebView ignores SSL Certificate errors and accept any SSL Certificate. This application is vulnerable to MITM attacks',
        'type': 'string',
        'string1': 'onReceivedSslError(WebView',
        'string2': '.proceed();',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.',
        'type': 'string',
        'string1': 'android.database.sqlite',
        'string_or1': 'rawQuery(',
        'string_or2': 'execSQL(',
        'level': 'high',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
       {
        'desc': 'This App detects frida server.',
        'type': 'string',
        'string1': 'fridaserver',
        'string_or1': '27047',
        'string_or2': 'REJECT',
        'string_or3': 'LIBFRIDA',
        'level': 'good',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to prevent MITM attacks in secure communication channel.',
        'type': 'string',
        'string1': 'org.thoughtcrime.ssl.pinning',
        'string_or1': 'PinningHelper.getPinnedHttpsURLConnection',
        'string_or2': 'PinningHelper.getPinnedHttpClient',
        'string_or3': 'PinningSSLSocketFactory(',
        'level': 'good',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
    {
        'desc': 'This App has capabilities to prevent against Screenshots from Recent Task History/ Now On Tap etc.',
        'type': 'string',
        'string1': '.FLAG_SECURE',
        'string_or1': 'getWindow().setFlags(',
        'string_or2': 'getWindow().addFlags(',
        'level': 'high',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard Debug Detection code to detect wheather an App is debuggable or not is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isDebuggable',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard Debugger Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isDebuggerConnected',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard Emulator Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'EmulatorDetector.isRunningInEmulator',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DecGuard code to detect wheather the App is signed with a debug key or not is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'DebugDetector.isSignedWithDebugKey',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard Root Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'RootDetector.isDeviceRooted',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard App Tamper Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'TamperDetector.checkApk',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'DexGuard Signer Certificate Tamper Detection code is identified.',
        'type': 'string',
        'string1': 'import dexguard.util',
        'string2': 'TCertificateChecker.checkCertificate',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'The App may use package signature for tamper detection.',
        'type': 'string',
        'string1': 'PackageManager.GET_SIGNATURES',
        'string2': 'getPackageName(',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App uses SafetyNet API.',
        'type': 'string',
        'string1': 'com.google.android.gms.safetynet.SafetyNetApi',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'This App may request root (Super User) privileges.',
        'type': 'string',
        'string1': 'com.noshufou.android.su',
        'string2': 'com.thirdparty.superuser',
        'string3': 'eu.chainfire.supersu',
        'string4': 'com.koushikdutta.superuser',
        'string5': 'eu.chainfire.',
        'level': 'high',
        'match': 'string_or',
        'input_case': 'exact'
    },
    {
        'desc': 'This App may have root detection capabilities.',
        'type': 'string',
        'string1': '.contains("test-keys")',
        'string2': '/system/app/Superuser.apk',
        'string3': 'isDeviceRooted()',
        'string4': '/system/bin/failsafe/su',
        'string5': '/system/sd/xbin/su',
        'string6': '"/system/xbin/which", "su"',
        "string7": 'RootTools.isAccessGiven()',
        'level': 'good',
        'match': 'string_or',
        'input_case': 'exact'
    }]


