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
   d. single_string - if string1 in input
   e. string_and - if (string1 in input) and (string2 in input)
   f. string_or - if (string1 in input) or (string2 in input)
   g. string_and_or -  if (string1 in input) and ((string_or1 in input) or (string_or2 in input))
   h. string_or_and - if (string1 in input) or ((string_and1 in input) and (string_and2 in input))

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

"""
CODE_RULES = [
    {
        'desc': 'The App may contain banned API(s). These API(s) are insecure and must not be used.',
        'type': 'regex',
        'regex1': r'strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'App allows self signed or invalid SSL certificates. App is vulnerable to MITM attacks.',
        'type': 'regex',
        'regex1': r'canAuthenticateAgainstProtectionSpace|' +
                  r'continueWithoutCredentialForAuthenticationChallenge|' +
                  r'kCFStreamSSLAllowsExpiredCertificates|' +
                  r'kCFStreamSSLAllowsAnyRoot|' +
                  r'kCFStreamSSLAllowsExpiredRoots|' +
                  r'validatesSecureCertificate\s*=\s*(no|NO)|' +
                  r'allowInvalidCertificates\s*=\s*(YES|yes)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'UIWebView in App ignore SSL errors and accept any SSL Certificate. App is vulnerable to MITM attacks.',
        'type': 'regex',
        'regex1': r'setAllowsAnyHTTPSCertificate:\s*YES|' +
                  r'allowsAnyHTTPSCertificateForHost|' +
                  r'loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.',
        'type': 'regex',
        'regex1': r'''(password\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(pass\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(username\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(secret\s*=\s*@*\s*['|"].+['|"]\s{0,5})|(key\s*=\s*@*\s*['|"].+['|"]\s{0,5})''',
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
        'desc': 'The App logs information. Sensitive information should never be logged.',
        'type': 'regex',
        'regex1': r'NSLog|NSAssert|fprintf|fprintf|Logging',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'This app listens to Clipboard changes. Some malwares also listen to Clipboard changes.',
        'type': 'regex',
        'regex1': r'UIPasteboardChangedNotification|generalPasteboard\]\.string',
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'App uses SQLite Database. Sensitive Information should be encrypted.',
        'type': 'string',
        'string1': 'sqlite3_exec',
        'level': 'info',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'Untrusted user input to "NSTemporaryDirectory()" will result in path traversal vulnerability.',
        'type': 'string',
        'string1': 'NSTemporaryDirectory(),',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'User input in "loadHTMLString" will result in JavaScript Injection.',
        'type': 'string',
        'string1': 'loadHTMLString',
        'string2': 'webView',
        'level': 'warning',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'SFAntiPiracy Jailbreak checks found',
        'type': 'string',
        'string1': 'SFAntiPiracy.h',
        'string2': 'SFAntiPiracy',
        'string3': 'isJailbroken',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'SFAntiPiracy Piracy checks found',
        'type': 'string',
        'string1': 'SFAntiPiracy.h',
        'string2': 'SFAntiPiracy',
        'string3': 'isPirated',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': 'string',
        'string1': 'CommonDigest.h',
        'string2': 'CC_MD5',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'SHA1 is a weak hash known to have hash collisions.',
        'type': 'string',
        'string1': 'CommonDigest.h',
        'string2': 'CC_SHA1',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is known to be weak as it results in the same ciphertext for identical blocks of plaintext.',
        'type': 'string',
        'string1': 'kCCOptionECBMode',
        'string2': 'kCCAlgorithmAES',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'The App has ant-debugger code using ptrace() ',
        'type': 'string',
        'string1': 'ptrace_ptr',
        'string2': 'PT_DENY_ATTACH',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact'
    },
    {
        'desc': 'This App has anti-debugger code using Mach Exception Ports.',
        'type': 'string',
        'string1': 'mach/mach_init.h',
        'string_or1': 'MACH_PORT_VALID',
        'string_or2': 'mach_task_self()',
        'level': 'info',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
    {
        'desc': 'This App copies data to clipboard. Sensitive data should not be copied to clipboard as other applications can access it.',
        'type': 'string',
        'string1': 'UITextField',
        'string_or1': '@select(cut:)',
        'string_or2': '@select(copy:)',
        'level': 'info',
        'match': 'string_and_or',
        'input_case': 'exact'
    },
    {
        'desc': 'This App may have Jailbreak detection capabilities.',
        'type': 'string',
        'string1': '/Applications/Cydia.app',
        'string2': '/Library/MobileSubstrate/MobileSubstrate.dylib',
        'string3': '/usr/sbin/sshd',
        'string4': '/etc/apt',
        'string5': 'cydia://',
        'string6': '/var/lib/cydia',
        'string7': '/Applications/FakeCarrier.app',
        'string8': '/Applications/Icy.app',
        'string9': '/Applications/IntelliScreen.app',
        'string10': '/Applications/SBSettings.app',
        'string11': '/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist',
        'string12': '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
        'string13': '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
        'string14': '/etc/ssh/sshd_config',
        'string15': '/private/var/tmp/cydia.log',
        'string16': '/usr/libexec/ssh-keysign',
        'level': 'good',
        'match': 'string_or',
        'input_case': 'exact'
    }
]
