"""
Rule Format.

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
   g. string_and_or -  if (string1 in input) and ((string_or1 in input)
                       or (string_or2 in input))
   h. string_or_and - if (string1 in input) or ((string_and1 in input)
                      and (string_and2 in input))

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
from StaticAnalyzer.views.standards import (
    CWE,
    OWASP,
    OWASP_MSTG,
)
from StaticAnalyzer.views.ios import common_rules

OBJC_RULES = common_rules.COMMON_RULES + [
    {
        'desc': ('The App may contain banned API(s). '
                 'These API(s) are insecure and must not be used.'),
        'type': 'regex',
        'regex1': (r'strcpy|memcpy|strcat|strncat|'
                   r'strncpy|sprintf|vsprintf|gets'),
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 2.2,
        'cwe': CWE['CWE-676'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['code-8'],
    },
    {
        'desc': ('App allows self signed or invalid '
                 'SSL certificates. App is vulnerable to MITM attacks.'),
        'type': 'regex',
        'regex1': (r'canAuthenticateAgainstProtectionSpace|'
                   r'continueWithoutCredentialForAuthenticationChallenge|'
                   r'kCFStreamSSLAllowsExpiredCertificates|'
                   r'kCFStreamSSLAllowsAnyRoot|'
                   r'kCFStreamSSLAllowsExpiredRoots|'
                   r'validatesSecureCertificate\s*=\s*(no|NO)|'
                   r'allowInvalidCertificates\s*=\s*(YES|yes)'),
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': CWE['CWE-295'],
        'owasp': OWASP['m3'],
        'owasp-mstg': OWASP_MSTG['network-3'],
    },
    {
        'desc': ('UIWebView in App ignore SSL errors and accept'
                 ' any SSL Certificate. App is vulnerable to MITM attacks.'),
        'type': 'regex',
        'regex1': (r'setAllowsAnyHTTPSCertificate:\s*YES|'
                   r'allowsAnyHTTPSCertificateForHost|'
                   r'loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)'),
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': CWE['CWE-295'],
        'owasp': OWASP['m3'],
        'owasp-mstg': OWASP_MSTG['network-3'],
    },
    {
        'desc': ('The App logs information. '
                 'Sensitive information should never be logged.'),
        'type': 'regex',
        'regex1': r'NSLog|NSAssert|fprintf|fprintf|Logging',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': CWE['CWE-532'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-3'],
    },
    {
        'desc': ('This app listens to Clipboard changes. '
                 'Some malwares also listen to Clipboard changes.'),
        'type': 'regex',
        'regex1': (r'UIPasteboardChangedNotification|'
                   r'generalPasteboard\]\.string'),
        'level': 'warning',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['platform-4'],
    },
    {
        'desc': ('Untrusted user input to "NSTemporaryDirectory()"'
                 ' will result in path traversal vulnerability.'),
        'type': 'string',
        'string1': 'NSTemporaryDirectory(),',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': CWE['CWE-22'],
        'owasp': OWASP['m10'],
        'owasp-mstg': OWASP_MSTG['platform-2'],
    },
    {
        'desc': ('File is stored in an encrypted format on '
                 'disk and cannot be read from or written to '
                 'while the device is locked or booting.'),
        'type': 'string',
        'string1': 'NSFileProtectionComplete',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('File is stored in an encrypted format '
                 'on disk after it is closed.'),
        'type': 'string',
        'string1': 'NSFileProtectionCompleteUnlessOpen',
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('File is stored in an encrypted format '
                 'on disk and cannot be accessed until after '
                 'the device has booted.'),
        'type': 'string',
        'string1': (
            'NSFileProtectionComplete'
            'UntilFirstUserAuthentication'),
        'level': 'good',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('The file has no special protections '
                 'associated with it.'),
        'type': 'string',
        'string1': 'NSFileProtectionNone',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['storage-2'],
    },
    {
        'desc': 'SFAntiPiracy Jailbreak checks found',
        'type': 'string',
        'string1': 'SFAntiPiracy.h',
        'string2': 'SFAntiPiracy',
        'string3': 'isJailbroken',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-1'],
    },
    {
        'desc': 'SFAntiPiracy Piracy checks found',
        'type': 'string',
        'string1': 'SFAntiPiracy.h',
        'string2': 'SFAntiPiracy',
        'string3': 'isPirated',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-3'],
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': 'string',
        'string1': 'CommonDigest.h',
        'string2': 'CC_MD5',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'SHA1 is a weak hash known to have hash collisions.',
        'type': 'string',
        'string1': 'CommonDigest.h',
        'string2': 'CC_SHA1',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': ('The App uses ECB mode in Cryptographic encryption algorithm.'
                 ' ECB mode is known to be weak as it results in the same'
                 ' ciphertext for identical blocks of plaintext.'),
        'type': 'string',
        'string1': 'kCCOptionECBMode',
        'string2': 'kCCAlgorithmAES',
        'level': 'high',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-3'],
    },
    {
        'desc': 'The App has ant-debugger code using ptrace() ',
        'type': 'string',
        'string1': 'ptrace_ptr',
        'string2': 'PT_DENY_ATTACH',
        'level': 'info',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-2'],
    },
    {
        'desc': 'This App has anti-debugger code using Mach Exception Ports.',
        'type': 'string',
        'string1': 'mach/mach_init.h',
        'string_or1': 'MACH_PORT_VALID',
        'string_or2': 'mach_task_self()',
        'level': 'info',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-2'],
    },
    {
        'desc': ('This App copies data to clipboard. Sensitive data should'
                 ' not be copied to clipboard as other applications'
                 ' can access it.'),
        'type': 'string',
        'string1': 'UITextField',
        'string_or1': '@select(cut:)',
        'string_or2': '@select(copy:)',
        'level': 'info',
        'match': 'string_and_or',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-10'],
    },
    {
        'desc': ('App uses Realm Database. '
                 'Sensitive Information should be encrypted.'),
        'type': 'string',
        'string1': '[realm transactionWithBlock:',
        'level': 'info',
        'match': 'single_string',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
]
