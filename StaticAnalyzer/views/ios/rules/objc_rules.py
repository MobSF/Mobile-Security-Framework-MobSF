# -*- coding: utf_8 -*-
"""iOS Source Code Analysis Objective C Rules."""

from StaticAnalyzer.views.ios.rules import common_rules
from StaticAnalyzer.views.sast_core.matchers import (
    InputCase,
    Level,
    SingleRegex,
    SingleString,
    StringAnd,
    StringAndOr,
)
from StaticAnalyzer.views.sast_core.standards import (
    CWE,
    OWASP,
    OWASP_MSTG,
)

OBJC_RULES = common_rules.COMMON_RULES + [
    {
        'desc': ('The App may contain banned API(s). '
                 'These API(s) are insecure and must not be used.'),
        'type': SingleRegex.__name__,
        'match': (r'strcpy|memcpy|strcat|strncat|'
                  r'strncpy|sprintf|vsprintf|gets'),
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 2.2,
        'cwe': CWE['CWE-676'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['code-8'],
    },
    {
        'desc': ('App allows self signed or invalid '
                 'SSL certificates. App is vulnerable to MITM attacks.'),
        'type': SingleRegex.__name__,
        'match': (r'canAuthenticateAgainstProtectionSpace|'
                  r'continueWithoutCredentialForAuthenticationChallenge|'
                  r'kCFStreamSSLAllowsExpiredCertificates|'
                  r'kCFStreamSSLAllowsAnyRoot|'
                  r'kCFStreamSSLAllowsExpiredRoots|'
                  r'validatesSecureCertificate\s*=\s*(no|NO)|'
                  r'allowInvalidCertificates\s*=\s*(YES|yes)'),
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 7.4,
        'cwe': CWE['CWE-295'],
        'owasp': OWASP['m3'],
        'owasp-mstg': OWASP_MSTG['network-3'],
    },
    {
        'desc': ('UIWebView in App ignore SSL errors and accept'
                 ' any SSL Certificate. App is vulnerable to MITM attacks.'),
        'type': SingleRegex.__name__,
        'match': (r'setAllowsAnyHTTPSCertificate:\s*YES|'
                  r'allowsAnyHTTPSCertificateForHost|'
                  r'loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)'),
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 7.4,
        'cwe': CWE['CWE-295'],
        'owasp': OWASP['m3'],
        'owasp-mstg': OWASP_MSTG['network-3'],
    },
    {
        'desc': ('The App logs information. '
                 'Sensitive information should never be logged.'),
        'type': SingleRegex.__name__,
        'match': r'NSLog|NSAssert|fprintf|fprintf|Logging',
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 7.5,
        'cwe': CWE['CWE-532'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-3'],
    },
    {
        'desc': ('This app listens to Clipboard changes. '
                 'Some malwares also listen to Clipboard changes.'),
        'type': SingleRegex.__name__,
        'match': (r'UIPasteboardChangedNotification|'
                  r'generalPasteboard\]\.string'),
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['platform-4'],
    },
    {
        'desc': ('Untrusted user input to "NSTemporaryDirectory()"'
                 ' will result in path traversal vulnerability.'),
        'type': SingleString.__name__,
        'match': 'NSTemporaryDirectory(),',
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 7.5,
        'cwe': CWE['CWE-22'],
        'owasp': OWASP['m10'],
        'owasp-mstg': OWASP_MSTG['platform-2'],
    },
    {
        'desc': ('File is stored in an encrypted format on '
                 'disk and cannot be read from or written to '
                 'while the device is locked or booting.'),
        'type': SingleString.__name__,
        'match': 'NSFileProtectionComplete',
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('File is stored in an encrypted format '
                 'on disk after it is closed.'),
        'type': SingleString.__name__,
        'match': 'NSFileProtectionCompleteUnlessOpen',
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('File is stored in an encrypted format '
                 'on disk and cannot be accessed until after '
                 'the device has booted.'),
        'type': SingleString.__name__,
        'match': (
            'NSFileProtectionComplete'
            'UntilFirstUserAuthentication'),
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('The file has no special protections '
                 'associated with it.'),
        'type': SingleString.__name__,
        'match': 'NSFileProtectionNone',
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 4.3,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['storage-2'],
    },
    {
        'desc': 'SFAntiPiracy Jailbreak checks found',
        'type': StringAnd.__name__,
        'match': ['SFAntiPiracy.h', 'SFAntiPiracy', 'isJailbroken'],
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-1'],
    },
    {
        'desc': 'SFAntiPiracy Piracy checks found',
        'type': StringAnd.__name__,
        'match': ['SFAntiPiracy.h', 'SFAntiPiracy', 'isPirated'],
        'level': Level.good,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-3'],
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': StringAnd.__name__,
        'match': ['CommonDigest.h', 'CC_MD5'],
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 7.4,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'SHA1 is a weak hash known to have hash collisions.',
        'type': StringAnd.__name__,
        'match': ['CommonDigest.h', 'CC_SHA1'],
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': ('The App uses ECB mode in Cryptographic encryption algorithm.'
                 ' ECB mode is known to be weak as it results in the same'
                 ' ciphertext for identical blocks of plaintext.'),
        'type': StringAnd.__name__,
        'match': ['kCCOptionECBMode', 'kCCAlgorithmAES'],
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-3'],
    },
    {
        'desc': 'The App has anti-debugger code using ptrace() ',
        'type': StringAnd.__name__,
        'match': ['ptrace_ptr', 'PT_DENY_ATTACH'],
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-2'],
    },
    {
        'desc': 'This App has anti-debugger code using Mach Exception Ports.',
        'type': StringAndOr.__name__,
        'match': ['mach/mach_init.h', ['MACH_PORT_VALID', 'mach_task_self()']],
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-2'],
    },
    {
        'desc': ('This App copies data to clipboard. Sensitive data should'
                 ' not be copied to clipboard as other applications'
                 ' can access it.'),
        'type': StringAndOr.__name__,
        'match': ['UITextField', ['@select(cut:)', '@select(copy:)']],
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-10'],
    },
    {
        'desc': ('App uses Realm Database. '
                 'Sensitive Information should be encrypted.'),
        'type': SingleString.__name__,
        'match': '[realm transactionWithBlock:',
        'level': Level.info,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
]
