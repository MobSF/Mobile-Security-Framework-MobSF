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
from StaticAnalyzer.views.rules_properties import (
    Match,
    MatchType,
)
from StaticAnalyzer.views.ios import common_rules

SWIFT_RULES = common_rules.COMMON_RULES + [
    {
        'desc': ('The App logs information. '
                 'Sensitive information should never be logged.'),
        'type': MatchType.regex,
        'regex1': r'(print|NSLog|os_log|OSLog|os_signpost)\(.*\)',
        'level': 'info',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': CWE['CWE-532'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-3'],
    },
    {
        'desc': 'SHA1 is a weak hash known to have hash collisions.',
        'type': MatchType.regex,
        'regex1': r'(?i)SHA1\(',
        'regex2': r'CC_SHA1\(',
        'level': 'high',
        'match': Match.regex_or,
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'MD2 is a weak hash known to have hash collisions.',
        'type': MatchType.regex,
        'regex1': r'(?i)MD2\(',
        'regex2': r'CC_MD2\(',
        'level': 'high',
        'match': Match.regex_or,
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'MD4 is a weak hash known to have hash collisions.',
        'type': MatchType.regex,
        'regex1': r'(?i)MD4\(',
        'regex2': r'CC_MD4\(',
        'level': 'high',
        'match': Match.regex_or,
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': MatchType.regex,
        'regex1': r'(?i)MD5\(',
        'regex2': r'CC_MD5\(',
        'level': 'high',
        'match': Match.regex_or,
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'MD6 is a weak hash known to have hash collisions.',
        'type': MatchType.regex,
        'regex1': r'(?i)MD6\(',
        'regex2': r'CC_MD6\(',
        'level': 'high',
        'match': Match.regex_or,
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'This App may have custom keyboards disabled.',
        'type': MatchType.regex,
        'regex1': r'extensionPointIdentifier == .*\.keyboard',
        'level': 'good',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['platform-11'],
    },
    {
        'desc': ('Keyboard cache should be disabled for all '
                 'sensitve data inputs.'),
        'type': MatchType.regex,
        'regex1': r'.autocorrectionType = .no',
        'level': 'good',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-5'],
    },
    {
        'desc': ('It is recommended to use WKWebView instead '
                 'of SFSafariViewController or UIViewView.'),
        'type': MatchType.regex,
        'regex1': r'UIViewView|SFSafariViewController',
        'level': 'warning',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-5'],
    },
    {
        'desc': 'This App may have Reverse enginering detection capabilities.',
        'type': MatchType.string,
        'string1': '\"FridaGadget\"',
        'string2': '\"cynject\"',
        'string3': '\"libcycript\"',
        'string4': '\"/usr/sbin/frida-server\"',
        'level': 'good',
        'match': Match.string_and,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-4'],
    },
    {
        'desc': 'This App may have Emulator detection capabilities.',
        'type': MatchType.string,
        'string1': '\"SIMULATOR_DEVICE_NAME\"',
        'level': 'good',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-5'],
    },
    {
        'desc': ('Biometric authentication should be based '
                 'on Keychain, not based on bool.'),
        'type': MatchType.regex,
        'regex1': r'\.evaluatePolicy\(.deviceOwnerAuthentication',
        'level': 'warning',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['auth-8'],
    },
    {
        'desc': 'The file has no special protections associated with it.',
        'type': MatchType.regex,
        'regex1': r'(?i)\.noFileProtection',
        'level': 'high',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m2'],
        'owasp-mstg': OWASP_MSTG['storage-1'],
    },
    {
        'desc': ('This application uses UIPasteboard, improper use '
                 'of this class can lead to security issues.'),
        'type': MatchType.string,
        'string1': 'UIPasteboard',
        'level': 'warning',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-4'],
    },
    {
        'desc': 'Usage of generalPasteboard should be avoided.',
        'type': MatchType.string,
        'string1': 'UIPasteboard.generalPasteboard',
        'level': 'warning',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-4'],
    },
    {
        'desc': ('The app should not export sensitive functionality via '
                 'custom URL schemes, unless these '
                 'mechanisms are properly protected.'),
        'type': MatchType.string,
        'string1': 'CFBundleURLSchemes',
        'level': 'warning',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-3'],
    },
    {
        'desc': 'Some UI controls have secure text entry configured.',
        'type': MatchType.string,
        'string1': '.secureTextEntry = true',
        'level': 'good',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-5'],
    },
    {
        'desc': 'This App may have Certificate Pinning mechanizm.',
        'type': MatchType.string,
        'string1': 'PinnedCertificatesTrustEvaluator',
        'string2': 'TrustKit.initSharedInstance',
        'level': 'good',
        'match': Match.string_or,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': CWE['CWE-295'],
        'owasp': OWASP['m3'],
        'owasp-mstg': OWASP_MSTG['network-4'],
    },
    {
        'desc': ('App uses Realm Database. '
                 'Sensitive Information should be encrypted.'),
        'type': MatchType.string,
        'string1': 'realm.write',
        'level': 'info',
        'match': Match.single_string,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m2'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('App uses CoreData Database. '
                 'Sensitive Information should be encrypted.'),
        'type': MatchType.string,
        'string1': 'NSManagedObjectContext',
        'string2': '.save()',
        'level': 'info',
        'match': Match.string_and,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m2'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': 'Used Realm database has configured encryption.',
        'type': MatchType.string,
        'string1': 'Realm.Configuration(encryptionKey:',
        'string2': 'Realm(configuration:',
        'level': 'good',
        'match': Match.string_and,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': CWE['CWE-311'],
        'owasp': OWASP['m2'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': 'Copy feature may be disabled in some UI controls.',
        'type': MatchType.regex,
        'regex1': r'canPerformAction',
        'regex2': r'UIResponderStandardEditActions\.copy|\.copy',
        'level': 'info',
        'match': Match.regex_and,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': '',
    },
    {
        'desc': 'Opening App with URLs can lead to potencial security leaks.',
        'type': MatchType.regex,
        'regex1': r'func application\(.*open url: URL',
        'level': 'warning',
        'match': Match.single_regex,
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': CWE['CWE-939'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['platform-3'],
    },
]
