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

from StaticAnalyzer.views.ios import common_rules

SWIFT_RULES = common_rules.COMMON_RULES + [
    {
        'desc': ('The App logs information. '
                 'Sensitive information should never be logged.'),
        'type': 'regex',
        'regex1': r'(print|NSLog|os_log|OSLog|os_signpost)\(.*\)',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': 'CWE-532',
        'owasp': '',
    },
    {
        'desc': 'SHA1 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'(?i)SHA1\(',
        'regex2': r'CC_SHA1\(',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327',
        'owasp': 'M5: Insufficient Cryptography',
    },
    {
        'desc': 'MD2 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'(?i)MD2\(',
        'regex2': r'CC_MD2\(',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327',
        'owasp': 'M5: Insufficient Cryptography',
    },
    {
        'desc': 'MD4 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'(?i)MD4\(',
        'regex2': r'CC_MD4\(',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327',
        'owasp': 'M5: Insufficient Cryptography',
    },
    {
        'desc': 'MD5 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'(?i)MD5\(',
        'regex2': r'CC_MD5\(',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327',
        'owasp': 'M5: Insufficient Cryptography',
    },
    {
        'desc': 'MD6 is a weak hash known to have hash collisions.',
        'type': 'regex',
        'regex1': r'(?i)MD6\(',
        'regex2': r'CC_MD6\(',
        'level': 'high',
        'match': 'regex_or',
        'input_case': 'exact',
        'cvss': 5.9,
        'cwe': 'CWE-327',
        'owasp': 'M5: Insufficient Cryptography',
    },
    {
        'desc': 'This App may have custom keyboards disabled.',
        'type': 'regex',
        'regex1': r'extensionPointIdentifier == .*\.keyboard',
        'level': 'good',
        'match': 'regex',
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': 'MSTG-PLATFORM-11',
    },
    {
        'desc': ('Keyboard cache should be disabled for all '
                 'sensitve data inputs.'),
        'type': 'regex',
        'regex1': r'.autocorrectionType = .no',
        'level': 'good',
        'match': 'regex',
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': 'MSTG-STORAGE-5',
    },
    {
        'desc': ('It is recommended to use WKWebView instead '
                 'of SFSafariViewController or UIViewView.'),
        'type': 'regex',
        'regex1': r'UIViewView|SFSafariViewController',
        'level': 'warning',
        'match': 'regex',
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': 'MSTG-PLATFORM-5',
    },
    {
        'desc': 'This App may have Reverse enginering detection capabilities.',
        'type': 'string',
        'string1': '\"FridaGadget\"',
        'string2': '\"cynject\"',
        'string3': '\"libcycript\"',
        'string4': '\"/usr/sbin/frida-server\"',
        'level': 'good',
        'match': 'string_and',
        'input_case': 'exact',
        'cvss': 0.0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': 'MSTG-RESILIENCE-4',
    },
]
