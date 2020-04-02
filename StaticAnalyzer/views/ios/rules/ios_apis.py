"""
This files contains rules that detects usage of API.

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
   g. string_and_or -  if (string1 in input) and ((string2 in input)
                       or (string3 in input))
   h. string_or_and - if (string1 in input) or ((string2 in input)
                      and (string3 in input))

4. input_case
   a. upper
   b. lower
   c. exact

5. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3

"""

from StaticAnalyzer.views.rules_properties import (
    InputCase,
)
from StaticAnalyzer.views.matchers import (
    RegexAnd,
    SingleRegex,
    SingleString,
    StringAnd,
)

CODE_APIS = [
    {
        'desc': 'Network Calls',
        'type': SingleRegex.__name__,
        'match': r'URLSession|CFStream|NSStream',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Keychain Access.',
        'type': SingleRegex.__name__,
        'match': (r'Keychain|SecItemAdd|SecItemUpdate'
                  r'SecItemCopy| kSecAttr'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Component',
        'type': SingleRegex.__name__,
        'match': r'UIWebView|WKWebView',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'SFSafariViewController Component',
        'type': SingleRegex.__name__,
        'match': r'SFSafariViewController',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Encryption API',
        'type': SingleRegex.__name__,
        'match': r'CommonCrypto|CryptoKit',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Load Request',
        'type': StringAnd.__name__,
        'match': ['loadRequest', 'webView'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Load HTML String',
        'type': StringAnd.__name__,
        'match': ['loadHTMLString', 'webView'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Cookie Storage',
        'type': RegexAnd.__name__,
        'match': [r'HTTPCookieStorage', r'shared|sharedHTTPCookieStorage'],
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UIPasteboard',
        'type': SingleString.__name__,
        'match': 'UIPasteboard',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UserDefaults',
        'type': SingleString.__name__,
        'match': 'UserDefaults',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'CoreData',
        'type': SingleString.__name__,
        'match': 'CoreData',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Local Authentication Framework',
        'type': SingleString.__name__,
        'match': 'LAContext',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UIActivity Sharing',
        'type': SingleString.__name__,
        'match': 'UIActivity',
        'input_case': InputCase.exact,
    },
]
