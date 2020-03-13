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
    Match,
    MatchType,
)

CODE_APIS = [
    {
        'desc': 'Network Calls',
        'type': MatchType.regex,
        'match': Match.single_regex,
        'regex1': r'URLSession|CFStream|NSStream',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Keychain Access.',
        'type': MatchType.regex,
        'match': Match.single_regex,
        'regex1': (r'Keychain|SecItemAdd|SecItemUpdate'
                   r'SecItemCopy| kSecAttr'),
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Component',
        'type': MatchType.regex,
        'match': Match.single_regex,
        'regex1': r'UIWebView|WKWebView',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'SFSafariViewController Component',
        'type': MatchType.regex,
        'match': Match.single_regex,
        'regex1': r'SFSafariViewController',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Encryption API',
        'type': MatchType.regex,
        'match': Match.single_regex,
        'regex1': r'CommonCrypto|CryptoKit',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Load Request',
        'type': MatchType.string,
        'match': Match.string_and,
        'string1': 'loadRequest',
        'string2': 'webView',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'WebView Load HTML String',
        'type': MatchType.string,
        'match': Match.string_and,
        'string1': 'loadHTMLString',
        'string2': 'webView',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Cookie Storage',
        'type': MatchType.regex,
        'match': Match.regex_and,
        'regex1': r'HTTPCookieStorage',
        'regex2': r'shared|sharedHTTPCookieStorage',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UIPasteboard',
        'type': MatchType.string,
        'match': Match.single_string,
        'string1': 'UIPasteboard',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UserDefaults',
        'type': MatchType.string,
        'match': Match.single_string,
        'string1': 'UserDefaults',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'CoreData',
        'type': MatchType.string,
        'match': Match.single_string,
        'string1': 'CoreData',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'Local Authentication Framework',
        'type': MatchType.string,
        'match': Match.single_string,
        'string1': 'LAContext',
        'input_case': InputCase.exact,
    },
    {
        'desc': 'UIActivity Sharing',
        'type': MatchType.string,
        'match': Match.single_string,
        'string1': 'UIActivity',
        'input_case': InputCase.exact,
    },
]
