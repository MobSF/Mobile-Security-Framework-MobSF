# -*- coding: utf_8 -*-
"""iOS Source Code Analysis API Rules."""

from StaticAnalyzer.views.sast_core.matchers import (
    InputCase,
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
