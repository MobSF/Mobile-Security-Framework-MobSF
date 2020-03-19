from StaticAnalyzer.views.standards import (
    CWE,
    OWASP,
    OWASP_MSTG,
)
from StaticAnalyzer.views.rules_properties import (
    InputCase,
    Level,
    Match,
    MatchType,
)

from StaticAnalyzer.views.match_strategy import single_regex 

SINGLE_REGEX = single_regex.__name__

RULES = [
    {
        'desc': ('Files may contain hardcoded sensitive '
                 'informations like usernames, passwords, keys etc.'),
        # 'type' : SINGLE_REGEX
        'type': Match.single_regex,
        'match': (r'(password\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(pass\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(username\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(secret\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(key\s*=\s*[\'|\"].+[\'|\"]\s{0,5})'),      
        'level': Level.high,
        'input_case': InputCase.lower,
        'cvss': 7.4,
        'cwe': CWE['CWE-312'],
        'owasp': OWASP['m9'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': 'The file is World Readable. Any App can read from the file',
        'type': Match.regex_or,
        'match': [r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE', r'openFileOutput\(\s*".+"\s*,\s*1\s*\)'],
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 4.0,
        'cwe': CWE['CWE-276'],
        'owasp': OWASP['m2'],
        'owasp-mstg': OWASP_MSTG['storage-2'],
    },
    {
        'desc': ('WebView load files from external storage. Files in external'
                 ' storage can be modified by any application.'),
        'type': Match.regex_and,
        'match': [r'\.loadUrl\(.*getExternalStorageDirectory\(', r'webkit\.WebView'],
        'level': Level.high,
        'input_case': InputCase.exact,
        'cvss': 5.0,
        'cwe': CWE['CWE-919'],
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-6'],
    },
    {
        'desc': ('Insecure WebView Implementation. Execution of user'
                 ' controlled code in WebView is a critical Security Hole.'),
        'type': Match.string_and,
        'match': ['setJavaScriptEnabled(true)', '.addJavascriptInterface('],
        'level': Level.warning,
        'input_case': InputCase.exact,
        'cvss': 8.8,
        'cwe': CWE['CWE-749'],
        'owasp': OWASP['m1'],
        'owasp-mstg': OWASP_MSTG['platform-7'],
    },

]