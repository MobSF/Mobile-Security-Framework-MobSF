"""
This file contains common iOS security rules used in source code analysis.

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
    InputCase,
    Level,
    Match,
    MatchType,
)

COMMON_RULES = [
    {
        'desc': 'IP Address disclosure',
        'type': MatchType.regex,
        'regex1': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'level': Level.warning,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 4.3,
        'cwe': CWE['CWE-200'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-2'],
    },
    {
        'desc': ('Files may contain hardcoded sensitive'
                 ' informations like usernames, passwords, keys etc.'),
        'type': MatchType.regex,
        'regex1': (r'(password\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(pass\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(username\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(secret\s*=\s*[\'|\"].+[\'|\"]\s{0,5})|'
                   r'(key\s*=\s*[\'|\"].+[\'|\"]\s{0,5})'),
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.lower,
        'cvss': 7.4,
        'cwe': CWE['CWE-312'],
        'owasp': OWASP['m9'],
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('App uses SQLite Database. '
                 'Sensitive Information should be encrypted.'),
        'type': MatchType.string,
        'string1': 'sqlite3_exec',
        'string2': 'sqlite3_finalize',
        'level': Level.info,
        'match': Match.string_or,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-14'],
    },
    {
        'desc': ('User input in "loadHTMLString" '
                 'will result in JavaScript Injection.'),
        'type': MatchType.string,
        'string1': 'loadHTMLString',
        'string2': 'webView',
        'level': Level.warning,
        'match': Match.string_and,
        'input_case': InputCase.exact,
        'cvss': 8.8,
        'cwe': CWE['CWE-95'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['platform-5'],
    },
    {
        'desc': 'This App may have Jailbreak detection capabilities.',
        'type': MatchType.string,
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
        'string11': ('/Library/MobileSubstrate/DynamicLibraries/'
                     'LiveClock.plist'),
        'string12': '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
        'string13': ('/System/Library/LaunchDaemons/'
                     'com.saurik.Cydia.Startup.plist'),
        'string14': '/etc/ssh/sshd_config',
        'string15': '/private/var/tmp/cydia.log',
        'string16': '/usr/libexec/ssh-keysign',
        'string17': '/Applications/MxTube.app',
        'string18': '/Applications/RockApp.app',
        'string19': '/Applications/WinterBoard.app',
        'string20': '/Applications/blackra1n.app',
        'string21': '/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
        'string22': '/private/var/lib/apt',
        'string23': '/private/var/lib/cydia',
        'string24': '/private/var/mobile/Library/SBSettings/Themes',
        'string25': '/private/var/stash',
        'string26': '/usr/bin/sshd',
        'string27': '/usr/libexec/sftp-server',
        'string28': '/var/cache/apt',
        'string29': '/var/lib/apt',
        'string30': '/usr/sbin/frida-server',
        'string31': '/usr/bin/cycript',
        'string32': '/usr/local/bin/cycript',
        'string33': '/usr/lib/libcycript.dylib',
        'string34': 'frida-server',
        'string35': '/etc/apt/sources.list.d/electra.list',
        'string36': '/etc/apt/sources.list.d/sileo.sources',
        'string37': '/.bootstrapped_electra',
        'string38': '/usr/lib/libjailbreak.dylib',
        'string39': '/jb/lzma',
        'string40': '/.cydia_no_stash',
        'string41': '/.installed_unc0ver',
        'string42': '/jb/offsets.plist',
        'string43': '/usr/share/jailbreak/injectme.plist',
        'string44': '/Library/MobileSubstrate/MobileSubstrate.dylib',
        'string45': '/usr/libexec/cydia/firmware.sh',
        'string46': '/private/var/cache/apt/',
        'string47': '/Library/MobileSubstrate/CydiaSubstrate.dylib',
        'level': Level.good,
        'match': Match.string_or,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['resilience-1'],
    },
]
