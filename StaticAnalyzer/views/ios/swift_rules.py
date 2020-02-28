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
        'regex1': r'print|NSLog|os_log|OSLog|os_signpost',
        'level': 'info',
        'match': 'single_regex',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': 'CWE-532',
        'owasp': '',
    },
]
