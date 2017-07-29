"""
Rule Format

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
   g. string_and_or -  if (string1 in input) and ((string2 in input) or (string3 in input))
   h. string_or_and - if (string1 in input) or ((string2 in input) and (string3 in input))

4. input_case
   a. upper
   b. lower
   c. exact

5. others
   a. string<no> - string1, string2, string3, string_or1, string_and1
   b. regex<no> - regex1, regex2, regex3

"""
CODE_APIS = [
    {
        'desc': 'Network Calls',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'NSURL|CFStream|NSStream',
        'input_case': 'exact'
    },
    {
        'desc': 'Local File I/O Operations.',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'Keychain|kSecAttrAccessibleWhenUnlocked|' +
                  r'kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|' +
                  r'SecItemUpdate|NSDataWritingFileProtectionComplete',
        'input_case': 'exact'
    },
    {
        'desc': 'WebView Component',
        'type': 'regex',
        'match': 'single_regex',
        'regex1': r'WebView|UIWebView',
        'input_case': 'exact'
    },
]
