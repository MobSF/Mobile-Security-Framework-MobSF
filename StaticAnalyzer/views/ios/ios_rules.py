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
   g. string_and_or -  if (string1 in input) and ((string_or1 in input) or (string_or2 in input))
   h. string_or_and - if (string1 in input) or ((string_and1 in input) and (string_and2 in input))

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
CODE_RULES = [
    {
        'desc': 'The App may contain banned API(s). These API(s) are insecure and must not be used.',
        'type': 'regex',
        'regex1': r'strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'App allows self signed or invalid SSL certificates. App is vulnerable to MITM attacks.',
        'type': 'regex',
        'regex1': r'canAuthenticateAgainstProtectionSpace|' +
                  r'continueWithoutCredentialForAuthenticationChallenge|' +
                  r'kCFStreamSSLAllowsExpiredCertificates|' +
                  r'kCFStreamSSLAllowsAnyRoot|' +
                  r'kCFStreamSSLAllowsExpiredRoots|' +
                  r'allowInvalidCertificates\s*=\s*(YES|yes)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'UIWebView in App ignore SSL errors and accept any SSL Certificate. App is vulnerable to MITM attacks.',
        'type': 'regex',
        'regex1': r'setAllowsAnyHTTPSCertificate:\s*YES|' +
                  r'allowsAnyHTTPSCertificateForHost|' +
                  r'loadingUnvalidatedHTTPSPage\s*=\s*(YES|yes)',
        'level': 'high',
        'match': 'single_regex',
        'input_case': 'exact'
    },
    {
        'desc': 'The App logs information. Sensitive information should never be logged.',
        'type': 'string',
        'string1': 'NSLog',
        'level': 'info',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'App uses SQLite Database. Sensitive Information should be encrypted.',
        'type': 'string',
        'string1': 'sqlite3_exec',
        'level': 'info',
        'match': 'single_string',
        'input_case': 'exact'
    },
    {
        'desc': 'Untrusted user input to "NSTemporaryDirectory()" will result in path traversal vulnerability.',
        'type': 'string',
        'string1': 'NSTemporaryDirectory(),',
        'level': 'warning',
        'match': 'single_string',
        'input_case': 'exact'
    },
]
