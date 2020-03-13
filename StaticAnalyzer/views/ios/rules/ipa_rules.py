"""
This file contains IPA security rules used in binary analysis.

Rule Format.

1. desc - Description of the findings

2. detailed_desc - Detailed description. If a {} placeholder is used, captures
                   will be inserted to detailed description on rule match.
                   formatting is only supported with regex

3. type
   a. string
   b. regex

4. match
   a. single_regex - if re.findall(regex1, input)
   b. single_string - if string1 in input

5. level
   a. high
   b. warning
   c. info
   d. good

6. input_case
   a. upper
   b. lower
   c. exact

7. others
   a. string1
   b. regex2

8. conditional - Conditional rules to match the opposite case.
                 The opposite case must contain a dict of desc,
                 detailed_desc, level, cvss, cwe, owasp, and,
                 owasp-mstg
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

IPA_RULES = [
    {
        'desc': 'Binary make use of insecure API(s)',
        'detailed_desc': (
            'The binary may contain'
            ' the following insecure API(s) {}.'),
        'type': MatchType.regex,
        'regex1': (
            rb'\b_alloca\b|\b_gets\b|\b_memcpy\b|\b_printf\b|\b_scanf\b|'
            rb'\b_sprintf\b|\b_sscanf\b|\b_strcat\b|'
            rb'\bStrCat\b|\b_strcpy\b|\bStrCpy\b|\b_strlen\b|\bStrLen\b|'
            rb'\b_strncat\b|\bStrNCat\b|\b_strncpy\b|'
            rb'\bStrNCpy\b|\b_strtok\b|\b_swprintf\b|\b_vsnprintf\b|'
            rb'\b_vsprintf\b|\b_vswprintf\b|\b_wcscat\b|\b_wcscpy\b|'
            rb'\b_wcslen\b|\b_wcsncat\b|\b_wcsncpy\b|\b_wcstok\b|\b_wmemcpy\b|'
            rb'\b_fopen\b|\b_chmod\b|\b_chown\b|\b_stat\b|\b_mktemp\b'),
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 6,
        'cwe': CWE['CWE-676'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['code-8'],
    },
    {
        'desc': 'Binary make use of some weak Crypto API(s)',
        'detailed_desc': (
            'The binary may use the'
            ' following weak crypto API(s) {}.'),
        'type': MatchType.regex,
        'regex1': (
            rb'\bkCCAlgorithmDES\b|'
            rb'\bkCCAlgorithm3DES\b|'
            rb'\bkCCAlgorithmRC2\b|'
            rb'\bkCCAlgorithmRC4\b|'
            rb'\bkCCOptionECBMode\b|'
            rb'\bkCCOptionCBCMode\b'),
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 3,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-3'],
    },
    {
        'desc': 'Binary make use of the following Crypto API(s)',
        'detailed_desc': (
            'The binary may use '
            'the following crypto API(s) {}.'),
        'type': MatchType.regex,
        'regex1': (
            rb'\bCCKeyDerivationPBKDF\b|\bCCCryptorCreate\b|\b'
            rb'CCCryptorCreateFromData\b|\b'
            rb'CCCryptorRelease\b|\bCCCryptorUpdate\b|\bCCCryptorFinal\b|\b'
            rb'CCCryptorGetOutputLength\b|\bCCCryptorReset\b|\b'
            rb'CCCryptorRef\b|\bkCCEncrypt\b|\b'
            rb'kCCDecrypt\b|\bkCCAlgorithmAES128\b|\bkCCKeySizeAES128\b|\b'
            rb'kCCKeySizeAES192\b|\b'
            rb'kCCKeySizeAES256\b|\bkCCAlgorithmCAST\b|\b'
            rb'SecCertificateGetTypeID\b|\b'
            rb'SecIdentityGetTypeID\b|\bSecKeyGetTypeID\b|\b'
            rb'SecPolicyGetTypeID\b|\b'
            rb'SecTrustGetTypeID\b|\bSecCertificateCreateWithData\b|\b'
            rb'SecCertificateCreateFromData\b|\bSecCertificateCopyData\b|\b'
            rb'SecCertificateAddToKeychain\b|\bSecCertificateGetData\b|\b'
            rb'SecCertificateCopySubjectSummary\b|\b'
            rb'SecIdentityCopyCertificate\b|\b'
            rb'SecIdentityCopyPrivateKey\b|\bSecPKCS12Import\b|\b'
            rb'SecKeyGeneratePair\b|\b'
            rb'SecKeyEncrypt\b|\bSecKeyDecrypt\b|\bSecKeyRawSign\b|\b'
            rb'SecKeyRawVerify\b|\b'
            rb'SecKeyGetBlockSize\b|\bSecPolicyCopyProperties\b|\b'
            rb'SecPolicyCreateBasicX509\b|\bSecPolicyCreateSSL\b|\b'
            rb'SecTrustCopyCustomAnchorCertificates\b|\b'
            rb'SecTrustCopyExceptions\b|\b'
            rb'SecTrustCopyProperties\b|\bSecTrustCopyPolicies\b|\b'
            rb'SecTrustCopyPublicKey\b|\bSecTrustCreateWithCertificates\b|\b'
            rb'SecTrustEvaluate\b|\bSecTrustEvaluateAsync\b|\b'
            rb'SecTrustGetCertificateCount\b|\b'
            rb'SecTrustGetCertificateAtIndex\b|\b'
            rb'SecTrustGetTrustResult\b|\bSecTrustGetVerifyTime\b|\b'
            rb'SecTrustSetAnchorCertificates\b|\b'
            rb'SecTrustSetAnchorCertificatesOnly\b|\b'
            rb'SecTrustSetExceptions\b|\bSecTrustSetPolicies\b|\b'
            rb'SecTrustSetVerifyDate\b|\bSecCertificateRef\b|\b'
            rb'SecIdentityRef\b|\bSecKeyRef\b|\bSecPolicyRef\b|\b'
            rb'SecTrustRef\b'),
        'level': Level.info,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': '',
    },
    {
        'desc': 'Binary make use of some weak Hashing API(s)',
        'detailed_desc': (
            'The binary may use the '
            'following weak hash API(s) {}.'),
        'type': MatchType.regex,
        'regex1': (
            rb'\bCC_MD2_Init\b|\bCC_MD2_Update\b|\b'
            rb'CC_MD2_Final\b|\bCC_MD2\b|\bMD2_Init\b|\b'
            rb'MD2_Update\b|\bMD2_Final\b|\bCC_MD4_Init\b|\b'
            rb'CC_MD4_Update\b|\bCC_MD4_Final\b|\b'
            rb'CC_MD4\b|\bMD4_Init\b|\bMD4_Update\b|\b'
            rb'MD4_Final\b|\bCC_MD5_Init\b|\bCC_MD5_Update'
            rb'\b|\bCC_MD5_Final\b|\bCC_MD5\b|\bMD5_Init\b|\b'
            rb'MD5_Update\b|\bMD5_Final\b|\bMD5Init\b|\b'
            rb'MD5Update\b|\bMD5Final\b|\bCC_SHA1_Init\b|\b'
            rb'CC_SHA1_Update\b|\b'
            rb'CC_SHA1_Final\b|\bCC_SHA1\b|\bSHA1_Init\b|\b'
            rb'SHA1_Update\b|\bSHA1_Final\b'),
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 3,
        'cwe': CWE['CWE-327'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-4'],
    },
    {
        'desc': 'Binary make use of the following Hash API(s)',
        'detailed_desc': (
            'The binary may use the'
            ' following hash API(s) {}.'),
        'type': MatchType.regex,
        'regex1': (
            rb'\bCC_SHA224_Init\b|\bCC_SHA224_Update\b|\b'
            rb'CC_SHA224_Final\b|\bCC_SHA224\b|\b'
            rb'SHA224_Init\b|\bSHA224_Update\b|\b'
            rb'SHA224_Final\b|\bCC_SHA256_Init\b|\b'
            rb'CC_SHA256_Update\b|\bCC_SHA256_Final\b|\b'
            rb'CC_SHA256\b|\bSHA256_Init\b|\b'
            rb'SHA256_Update\b|\bSHA256_Final\b|\b'
            rb'CC_SHA384_Init\b|\bCC_SHA384_Update\b|\b'
            rb'CC_SHA384_Final\b|\bCC_SHA384\b|\b'
            rb'SHA384_Init\b|\bSHA384_Update\b|\b'
            rb'SHA384_Final\b|\bCC_SHA512_Init\b|\b'
            rb'CC_SHA512_Update\b|\bCC_SHA512_Final\b|\b'
            rb'CC_SHA512\b|\bSHA512_Init\b|\b'
            rb'SHA512_Update\b|\bSHA512_Final\b'),
        'level': Level.info,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': '',
    },
    {
        'desc': 'Binary make use of the insecure Random function(s)',
        'detailed_desc': (
            'The binary may use the following '
            'insecure Random function(s) {}.'),
        'type': MatchType.regex,
        'regex1': rb'\b_srand\b|\b_random\b',
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 3,
        'cwe': CWE['CWE-330'],
        'owasp': OWASP['m5'],
        'owasp-mstg': OWASP_MSTG['crypto-6'],
    },
    {
        'desc': 'Binary make use of Logging function',
        'detailed_desc': (
            'The binary may use {}'
            ' function for logging.'),
        'type': MatchType.regex,
        'regex1': rb'\b_NSLog\b',
        'level': Level.info,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 7.5,
        'cwe': CWE['CWE-532'],
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['storage-3'],
    },
    {
        'desc': 'Binary make use of malloc function',
        'detailed_desc': (
            'The binary may use {}'
            ' function instead of calloc.'),
        'type': MatchType.regex,
        'regex1': rb'\b_malloc\b',
        'level': Level.high,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 2,
        'cwe': CWE['CWE-789'],
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['code-8'],
    },
    {
        'desc': 'Binary calls ptrace() function for anti-debugging.',
        'detailed_desc': (
            'The binary may use ptrace() function. It can be'
            ' used to detect and prevent debuggers.'
            ' Ptrace is not a public API and apps that'
            ' use non-public APIs will be rejected'
            ' from AppStore.'),
        'type': MatchType.regex,
        'regex1': rb'\b_ptrace\b',
        'level': Level.warning,
        'match': Match.single_regex,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': OWASP['m7'],
        'owasp-mstg': OWASP_MSTG['resilience-2'],
    },
    {
        'desc': 'fPIE -pie flag is Found',
        'detailed_desc': (
            'App is compiled with Position Independent '
            'Executable (PIE) flag. This enables Address'
            ' Space Layout Randomization (ASLR), a memory'
            ' protection mechanism for'
            ' exploit mitigation.'),
        'type': MatchType.string,
        'string1': b'PIE',
        'level': Level.good,
        'match': Match.single_string,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-9'],
        'conditional': {
            'desc': 'fPIE -pie flag is Found',
            'detailed_desc': (
                'with Position Independent Executable (PIE) '
                'flag. So Address Space Layout Randomization '
                '(ASLR) is missing. ASLR is a memory '
                'protection mechanism for '
                'exploit mitigation.'),
            'level': Level.high,
            'cvss': 2,
            'cwe': CWE['CWE-119'],
            'owasp': OWASP['m1'],
            'owasp-mstg': OWASP_MSTG['code-9'],
        },
    },
    {
        'desc': 'fstack-protector-all flag is Found',
        'detailed_desc': (
            'App is compiled with Stack Smashing Protector'
            ' (SSP) flag and is having protection against'
            ' Stack Overflows/Stack Smashing Attacks.'),
        'type': MatchType.string,
        'string1': b'stack_chk_guard',
        'level': Level.good,
        'match': Match.single_string,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-9'],
        'conditional': {
            'desc': 'fstack-protector-all flag is not Found',
            'detailed_desc': (
                'App is not compiled with Stack Smashing '
                'Protector (SSP) flag. It is vulnerable to'
                'Stack Overflows/Stack Smashing Attacks.'),
            'level': Level.high,
            'cvss': 2,
            'cwe': CWE['CWE-119'],
            'owasp': OWASP['m1'],
            'owasp-mstg': OWASP_MSTG['code-9'],
        },
    },
    {
        'desc': 'fobjc-arc flag is Found',
        'detailed_desc': (
            'App is compiled with Automatic Reference '
            'Counting (ARC) flag. ARC is a compiler '
            'feature that provides automatic memory '
            'management of Objective-C objects and is an '
            'exploit mitigation mechanism against memory '
            'corruption vulnerabilities.'),
        'type': MatchType.string,
        'string1': b'_objc_release',
        'level': Level.good,
        'match': Match.single_string,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-9'],
        'conditional': {
            'desc': 'fobjc-arc flag is not Found',
            'detailed_desc': (
                'App is not compiled with Automatic Reference '
                'Counting (ARC) flag. ARC is a compiler '
                'feature that provides automatic memory '
                'management of Objective-C objects and '
                'protects from memory corruption '
                'vulnerabilities.'),
            'level': Level.high,
            'cvss': 2,
            'cwe': CWE['CWE-119'],
            'owasp': OWASP['m1'],
            'owasp-mstg': OWASP_MSTG['code-9'],
        },
    },
    {
        'desc': 'Binary uses WebView Component.',
        'detailed_desc': 'The binary may use UIWebView Component.',
        'type': MatchType.string,
        'string1': b'UIWebView',
        'level': Level.info,
        'match': Match.single_string,
        'input_case': InputCase.exact,
        'cvss': 0,
        'cwe': '',
        'owasp': '',
        'owasp-mstg': OWASP_MSTG['code-9'],
    },
]
