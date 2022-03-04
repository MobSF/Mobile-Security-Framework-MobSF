# -*- coding: utf_8 -*-
"""IPA Binary Analysis Rules."""
from libsast.standards import get_standards


STDS = get_standards()
IPA_RULES = [
    {
        'description': 'Binary makes use of insecure API(s)',
        'detailed_desc': (
            'The binary may contain the following insecure API(s) {}'),
        'type': 'Regex',
        'pattern': (
            rb'\b_alloca\n\b|\b_gets\n\b|\b_memcpy\n\b|\b_printf\n\b|'
            rb'\b_scanf\n\b|\b_sprintf\n\b|\b_sscanf\n\b|\b_strcat\n\b|'
            rb'\bStrCat\n\b|\b_strcpy\n\b|\bStrCpy\n\b|\b_strlen\n\b|'
            rb'\bStrLen\n\b|\b_strncat\n\b|\bStrNCat\n\b|\b_strncpy\n\b|'
            rb'\bStrNCpy\n\b|\b_strtok\n\b|\b_swprintf\n\b|\b_vsnprintf\n\b|'
            rb'\b_vsprintf\b|\b_vswprintf\b|\b_wcscat\b|\b_wcscpy\b|'
            rb'\b_wcslen\n\b|\b_wcsncat\n\b|\b_wcsncpy\n\b|\b_wcstok\n\b|'
            rb'\b_wmemcpy\n\b|\b_fopen\n\b|\b_chmod\n\b|\b_chown\n\b|'
            rb'\b_stat\n\b|\b_mktemp\n\b'),
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 6,
        'cwe': STDS['cwe']['cwe-676'],
        'owasp-mobile': STDS['owasp-mobile']['m7'],
        'masvs': STDS['masvs']['code-8'],
    },
    {
        'description': 'Binary makes use of some weak Crypto API(s)',
        'detailed_desc': (
            'The binary may use the following weak crypto API(s) {}'),
        'type': 'Regex',
        'pattern': (
            rb'\bkCCAlgorithmDES\b|'
            rb'\bkCCAlgorithm3DES\b|'
            rb'\bkCCAlgorithmRC2\b|'
            rb'\bkCCAlgorithmRC4\b|'
            rb'\bkCCOptionECBMode\b|'
            rb'\bkCCOptionCBCMode\b'),
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 3,
        'cwe': STDS['cwe']['cwe-327'],
        'owasp-mobile': STDS['owasp-mobile']['m5'],
        'masvs': STDS['masvs']['crypto-3'],
    },
    {
        'description': 'Binary makes use of the following Crypto API(s)',
        'detailed_desc': (
            'The binary may use the following crypto API(s) {}'),
        'type': 'Regex',
        'pattern': (
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
        'severity': 'info',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp-mobile': '',
        'masvs': '',
    },
    {
        'description': 'Binary makes use of some weak Hashing API(s)',
        'detailed_desc': (
            'The binary may use the following weak hash API(s) {}'),
        'type': 'Regex',
        'pattern': (
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
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 3,
        'cwe': STDS['cwe']['cwe-327'],
        'owasp-mobile': STDS['owasp-mobile']['m5'],
        'masvs': STDS['masvs']['crypto-4'],
    },
    {
        'description': 'Binary makes use of the following Hash API(s)',
        'detailed_desc': (
            'The binary may use the following hash API(s) {}'),
        'type': 'Regex',
        'pattern': (
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
        'severity': 'info',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp-mobile': '',
        'masvs': '',
    },
    {
        'description': 'Binary makes use of the insecure Random function(s)',
        'detailed_desc': (
            'The binary may use the following '
            'insecure Random function(s) {}'),
        'type': 'Regex',
        'pattern': rb'\b_srand\n\b|\b_random\n\b',
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 3,
        'cwe': STDS['cwe']['cwe-330'],
        'owasp-mobile': STDS['owasp-mobile']['m5'],
        'masvs': STDS['masvs']['crypto-6'],
    },
    {
        'description': 'Binary makes use of Logging function',
        'detailed_desc': (
            'The binary may use {} function for logging.'),
        'type': 'Regex',
        'pattern': rb'\b_NSLog\n\b',
        'severity': 'info',
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': STDS['cwe']['cwe-532'],
        'owasp-mobile': '',
        'masvs': STDS['masvs']['storage-3'],
    },
    {
        'description': 'Binary makes use of malloc function',
        'detailed_desc': (
            'The binary may use {} function instead of calloc'),
        'type': 'Regex',
        'pattern': rb'_malloc\n',
        'severity': 'high',
        'input_case': 'exact',
        'cvss': 2,
        'cwe': STDS['cwe']['cwe-789'],
        'owasp-mobile': STDS['owasp-mobile']['m7'],
        'masvs': STDS['masvs']['code-8'],
    },
    {
        'description': 'Binary calls ptrace() function for anti-debugging.',
        'detailed_desc': (
            'The binary may use ptrace() function. It can be'
            ' used to detect and prevent debuggers.'
            ' Ptrace is not a public API and apps that'
            ' use non-public APIs will be rejected'
            ' from AppStore.'),
        'type': 'Regex',
        'pattern': rb'\b_ptrace\b',
        'severity': 'warning',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp-mobile': STDS['owasp-mobile']['m7'],
        'masvs': STDS['masvs']['resilience-2'],
    },
    {
        'description': 'Binary uses WebView Component.',
        'detailed_desc': 'The binary may use UIWebView Component.',
        'type': 'Regex',
        'pattern': b'UIWebView',
        'severity': 'info',
        'input_case': 'exact',
        'cvss': 0,
        'cwe': '',
        'owasp-mobile': '',
        'masvs': STDS['masvs']['code-9'],
    },
]
