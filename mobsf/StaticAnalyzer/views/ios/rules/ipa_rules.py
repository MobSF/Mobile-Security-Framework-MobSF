# -*- coding: utf_8 -*-
"""IPA Binary Analysis Rules."""
from libsast.standards import get_standards

HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
STDS = get_standards()
IPA_RULES = [
    {
        'description': 'Binary makes use of insecure API(s)',
        'detailed_desc': (
            'The binary may contain the following insecure API(s) {}'),
        'type': 'Regex',
        'pattern': (
            rb'\b_alloca\b|\b_gets\b|\b_memcpy\b|\b_printf\b|'
            rb'\b_scanf\b|\b_sprintf\b|\b_sscanf\b|\b_strcat\b|'
            rb'\bStrCat\b|\b_strcpy\b|\bStrCpy\b|\b_strlen\b|'
            rb'\bStrLen\b|\b_strncat\b|\bStrNCat\b|\b_strncpy\b|'
            rb'\bStrNCpy\b|\b_strtok\b|\b_swprintf\b|\b_vsnprintf\b|'
            rb'\b_vsprintf\b|\b_vswprintf\b|\b_wcscat\b|\b_wcscpy\b|'
            rb'\b_wcslen\b|\b_wcsncat\b|\b_wcsncpy\b|\b_wcstok\b|'
            rb'\b_wmemcpy\b|\b_fopen\b|\b_chmod\b|\b_chown\b|'
            rb'\b_stat\b|\b_mktemp\b'),
        'severity': WARNING,
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
        'severity': WARNING,
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
        'severity': INFO,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': STDS['cwe']['cwe-310'],
        'owasp-mobile': STDS['owasp-mobile']['m5'],
        'masvs': STDS['masvs']['crypto-3'],
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
        'severity': WARNING,
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
        'severity': INFO,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': STDS['cwe']['cwe-310'],
        'owasp-mobile': STDS['owasp-mobile']['m5'],
        'masvs': STDS['masvs']['crypto-4'],
    },
    {
        'description': 'Binary makes use of the insecure Random function(s)',
        'detailed_desc': (
            'The binary may use the following '
            'insecure Random function(s) {}'),
        'type': 'Regex',
        'pattern': rb'\b_srand\b|\b_random\b|\b_rand\b|\b_drand48\b',
        'severity': WARNING,
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
        'pattern': rb'\b_NSLog\b|\b_NSLogv\b',
        'severity': INFO,
        'input_case': 'exact',
        'cvss': 7.5,
        'cwe': STDS['cwe']['cwe-532'],
        'owasp-mobile': STDS['owasp-mobile']['m2'],
        'masvs': STDS['masvs']['storage-3'],
    },
    {
        'description': 'Binary makes use of malloc function',
        'detailed_desc': (
            'The binary may use {} function instead of calloc'),
        'type': 'Regex',
        'pattern': rb'\b_malloc\b',
        'severity': WARNING,
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
        'severity': WARNING,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': STDS['cwe']['cwe-489'],
        'owasp-mobile': STDS['owasp-mobile']['m7'],
        'masvs': STDS['masvs']['resilience-2'],
    },
    {
        'description': 'Binary uses deprecated UIWebView Component',
        'detailed_desc': (
            'The binary references UIWebView ({}), which is deprecated by '
            'Apple and lacks modern out-of-process sandboxing and content '
            'security controls. Migrate to WKWebView.'
        ),
        'type': 'Regex',
        'pattern': (
            rb'\b_?OBJC_(?:CLASS|METACLASS)_\$_UIWebView\b|\bUIWebView\b'
        ),
        'severity': WARNING,
        'input_case': 'exact',
        'cvss': 4.3,
        'cwe': STDS['cwe']['cwe-477'],
        'owasp-mobile': STDS['owasp-mobile']['m1'],
        'masvs': STDS['masvs']['platform-2'],
    },
    {
        'description': (
            'Binary references weak Keychain accessibility attribute(s)'
        ),
        'detailed_desc': (
            'The binary references weak Keychain accessibility constant(s) '
            '({}). Items stored with kSecAttrAccessibleAlways remain '
            'decrypted even when the device is locked. Use '
            'kSecAttrAccessibleWhenUnlockedThisDeviceOnly or '
            'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.'
        ),
        'type': 'Regex',
        'pattern': (
            rb'\b_?kSecAttrAccessibleAlways\b|'
            rb'\b_?kSecAttrAccessibleAlwaysThisDeviceOnly\b'
        ),
        'severity': WARNING,
        'input_case': 'exact',
        'cvss': 5.3,
        'cwe': STDS['cwe']['cwe-522'],
        'owasp-mobile': STDS['owasp-mobile']['m2'],
        'masvs': STDS['masvs']['storage-1'],
    },
    {
        'description': (
            'Binary references insecure SSL/TLS certificate validation API(s)'
        ),
        'detailed_desc': (
            'The binary references selector(s) or constant(s) that can '
            'disable TLS certificate chain validation ({}), exposing '
            'network connections to Man-in-the-Middle (MitM) attacks.'
        ),
        'type': 'Regex',
        'pattern': (
            rb'setAllowsAnyHTTPSCertificate|'
            rb'allowsAnyHTTPSCertificateForHost|'
            rb'continueWithoutCredentialForAuthenticationChallenge|'
            rb'\b_?kCFStreamSSLAllowsAnyRoot\b|'
            rb'\b_?kCFStreamSSLAllowsExpiredCertificates\b|'
            rb'\b_?kCFStreamSSLAllowsExpiredRoots\b'
        ),
        'severity': HIGH,
        'input_case': 'exact',
        'cvss': 7.4,
        'cwe': STDS['cwe']['cwe-295'],
        'owasp-mobile': STDS['owasp-mobile']['m3'],
        'masvs': STDS['masvs']['network-1'],
    },
    {
        'description': (
            'Binary references dangerous WKWebView file access selector(s)'
        ),
        'detailed_desc': (
            'The binary references WKWebView configuration selector(s) ({}) '
            'that enable file:// or cross-origin universal access from local '
            'files, which can allow local file disclosure if untrusted '
            'content is loaded.'
        ),
        'type': 'Regex',
        'pattern': (
            rb'(?:set[Aa]llow|[Aa]llow)FileAccessFromFileURLs:?|'
            rb'(?:set[Aa]llow|[Aa]llow)UniversalAccessFromFileURLs:?'
        ),
        'severity': WARNING,
        'input_case': 'exact',
        'cvss': 5.4,
        'cwe': STDS['cwe']['cwe-749'],
        'owasp-mobile': STDS['owasp-mobile']['m1'],
        'masvs': STDS['masvs']['platform-2'],
    },
    {
        'description': 'Binary makes use of UIPasteboard',
        'detailed_desc': (
            'The binary references UIPasteboard ({}). Copying sensitive data '
            'to the system-wide generalPasteboard exposes it to other '
            'installed applications.'
        ),
        'type': 'Regex',
        'pattern': rb'\b_?OBJC_CLASS_\$_UIPasteboard\b|\bgeneralPasteboard\b',
        'severity': INFO,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': STDS['cwe']['cwe-200'],
        'owasp-mobile': STDS['owasp-mobile']['m1'],
        'masvs': STDS['masvs']['platform-1'],
    },
    {
        'description': 'Binary makes use of SQLite API(s)',
        'detailed_desc': (
            'The binary uses raw SQLite C API(s) ({}). Ensure queries use '
            'parameterized statements (sqlite3_bind_*) rather than string '
            'concatenation and that sensitive databases are encrypted.'
        ),
        'type': 'Regex',
        'pattern': (
            rb'\b_sqlite3_exec\b|\b_sqlite3_prepare\b|'
            rb'\b_sqlite3_prepare_v2\b|\b_sqlite3_prepare_v3\b'
        ),
        'severity': INFO,
        'input_case': 'exact',
        'cvss': 0,
        'cwe': STDS['cwe']['cwe-89'],
        'owasp-mobile': STDS['owasp-mobile']['m7'],
        'masvs': STDS['masvs']['platform-2'],
    },
]
