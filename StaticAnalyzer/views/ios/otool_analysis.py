import logging
import os
import re
import platform
import stat
import subprocess

from django.conf import settings
from django.utils.encoding import smart_text
from django.utils.html import escape

from MobSF.utils import is_file_exists

from StaticAnalyzer.views.standards import (
    CWE,
    OWASP,
    OWASP_MSTG,
)
from StaticAnalyzer.views.rules_properties import Level

logger = logging.getLogger(__name__)


def get_otool_out(tools_dir, cmd_type, bin_path, bin_dir):
    """Get otool args by OS and type."""
    if (len(settings.OTOOL_BINARY) > 0
            and is_file_exists(settings.OTOOL_BINARY)):
        otool_bin = settings.OTOOL_BINARY
    else:
        otool_bin = 'otool'
    if (len(settings.JTOOL_BINARY) > 0
            and is_file_exists(settings.JTOOL_BINARY)):
        jtool_bin = settings.JTOOL_BINARY
    else:
        jtool_bin = os.path.join(tools_dir, 'jtool.ELF64')
    jtool2_bin = os.path.join(tools_dir, 'jtool2.ELF64')
    # jtool execute permission check
    for toolbin in [jtool_bin, jtool2_bin]:
        if not os.access(toolbin, os.X_OK):
            os.chmod(toolbin, stat.S_IEXEC)
    plat = platform.system()
    if cmd_type == 'libs':
        if plat == 'Darwin':
            args = [otool_bin, '-L', bin_path]
            args2 = args
        elif plat == 'Linux':
            args = [jtool_bin, '-arch', 'arm', '-L', '-v', bin_path]
            args2 = [jtool2_bin, '-L', '-v', '-q', bin_path]
        else:
            # Platform Not Supported
            return None
        try:
            libs = subprocess.check_output(args2).decode('utf-8', 'ignore')
        except Exception:
            libs = subprocess.check_output(args).decode('utf-8', 'ignore')
        libs = smart_text(escape(libs.replace(bin_dir + '/', '')))
        return libs.split('\n')
    elif cmd_type == 'header':
        if plat == 'Darwin':
            args = [otool_bin, '-hv', bin_path]
            args2 = args
        elif plat == 'Linux':
            args = [jtool_bin, '-arch', 'arm', '-h', '-v', bin_path]
            args2 = [jtool2_bin, '-h', '-v', '-q', bin_path]
        else:
            # Platform Not Supported
            return None
        try:
            return subprocess.check_output(args2)
        except Exception:
            return subprocess.check_output(args)
    elif cmd_type == 'symbols':
        if plat == 'Darwin':
            args = [otool_bin, '-Iv', bin_path]
            args2 = args
            return subprocess.check_output(args)
        elif plat == 'Linux':
            args = [jtool_bin, '-arch', 'arm', '-S', bin_path]
            arg2 = [jtool2_bin, '-S', bin_path]
            try:
                with open(os.devnull, 'w') as devnull:
                    return subprocess.check_output(arg2, stderr=devnull)
            except Exception:
                return subprocess.check_output(args)
        else:
            # Platform Not Supported
            return None
    elif cmd_type == 'classdump':
        # Handle Classdump in Linux
        # Add timeout to handle ULEB128 malformed
        return [jtool_bin, '-arch', 'arm', '-d', 'objc', '-v', bin_path]
    return None


def otool_analysis(tools_dir, bin_name, bin_path, bin_dir):
    """OTOOL Analysis of Binary."""
    try:
        otool_dict = {
            'libs': [],
            'anal': [],
        }
        logger.info('Running Object analysis of binary: %s', bin_name)
        otool_dict['libs'] = get_otool_out(
            tools_dir, 'libs', bin_path, bin_dir)
        # PIE
        pie_dat = get_otool_out(tools_dir, 'header', bin_path, bin_dir)
        if b'PIE' in pie_dat:
            pie_flag = {
                'issue': 'fPIE -pie flag is Found',
                'level': Level.good.value,
                'description': ('App is compiled with Position Independent '
                                'Executable (PIE) flag. This enables Address'
                                ' Space Layout Randomization (ASLR), a memory'
                                ' protection mechanism for'
                                ' exploit mitigation.'),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
                'owasp-mstg': OWASP_MSTG['code-9'],
            }
        else:
            pie_flag = {
                'issue': 'fPIE -pie flag is not Found',
                'level': Level.high.value,
                'description': ('with Position Independent Executable (PIE) '
                                'flag. So Address Space Layout Randomization '
                                '(ASLR) is missing. ASLR is a memory '
                                'protection mechanism for '
                                'exploit mitigation.'),
                'cvss': 2,
                'cwe': CWE['CWE-119'],
                'owasp': OWASP['m1'],
                'owasp-mstg': OWASP_MSTG['code-9'],
            }
        # Stack Smashing Protection & ARC
        dat = get_otool_out(tools_dir, 'symbols', bin_path, bin_dir)
        if b'stack_chk_guard' in dat:
            ssmash = {
                'issue': 'fstack-protector-all flag is Found',
                'level': Level.good.value,
                'description': ('App is compiled with Stack Smashing Protector'
                                ' (SSP) flag and is having protection against'
                                ' Stack Overflows/Stack Smashing Attacks.'),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
                'owasp-mstg': OWASP_MSTG['code-9'],
            }
        else:
            ssmash = {
                'issue': 'fstack-protector-all flag is not Found',
                'level': Level.high.value,
                'description': ('App is not compiled with Stack Smashing '
                                'Protector (SSP) flag. It is vulnerable to'
                                'Stack Overflows/Stack Smashing Attacks.'),
                'cvss': 2,
                'cwe': 'CWE-119',
                'owasp': OWASP['m1'],
                'owasp-mstg': OWASP_MSTG['code-9'],
            }

        # ARC
        if b'_objc_release' in dat:
            arc_flag = {
                'issue': 'fobjc-arc flag is Found',
                'level': Level.good.value,
                'description': ('App is compiled with Automatic Reference '
                                'Counting (ARC) flag. ARC is a compiler '
                                'feature that provides automatic memory '
                                'management of Objective-C objects and is an '
                                'exploit mitigation mechanism against memory '
                                'corruption vulnerabilities.'),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
                'owasp-mstg': OWASP_MSTG['code-9'],
            }
        else:
            arc_flag = {
                'issue': 'fobjc-arc flag is not Found',
                'level': Level.high.value,
                'description': ('App is not compiled with Automatic Reference '
                                'Counting (ARC) flag. ARC is a compiler '
                                'feature that provides automatic memory '
                                'management of Objective-C objects and '
                                'protects from memory corruption '
                                'vulnerabilities.'),
                'cvss': 2,
                'cwe': CWE['CWE-119'],
                'owasp': OWASP['m1'],
                'owasp-mstg': OWASP_MSTG['code-9'],

            }

        banned_apis = {}
        baned = re.findall(
            rb'\b_alloca\b|\b_gets\b|\b_memcpy\b|\b_printf\b|\b_scanf\b|'
            rb'\b_sprintf\b|\b_sscanf\b|\b_strcat\b|'
            rb'\bStrCat\b|\b_strcpy\b|\bStrCpy\b|\b_strlen\b|\bStrLen\b|'
            rb'\b_strncat\b|\bStrNCat\b|\b_strncpy\b|'
            rb'\bStrNCpy\b|\b_strtok\b|\b_swprintf\b|\b_vsnprintf\b|'
            rb'\b_vsprintf\b|\b_vswprintf\b|\b_wcscat\b|\b_wcscpy\b|'
            rb'\b_wcslen\b|\b_wcsncat\b|\b_wcsncpy\b|\b_wcstok\b|\b_wmemcpy\b|'
            rb'\b_fopen\b|\b_chmod\b|\b_chown\b|\b_stat\b|\b_mktemp\b', dat)
        baned = list(set(baned))
        baned_s = b', '.join(baned)
        if len(baned_s) > 1:
            banned_apis = {
                'issue': 'Binary make use of insecure API(s)',
                'level': Level.high.value,
                'description': ('The binary may contain'
                                ' the following insecure API(s) {}.').format(
                                    baned_s.decode('utf-8', 'ignore')),
                'cvss': 6,
                'cwe': CWE['CWE-676'],
                'owasp': OWASP['m7'],
                'owasp-mstg': OWASP_MSTG['code-8'],
            }

        weak_cryptos = {}
        weak_algo = re.findall(
            rb'\bkCCAlgorithmDES\b|'
            rb'\bkCCAlgorithm3DES\b|'
            rb'\bkCCAlgorithmRC2\b|'
            rb'\bkCCAlgorithmRC4\b|'
            rb'\bkCCOptionECBMode\b|'
            rb'\bkCCOptionCBCMode\b', dat)
        weak_algo = list(set(weak_algo))
        weak_algo_s = b', '.join(weak_algo)
        if len(weak_algo_s) > 1:
            weak_cryptos = {
                'issue': 'Binary make use of some Weak Crypto API(s)',
                'level': Level.high.value,
                'description': ('The binary may use the'
                                ' following weak crypto API(s) {}.').formnat(
                                    weak_algo_s.decode('utf-8', 'ignore')),
                'cvss': 3,
                'cwe': CWE['CWE-327'],
                'owasp': OWASP['m5'],
                'owasp-mstg': OWASP_MSTG['crypto-3'],
            }

        crypto = {}
        crypto_algo = re.findall(
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
            rb'SecTrustRef\b', dat)
        crypto_algo = list(set(crypto_algo))
        crypto_algo_s = b', '.join(crypto_algo)
        if len(crypto_algo_s) > 1:
            crypto = {
                'issue': 'Binary make use of the following Crypto API(s)',
                'level': Level.info.value,
                'description': ('The binary may use '
                                'the following crypto API(s) {}.').format(
                                    crypto_algo_s.decode('utf-8', 'ignore')),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
                'owasp-mstg': '',
            }

        weak_hashes = {}
        weak_hash_algo = re.findall(
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
            rb'SHA1_Update\b|\bSHA1_Final\b', dat)
        weak_hash_algo = list(set(weak_hash_algo))
        weak_hash_algo_s = b', '.join(weak_hash_algo)
        if len(weak_hash_algo_s) > 1:
            weak_hashes = {
                'issue': 'Binary make use of the following Weak Hash API(s)',
                'level': Level.high.value,
                'description': (
                    'The binary may use the '
                    'following weak hash API(s) {}.').format(
                        weak_hash_algo_s.decode('utf-8', 'ignore')),
                'cvss': 3,
                'cwe': CWE['CWE-327'],
                'owasp': OWASP['m5'],
                'owasp-mstg': OWASP_MSTG['crypto-4'],
            }

        hashes = {}
        hash_algo = re.findall(
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
            rb'SHA512_Update\b|\bSHA512_Final\b', dat)
        hash_algo = list(set(hash_algo))
        hash_algo_s = b', '.join(hash_algo)
        if len(hash_algo_s) > 1:
            hashes = {
                'issue': 'Binary make use of the following Hash API(s)',
                'level': Level.info.value,
                'description': ('The binary may use the'
                                ' following hash API(s) {}.').format(
                                    hash_algo_s.decode('utf-8', 'ignore')),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
                'owasp-mstg': '',
            }

        randoms = {}
        rand_algo = re.findall(rb'\b_srand\b|\b_random\b', dat)
        rand_algo = list(set(rand_algo))
        rand_algo_s = b', '.join(rand_algo)
        if len(rand_algo_s) > 1:
            randoms = {
                'issue': 'Binary make use of the insecure Random Function(s)',
                'level': Level.high.value,
                'description': ('The binary may use the following '
                                'insecure Random Function(s) {}.').format(
                                    rand_algo_s.decode('utf-8', 'ignore')),
                'cvss': 3,
                'cwe': CWE['CWE-330'],
                'owasp': OWASP['m5'],
                'owasp-mstg': OWASP_MSTG['crypto-6'],
            }

        logging = {}
        log = re.findall(rb'\b_NSLog\b', dat)
        log = list(set(log))
        log_s = b', '.join(log)
        if len(log_s) > 1:
            logging = {
                'issue': 'Binary make use of Logging Function',
                'level': Level.info.value,
                'description': ('The binary may use NSLog'
                                ' function for logging.'),
                'cvss': 7.5,
                'cwe': CWE['CWE-532'],
                'owasp': '',
                'owasp-mstg': OWASP_MSTG['storage-3'],
            }

        malloc = {}
        mal = re.findall(rb'\b_malloc\b', dat)
        mal = list(set(mal))
        mal_s = b', '.join(mal)
        if len(mal_s) > 1:
            malloc = {
                'issue': 'Binary make use of malloc Function',
                'level': Level.high.value,
                'description': ('The binary may use malloc'
                                ' function instead of calloc.'),
                'cvss': 2,
                'cwe': CWE['CWE-789'],
                'owasp': OWASP['m7'],
                'owasp-mstg': OWASP_MSTG['code-8'],
            }

        debug = {}
        ptrace = re.findall(rb'\b_ptrace\b', dat)
        ptrace = list(set(ptrace))
        ptrace_s = b', '.join(ptrace)
        if len(ptrace_s) > 1:
            debug = {
                'issue': 'Binary calls ptrace Function for anti-debugging.',
                'level': Level.warning.value,
                'description': ('The binary may use ptrace function. It can be'
                                ' used to detect and prevent debuggers.'
                                'Ptrace is not a public API and Apps that use'
                                ' non-public APIs will be rejected'
                                ' from AppStore.'),
                'cvss': 0,
                'cwe': '',
                'owasp': OWASP['m7'],
                'owasp-mstg': OWASP_MSTG['resilience-2'],
            }
        otool_dict['anal'] = [pie_flag,
                              ssmash,
                              arc_flag,
                              banned_apis,
                              weak_cryptos,
                              crypto,
                              weak_hashes,
                              hashes,
                              randoms,
                              logging,
                              malloc,
                              debug]
        return otool_dict
    except Exception:
        logger.exception('Performing Object Analysis of Binary')
