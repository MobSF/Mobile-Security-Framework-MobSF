# -*- coding: utf_8 -*-
"""Module for iOS IPA Binary Analysis."""

import re
import os
import platform
import subprocess

from django.conf import settings
from django.utils.html import escape
from django.utils.encoding import smart_text

from StaticAnalyzer.tools.strings import strings_util
from MobSF.utils import PrintException, isFileExists


SECURE = "Secure"
IN_SECURE = "Insecure"
INFO = "Info"
WARNING = "Warning"


def get_otool_out(tools_dir, cmd_type, bin_path, bin_dir):
    """Get otool args by OS and type"""
    if len(settings.OTOOL_BINARY) > 0 and isFileExists(settings.OTOOL_BINARY):
        otool_bin = settings.OTOOL_BINARY
    else:
        otool_bin = "otool"
    if len(settings.JTOOL_BINARY) > 0 and isFileExists(settings.JTOOL_BINARY):
        jtool_bin = settings.JTOOL_BINARY
    else:
        jtool_bin = os.path.join(tools_dir, 'jtool.ELF64')
    plat = platform.system()
    if cmd_type == "libs":
        if plat == "Darwin":
            args = [otool_bin, '-L', bin_path]
        elif plat == "Linux":
            args = [jtool_bin, '-arch', 'arm', '-L', '-v', bin_path]
        else:
            # Platform Not Supported
            return None
        libs = subprocess.check_output(args).decode("utf-8", "ignore")
        libs = smart_text(escape(libs.replace(bin_dir + "/", "")))
        return libs.split("\n")
    elif cmd_type == "header":
        if plat == "Darwin":
            args = [otool_bin, '-hv', bin_path]
        elif plat == "Linux":
            args = [jtool_bin, '-arch', 'arm', '-h', '-v', bin_path]
        else:
            # Platform Not Supported
            return None
        return subprocess.check_output(args)
    elif cmd_type == "symbols":
        if plat == "Darwin":
            args = [otool_bin, '-Iv', bin_path]
            return subprocess.check_output(args)
        elif plat == "Linux":
            arg1 = [jtool_bin, '-arch', 'arm', '-bind', '-v', bin_path]
            arg2 = [jtool_bin, '-arch', 'arm', '-lazy_bind', '-v', bin_path]
            return subprocess.check_output(arg1) + subprocess.check_output(arg2)
        else:
            # Platform Not Supported
            return None


def otool_analysis(tools_dir, bin_name, bin_path, bin_dir):
    """OTOOL Analysis of Binary"""
    try:
        otool_dict = {
            "libs": [],
            "anal": []
        }
        print("[INFO] Running Object Analysis of Binary : " + bin_name)
        otool_dict["libs"] = get_otool_out(tools_dir, "libs", bin_path, bin_dir)
        # PIE
        pie_dat = get_otool_out(tools_dir, "header", bin_path, bin_dir)
        if b"PIE" in pie_dat:
            pie_flag = {
                "issue": "<strong>fPIE -pie</strong> flag is Found",
                "status": SECURE,
                "description": """App is compiled with Position Independent Executable (PIE) flag. 
                    This enables Address Space Layout Randomization (ASLR), a memory protection
                    mechanism for exploit mitigation."""
            }
        else:
            pie_flag = {
                "issue": "<strong>fPIE -pie</strong> flag is not Found",
                "status": IN_SECURE,
                "description": """with Position Independent Executable (PIE) flag. So Address Space Layout 
                    Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation."""
            }
        # Stack Smashing Protection & ARC
        dat = get_otool_out(tools_dir, "symbols", bin_path, bin_dir)
        if b"stack_chk_guard" in dat:
            ssmash = { "issue": "<strong>fstack-protector-all</strong> flag is Found",
                "status": SECURE,
                "description": """App is compiled with Stack Smashing Protector (SSP) flag and is having protection against Stack
                Overflows/Stack Smashing Attacks."""
                }
        else:
            ssmash = { "issue": "<strong>fstack-protector-all</strong> flag is not Found",
                "status": IN_SECURE,
                "description": """App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to
                Stack Overflows/Stack Smashing Attacks."""
                }
        # ARC
        if b"_objc_release" in dat:
            arc_flag = { "issue": "<strong>fobjc-arc</strong> flag is Found",
                "status": SECURE,
                "description": """App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature 
                that provides automatic memory management of Objective-C objects and is an
                exploit mitigation mechanism against memory corruption vulnerabilities."""
                }
        else:
            arc_flag = { "issue": "<strong>fobjc-arc</strong> flag is not Found",
                "status": IN_SECURE,
                "description": """App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that
                provides automatic memory management of Objective-C objects and protects from
                memory corruption vulnerabilities."""
                }

        banned_apis = {}
        baned = re.findall(
            b"_alloca|_gets|_memcpy|_printf|_scanf|_sprintf|_sscanf|_strcat|StrCat|_strcpy|" +
            b"StrCpy|_strlen|StrLen|_strncat|StrNCat|_strncpy|StrNCpy|_strtok|_swprintf|_vsnprintf|" +
            b"_vsprintf|_vswprintf|_wcscat|_wcscpy|_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|" +
            b"_fopen|_chmod|_chown|_stat|_mktemp", dat)
        baned = list(set(baned))
        baned_s = b', '.join(baned)
        if len(baned_s) > 1:
            banned_apis = { "issue" : "Binary make use of banned API(s)",
                "status": IN_SECURE,
                "description": "The binary may contain the following banned API(s)<strong>" + baned_s.decode('utf-8', 'ignore') + "</strong>."
                }
        weak_cryptos = {}
        weak_algo = re.findall(
            b"kCCAlgorithmDES|kCCAlgorithm3DES||kCCAlgorithmRC2|kCCAlgorithmRC4|" +
            b"kCCOptionECBMode|kCCOptionCBCMode", dat)
        weak_algo = list(set(weak_algo))
        weak_algo_s = b', '.join(weak_algo)
        if len(weak_algo_s) > 1:
            weak_cryptos = {"issue": "Binary make use of some Weak Crypto API(s)",
                "status": IN_SECURE,
                "description": "The binary may use the following weak crypto API(s) <strong>" + weak_algo_s.decode('utf-8', 'ignore') + "</strong>."
            }
        crypto = {}
        crypto_algo = re.findall(
            b"CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|" +
            b"CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|" +
            b"CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|" +
            b"kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|" +
            b"SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|" +
            b"SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|" +
            b"SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|" +
            b"SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|" +
            b"SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|" +
            b"SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|" +
            b"SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|" +
            b"SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|" +
            b"SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|" +
            b"SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|" +
            b"SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|" +
            b"SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|" +
            b"SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|" +
            b"SecTrustSetVerifyDate|SecCertificateRef|" +
            b"SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef", dat)
        crypto_algo = list(set(crypto_algo))
        crypto_algo_s = b', '.join(crypto_algo)
        if len(crypto_algo_s) > 1:
            crypto = { "issue": "Binary make use of the following Crypto API(s)",
                "status": "Info",
                "description": "The binary may use the following crypto API(s) <strong>" + crypto_algo_s.decode('utf-8', 'ignore') + "</strong>."
            }
        weak_hashes = {}
        weak_hash_algo = re.findall(
            b"CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|" +
            b"MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|" +
            b"MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|" +
            b"MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|" +
            b"CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final", dat)
        weak_hash_algo = list(set(weak_hash_algo))
        weak_hash_algo_s = b', '.join(weak_hash_algo)
        if len(weak_hash_algo_s) > 1:
            weak_hashe = { "issue": "Binary make use of the following Weak HASH API(s)",
                            "status": IN_SECURE,
                            "description": "The binary may use the following weak hash API(s) <strong>" + weak_hash_algo_s.decode('utf-8', 'ignore') + "</strong>."
                        }
        hashes = {}
        hash_algo = re.findall(
            b"CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|" +
            b"SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|" +
            b"CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|" +
            b"CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|" +
            b"SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|" +
            b"CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final", dat)
        hash_algo = list(set(hash_algo))
        hash_algo_s = b', '.join(hash_algo)
        if len(hash_algo_s) > 1:
            hashes = { "issue": "Binary make use of the following HASH API(s)",
                       "status": INFO,
                       "description": "The binary may use the following hash API(s) <strong>" + hash_algo_s.decode('utf-8', 'ignore') + "</strong>."
                    }
        randoms = {}
        rand_algo = re.findall(b"_srand|_random", dat)
        rand_algo = list(set(rand_algo))
        rand_algo_s = b', '.join(rand_algo)
        if len(rand_algo_s) > 1:
            randoms = { "issue": "Binary make use of the insecure Random Function(s)",
                       "status": IN_SECURE,
                       "description": "The binary may use the following insecure Random Function(s) <strong>" + rand_algo_s.decode('utf-8', 'ignore') + "</strong>."
                    }
        logging = {}
        log = re.findall(b"_NSLog", dat)
        log = list(set(log))
        log_s = b', '.join(log)
        if len(log_s) > 1:
            logging = { "issue": "Binary make use of Logging Function",
                       "status": INFO,
                       "description": "The binary may use <strong>NSLog</strong> function for logging."
                       }
        malloc = {}

        mal = re.findall(b"_malloc", dat)
        mal = list(set(mal))
        mal_s = b', '.join(mal)
        if len(mal_s) > 1:
            malloc = { "issue": "Binary make use of <strong>malloc</strong> Function",
                       "status": IN_SECURE,
                       "description": "The binary may use <strong>malloc</strong> function instead of <strong>calloc</strong>."
                    }
        debug = {}

        ptrace = re.findall(b"_ptrace", dat)
        ptrace = list(set(ptrace))
        ptrace_s = b', '.join(ptrace)
        if len(ptrace_s) > 1:
            debug = { "issue": "Binary calls <strong>ptrace</strong> Function for anti-debugging.",
                       "status": WARNING,
                       "description": """The binary may use <strong>ptrace</strong> function. It can be used to detect and prevent debuggers. 
                            Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. """
                    }
        otool_dict["anal"] = [pie_flag, ssmash, arc_flag, banned_apis, weak_cryptos, crypto, weak_hashes, hashes, randoms, logging, malloc, debug]
        return otool_dict
    except:
        PrintException("[ERROR] Performing Object Analysis of Binary")


def class_dump_z(tools_dir, bin_path, app_dir):
    """Running Classdumpz on binary"""
    try:
        webview = {}
        if platform.system() == "Darwin":
            print("[INFO] Running class-dump-z against the binary for dumping classes")
            if len(settings.CLASSDUMPZ_BINARY) > 0 and isFileExists(settings.CLASSDUMPZ_BINARY):
                class_dump_z_bin = settings.CLASSDUMPZ_BINARY
            else:
                class_dump_z_bin = os.path.join(tools_dir, 'class-dump-z')
            subprocess.call(["chmod", "777", class_dump_z_bin])
            args = [class_dump_z_bin, bin_path]
        elif platform.system() == "Linux":
            print("[INFO] Running jtool against the binary for dumping classes")
            if len(settings.JTOOL_BINARY) > 0 and isFileExists(settings.JTOOL_BINARY):
                jtool_bin = settings.JTOOL_BINARY
            else:
                jtool_bin = os.path.join(tools_dir, 'jtool.ELF64')
            subprocess.call(["chmod", "777", jtool_bin])
            args = [jtool_bin, '-arch', 'arm', '-d', 'objc', '-v', bin_path]
        else:
            # Platform not supported
            return {}
        classdump = subprocess.check_output(args)
        dump_file = os.path.join(app_dir, "classdump.txt")
        with open(dump_file, "w") as flip:
            flip.write(classdump.decode("utf-8", "ignore"))
        if b"UIWebView" in classdump:
            webview = { "issue": "Binary uses WebView Component.",
                        "status": INFO,
                        "description":  "The binary may use WebView Component."
                    }
        return webview
    except:
        print("[INFO] class-dump-z does not work on iOS apps developed in Swift")
        PrintException("[ERROR] - Cannot perform class dump")


def strings_on_ipa(bin_path):
    """Extract Strings from IPA"""
    try:
        print("[INFO] Running strings against the Binary")
        unique_str = []
        unique_str = list(set(strings_util(bin_path)))  # Make unique
        unique_str = [escape(ip_str)
                      for ip_str in unique_str]  # Escape evil strings
        return unique_str
    except:
        PrintException("[ERROR] - Running strings against the Binary")


def binary_analysis(src, tools_dir, app_dir, executable_name):
    """Binary Analysis of IPA"""
    try:
        binary_analysis_dict = {}
        print("[INFO] Starting Binary Analysis")
        dirs = os.listdir(src)
        dot_app_dir = ""
        for dir_ in dirs:
            if dir_.endswith(".app"):
                dot_app_dir = dir_
                break
        # Bin Dir - Dir/Payload/x.app/
        bin_dir = os.path.join(src, dot_app_dir)
        if executable_name is None:
            bin_name = dot_app_dir.replace(".app", "")
        else:
            bin_name = executable_name
        # Bin Path - Dir/Payload/x.app/x
        bin_path = os.path.join(bin_dir, bin_name)
        binary_analysis_dict["libs"] = []
        binary_analysis_dict["bin_res"] = []
        binary_analysis_dict["strings"] = []
        if not isFileExists(bin_path):
            print("[WARNING] MobSF Cannot find binary in " + bin_path)
            print("[WARNING] Skipping Otool, Classdump and Strings")
        else:
            otool_dict = otool_analysis(tools_dir, bin_name, bin_path, bin_dir)
            cls_dump = class_dump_z(tools_dir, bin_path, app_dir)
            # Classdumpz can fail on swift coded binaries
            if not cls_dump:
                cls_dump = {}
            strings_in_ipa = strings_on_ipa(bin_path)
            otool_dict["anal"] = otool_dict["anal"] + [cls_dump]
            binary_analysis_dict["libs"] = otool_dict["libs"]
            binary_analysis_dict["bin_res"] = otool_dict["anal"]
            binary_analysis_dict["strings"] = strings_in_ipa
        return binary_analysis_dict
    except:
        PrintException("[ERROR] iOS Binary Analysis")
