# -*- coding: utf_8 -*-
"""Windows Analysis Module."""
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from shared_func import FileSize
from shared_func import HashGen
from shared_func import Unzip

from StaticAnalyzer.models import StaticAnalyzerWindows
from MobSF.utils import PrintException
from MobSF.utils import isFileExists

import re
import os
import subprocess
import plistlib

try:
    import xhtml2pdf.pisa as pisa
except ImportError:
    PrintException("[ERROR] xhtml2pdf is not installed. Cannot generate PDF reports")

try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO

##############################################################
# Code to support Windows Static Code Anlysis
##############################################################
#Windows Support Functions
def staticanalyzer_windows(request):
    """Analyse a windows app."""
    try:
        #Input validation
        print "[INFO] Windows Static Analysis Started"
        typ = request.GET['type']
        rescan = str(request.GET.get('rescan', 0))
        m = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if (m) and (typ in ['appx']):
            APP_NAME = request.GET['name'] #APP ORGINAL NAME
            MD5 = request.GET['checksum']  #MD5
            APP_DIR = os.path.join(settings.UPLD_DIR, MD5+'/') #APP DIRECTORY
            TOOLS_DIR = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/tools/windows/')  #TOOLS DIR
            if typ == 'appx':
                #DB
                DB = StaticAnalyzerWindows.objects.filter(MD5=MD5)
                if DB.exists() and rescan == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title' : DB[0].TITLE,
                        'name' : DB[0].APP_NAME,
                        'size' : DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1' : DB[0].SHA1,
                        'sha256' : DB[0].SHA256,
                        'bin_name' : DB[0].BINNAME,
                        'bin_anal' : DB[0].BIN_ANAL,
                        'strings' : DB[0].STRINGS
                    }
                else:
                    print "[INFO] Windows Binary Analysis Started"
                    APP_PATH = APP_DIR + MD5 + '.appx'      # Filename and dir
                    #BIN_DIR = os.path.join(APP_DIR, "Payload/") # Not needed, root dir
                    # ANALYSIS BEGINS
                    SIZE = str(FileSize(APP_PATH)) + 'MB'   # FILE SIZE
                    # Generate hashes
                    SHA1, SHA256 = HashGen(APP_PATH)
                    # EXTRACT APPX
                    print "[INFO] Extracting APPX"
                    Unzip(APP_PATH, APP_DIR)
                    # BIN_NAME, BIN_ANAL, STRINGS = BinaryAnalysis(BIN_DIR, TOOLS_DIR, APP_DIR)
                    BIN_NAME = BinaryAnalysis(TOOLS_DIR, APP_DIR)
                    # Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if rescan == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerWindows.objects.filter(
                            MD5=MD5
                        ).update(
                            TITLE='Static Analysis',
                            APP_NAME=APP_NAME,
                            SIZE=SIZE,
                            MD5=MD5,
                            SHA1=SHA1,
                            SHA256=SHA256,
                            BINNAME=BIN_NAME,
                            # BIN_ANAL=BIN_ANAL,
                            # STRINGS=STRINGS
                        )
                    elif rescan == '0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB = StaticAnalyzerWindows(
                            TITLE='Static Analysis',
                            APP_NAME=APP_NAME,
                            SIZE=SIZE,
                            MD5=MD5,
                            SHA1=SHA1,
                            SHA256=SHA256,
                            BINNAME=BIN_NAME,
                            #BIN_ANAL=BIN_ANAL,
                            #STRINGS=STRINGS
                        )
                        STATIC_DB.save()
                    context = {
                        'title' : 'Static Analysis',
                        'name' : APP_NAME,
                        'size' : SIZE,
                        'md5': MD5,
                        'sha1' : SHA1,
                        'sha256' : SHA256,
                        'bin_name' : BIN_NAME,
                        #'bin_anal' : BIN_ANAL,
                        #'strings' : STRINGS,
                    }
                template = "windows_binary_analysis.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except Exception as e:
        PrintException("[ERROR] Static Analyzer Windows")
        context = {
            'title' : 'Error',
            'exp' : e.message,
            'doc' : e.__doc__
        }
        template = "error.html"
        return render(request, template, context)

def BinaryAnalysis(TOOLS_DIR, APP_DIR):
    try:
        print "[INFO] Starting Binary Analysis"
        dirs = os.listdir(APP_DIR)
        for d in dirs:
            if d.endswith(".exe"):
                break
        BIN_DIR = os.path.join(APP_DIR, d)         #Full Dir/Payload/x.app
        XML_FILE = os.path.join(BIN_DIR, "Info.plist")
        BIN = d.replace(".exe", "")
        BIN_NAME = BIN

        return BIN
        ID = ""
        VER = ""
        SDK = ""
        PLTFM = ""
        MIN = ""
        XML = ""

        try:
            print "[INFO] Reading Info.plist"
            XML = readBinXML(XML_FILE)
            p = plistlib.readPlistFromString(XML)
            BIN_NAME = BIN = ID = VER = SDK = PLTFM = MIN = ""
            if "CFBundleDisplayName" in p:
                BIN_NAME = p["CFBundleDisplayName"]
            if "CFBundleExecutable" in p:
                BIN = p["CFBundleExecutable"]
            if "CFBundleIdentifier" in p:
                ID = p["CFBundleIdentifier"]
            if "CFBundleVersion" in p:
                VER = p["CFBundleVersion"]
            if "DTSDKName" in p:
                SDK = p["DTSDKName"]
            if "DTPlatformVersion" in p:
                PLTFM = p["DTPlatformVersion"]
            if "MinimumOSVersion" in p:
                MIN = p["MinimumOSVersion"]

        except:
            PrintException("[ERROR] - Reading from Info.plist")
        BIN_PATH = os.path.join(BIN_DIR, BIN)  #Full Dir/Payload/x.app/x
        print "[INFO] iOS Binary : " + BIN
        print "[INFO] Running otool against the Binary"
        #Libs Used
        LIBS = ''
        if len(settings.OTOOL_BINARY) > 0 and isFileExists(OTOOL_BINARY):
            OTOOL = settings.OTOOL_BINARY
        else:
            OTOOL = "otool"
        args = [OTOOL, '-L', BIN_PATH]
        dat = subprocess.check_output(args)
        dat = escape(dat.replace(BIN_DIR + "/", ""))
        LIBS = dat.replace("\n", "</br>")
        #PIE
        args = [OTOOL, '-hv', BIN_PATH]
        dat = subprocess.check_output(args)
        if "PIE" in dat:
            PIE = "<tr><td><strong>fPIE -pie</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Position Independent Executable (PIE) flag. This enables Address Space Layout Randomization (ASLR), a memory protection mechanism for exploit mitigation.</td></tr>"
        else:
            PIE = "<tr><td><strong>fPIE -pie</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Position Independent Executable (PIE) flag. So Address Space Layout Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation.</td></tr>"
        #Stack Smashing Protection & ARC
        args = [OTOOL, '-Iv', BIN_PATH]
        dat = subprocess.check_output(args)
        if "stack_chk_guard" in dat:
            SSMASH = "<tr><td><strong>fstack-protector-all</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Stack Smashing Protector (SSP) flag and is having protection against Stack Overflows/Stack Smashing Attacks.</td></tr>"
        else:
            SSMASH = "<tr><td><strong>fstack-protector-all</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to Stack Overflows/Stack Smashing Attacks.</td></tr>"
        #ARC
        if "_objc_release" in dat:
            ARC = "<tr><td><strong>fobjc-arc</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.</td></tr>"
        else:
            ARC = "<tr><td><strong>fobjc-arc</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and protects from memory corruption vulnerabilities.</td></tr>"
        ##########
        BANNED_API = ''
        x = re.findall("alloca|gets|memcpy|printf|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            BANNED_API = "<tr><td>Binary make use of banned API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may contain the following banned API(s) </br><strong>" + str(x) + "</strong>.</td></tr>"
        WEAK_CRYPTO = ''
        x = re.findall("kCCAlgorithmDES|kCCAlgorithm3DES||kCCAlgorithmRC2|kCCAlgorithmRC4|kCCOptionECBMode|kCCOptionCBCMode", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            WEAK_CRYPTO = "<tr><td>Binary make use of some Weak Crypto API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak crypto API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        CRYPTO = ''
        x = re.findall("CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|SecTrustSetVerifyDate|SecCertificateRef|SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            CRYPTO = "<tr><td>Binary make use of the following Crypto API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following crypto API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        WEAK_HASH = ''
        x = re.findall("CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            WEAK_HASH = "<tr><td>Binary make use of the following Weak HASH API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak hash API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        HASH = ''
        x = re.findall("CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            HASH = "<tr><td>Binary make use of the following HASH API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following hash API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        RAND = ''
        x = re.findall("srand|random", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            RAND = "<tr><td>Binary make use of the insecure Random Function(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following insecure Random Function(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        LOG = ''
        x = re.findall("NSLog", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            LOG = "<tr><td>Binary make use of Logging Function</td><td><span class='label label-info'>Info</span></td><td>The binary may use <strong>NSLog</strong> function for logging.</td></tr>"
        MALL = ''
        x = re.findall("malloc", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            MALL = "<tr><td>Binary make use of <strong>malloc</strong> Function</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use <strong>malloc</strong> function instead of <strong>calloc</strong>.</td></tr>"
        DBG = ''
        x = re.findall("ptrace", dat)
        x = list(set(x))
        x = ', '.join(x)
        if len(x) > 1:
            DBG = "<tr><td>Binary calls <strong>ptrace</strong> Function for anti-debugging.</td><td><span class='label label-warning'>warning</span></td><td>The binary may use <strong>ptrace</strong> function. It can be used to detect and prevent debuggers. Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. </td></tr>"
        CDUMP = ''
        WVIEW = ''
        try:
            print "[INFO] Running class-dump-z against the Binary"
            if len(settings.CLASSDUMPZ_BINARY) > 0 and isFileExists(settings.CLASSDUMPZ_BINARY):
                CLASSDUMPZ_BIN = settings.CLASSDUMPZ_BINARY
            else:
                CLASSDUMPZ_BIN = os.path.join(TOOLS_DIR, 'class-dump-z')
            subprocess.call(["chmod", "777", CLASSDUMPZ_BIN])
            dat = subprocess.check_output([CLASSDUMPZ_BIN, BIN_PATH])
            CDUMP = dat
            FILE = os.path.join(APP_DIR, "classdump.txt")
            with open(FILE, "w") as f:
                f.write(CDUMP)
            if "UIWebView" in CDUMP:
                WVIEW = "<tr><td>Binary uses WebView Component.</td><td><span class='label label-info'>Info</span></td><td>The binary may use WebView Component.</td></tr>"

        except Exception:
            PrintException("[ERROR] - Cannot perform class dump")
        BIN_RES = \
            PIE + \
            SSMASH + \
            ARC + \
            BANNED_API + \
            WEAK_CRYPTO + \
            CRYPTO + \
            WEAK_HASH + \
            HASH + \
            RAND + \
            LOG + \
            MALL + \
            DBG + \
            WVIEW
        #classdump

        # strings
        args = ["strings", BIN_PATH]
        strings = subprocess.check_output(args)
        strings = escape(strings.replace(BIN_DIR + "/", ""))
        STRINGS = strings.replace("\n", "</br>")

        return XML, BIN_NAME, ID, VER, SDK, PLTFM, MIN, LIBS, BIN_RES, STRINGS
    except Exception:
        PrintException("[ERROR] iOS Binary Analysis")
