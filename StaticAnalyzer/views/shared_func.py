# -*- coding: utf_8 -*-
"""
Module providing the shared functions for static analysis of iOS and Android
"""
import os
import hashlib
import io
import re
import json
import zipfile
import subprocess
import platform
import errno
import pdfkit

from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.template.loader import get_template

from MobSF.utils import PrintException
from MobSF.utils import python_list
from MobSF.utils import python_dict

from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.models import StaticAnalyzerIPA
from StaticAnalyzer.models import StaticAnalyzerIOSZIP
from StaticAnalyzer.models import StaticAnalyzerWindows

from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry
)

from StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry_ipa,
    get_context_from_db_entry_ios
)

def FileSize(APP_PATH):
    """Return the size of the file."""
    return round(float(os.path.getsize(APP_PATH)) / (1024 * 1024), 2)


def HashGen(APP_PATH):
    """Generate and return sha1 and sha256 as a tupel."""
    try:
        print "[INFO] Generating Hashes"
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        BLOCKSIZE = 65536
        with io.open(APP_PATH, mode='rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except:
        PrintException("[ERROR] Generating Hashes")


def Unzip(APP_PATH, EXT_PATH):
    print "[INFO] Unzipping"
    try:
        files = []
        with zipfile.ZipFile(APP_PATH, "r") as z:
            for fileinfo in z.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, unicode):
                    filename = unicode(filename, encoding="utf-8", errors="replace")
                files.append(filename)
                z.extract(fileinfo, EXT_PATH)
        return files
    except:
        PrintException("[ERROR] Unzipping Error")
        if platform.system() == "Windows":
            print "\n[INFO] Not yet Implemented."
        else:
            print "\n[INFO] Using the Default OS Unzip Utility."
            try:
                subprocess.call(
                    ['unzip', '-o', '-q', APP_PATH, '-d', EXT_PATH])
                dat = subprocess.check_output(['unzip', '-qq', '-l', APP_PATH])
                dat = dat.split('\n')
                x = ['Length   Date   Time   Name']
                x = x + dat
                return x
            except:
                PrintException("[ERROR] Unzipping Error")


def PDF(request):
    try:
        MD5 = request.GET['md5']
        TYP = request.GET['type']
        m = re.match('^[0-9a-f]{32}$', MD5)
        if m:
            if TYP in ['APK', 'ANDZIP']:
                DB = StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists():
                    print "\n[INFO] Fetching data from DB for PDF Report Generation (Android)"
                    context = get_context_from_db_entry(DB)
                    if TYP == 'APK':
                        template = get_template("pdf/static_analysis_pdf.html")
                    else:
                        template = get_template(
                            "pdf/static_analysis_zip_pdf.html")
                else:
                    return HttpResponse(json.dumps({"report": "Report not Found"}),
                                        content_type="application/json; charset=utf-8")
            elif re.findall('IPA|IOSZIP', TYP):
                if TYP == 'IPA':
                    DB = StaticAnalyzerIPA.objects.filter(MD5=MD5)
                    if DB.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS IPA)"
                        context = get_context_from_db_entry_ipa(DB)
                        template = get_template(
                            "pdf/ios_binary_analysis_pdf.html")
                    else:
                        return HttpResponse(json.dumps({"report": "Report not Found"}),
                                            content_type="application/json; charset=utf-8")
                elif TYP == 'IOSZIP':
                    DB = StaticAnalyzerIOSZIP.objects.filter(MD5=MD5)
                    if DB.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS ZIP)"
                        context = get_context_from_db_entry_ios(DB)
                        template = get_template(
                            "pdf/ios_source_analysis_pdf.html")
                    else:
                        return HttpResponse(json.dumps({"report": "Report not Found"}),
                                            content_type="application/json; charset=utf-8")
            elif re.findall('APPX', TYP):
                if TYP == 'APPX':
                    db_entry = StaticAnalyzerWindows.objects.filter(  # pylint: disable-msg=E1101
                        MD5=MD5
                    )
                    if db_entry.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (APPX)"

                        context = {
                            'title': db_entry[0].TITLE,
                            'name': db_entry[0].APP_NAME,
                            'pub_name': db_entry[0].PUB_NAME,
                            'size': db_entry[0].SIZE,
                            'md5': db_entry[0].MD5,
                            'sha1': db_entry[0].SHA1,
                            'sha256': db_entry[0].SHA256,
                            'bin_name': db_entry[0].BINNAME,
                            'version':  db_entry[0].VERSION,
                            'arch':  db_entry[0].ARCH,
                            'compiler_version':  db_entry[0].COMPILER_VERSION,
                            'visual_studio_version':  db_entry[0].VISUAL_STUDIO_VERSION,
                            'visual_studio_edition':  db_entry[0].VISUAL_STUDIO_EDITION,
                            'target_os':  db_entry[0].TARGET_OS,
                            'appx_dll_version':  db_entry[0].APPX_DLL_VERSION,
                            'proj_guid':  db_entry[0].PROJ_GUID,
                            'opti_tool':  db_entry[0].OPTI_TOOL,
                            'target_run':  db_entry[0].TARGET_RUN,
                            'files':  python_list(db_entry[0].FILES),
                            'strings': python_list(db_entry[0].STRINGS),
                            'bin_an_results': python_list(db_entry[0].BIN_AN_RESULTS),
                            'bin_an_warnings': python_list(db_entry[0].BIN_AN_WARNINGS)
                        }
                        template = get_template(
                            "pdf/windows_binary_analysis_pdf.html")
            else:
                return HttpResponse(json.dumps({"type": "Type is not Allowed"}),
                                    content_type="application/json; charset=utf-8")
            html = template.render(context)
            try:
                options = {
                    'page-size': 'A4',
                    'quiet': '',
                    'no-collate': '',
                    'margin-top': '0.50in',
                    'margin-right': '0.50in',
                    'margin-bottom': '0.50in',
                    'margin-left': '0.50in',
                    'encoding': "UTF-8",
                    'custom-header': [
                        ('Accept-Encoding', 'gzip')
                    ],
                    'no-outline': None
                }
                pdf = pdfkit.from_string(html, False, options=options)
                return HttpResponse(pdf, content_type='application/pdf')
            except Exception as exp:
                return HttpResponse(json.dumps({"pdf_error": "Cannot Generate PDF",
                                                "err_details": str(exp)}),
                                    content_type="application/json; charset=utf-8")

        else:
            return HttpResponse(json.dumps({"md5": "Invalid MD5"}),
                                content_type="application/json; charset=utf-8")
    except:

        PrintException("[ERROR] PDF Report Generation Error")
        return HttpResponseRedirect('/error/')
