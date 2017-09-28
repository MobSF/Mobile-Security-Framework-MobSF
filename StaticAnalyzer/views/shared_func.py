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

try:
    import pdfkit
except:
    print "[WARNING] wkhtmltopdf is not installed/configured properly. PDF Report Generation is disabled"
from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.template.loader import get_template
from django.utils.html import escape

from MobSF.utils import (
    print_n_send_error_response,
    PrintException,
    python_list
)
from MobSF import settings

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

import StaticAnalyzer.views.android.VirusTotal as VirusTotal

def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def hash_gen(app_path):
    """Generate and return sha1 and sha256 as a tupel."""
    try:
        print "[INFO] Generating Hashes"
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        block_size = 65536
        with io.open(app_path, mode='rb') as afile:
            buf = afile.read(block_size)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(block_size)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except:
        PrintException("[ERROR] Generating Hashes")


def unzip(app_path, ext_path):
    print "[INFO] Unzipping"
    try:
        files = []
        with zipfile.ZipFile(app_path, "r") as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, unicode):
                    filename = unicode(
                        filename, encoding="utf-8", errors="replace")
                files.append(filename)
                zipptr.extract(fileinfo, str(ext_path))
        return files
    except:
        PrintException("[ERROR] Unzipping Error")
        if platform.system() == "Windows":
            print "\n[INFO] Not yet Implemented."
        else:
            print "\n[INFO] Using the Default OS Unzip Utility."
            try:
                subprocess.call(
                    ['unzip', '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output(['unzip', '-qq', '-l', app_path])
                dat = dat.split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except:
                PrintException("[ERROR] Unzipping Error")


def pdf(request, api=False):
    try:
        if api:
            checksum = request.POST['hash']
            scan_type = request.POST['scan_type']
        else:
            checksum = request.GET['md5']
            scan_type = request.GET['type']
        hash_match = re.match('^[0-9a-f]{32}$', checksum)
        if hash_match:
            if scan_type.lower() in ['apk', 'andzip']:
                static_db = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
                if static_db.exists():
                    print "\n[INFO] Fetching data from DB for PDF Report Generation (Android)"
                    context = get_context_from_db_entry(static_db)
                    if scan_type.lower() == 'apk':
                        template = get_template("pdf/static_analysis_pdf.html")
                    else:
                        template = get_template(
                            "pdf/static_analysis_zip_pdf.html")
                else:
                    if api:
                        return {"report": "Report not Found"}
                    else:
                        return HttpResponse(json.dumps({"report": "Report not Found"}),
                                            content_type="application/json; charset=utf-8", status=500)
            elif re.findall('ipa|ioszip', scan_type.lower()):
                if scan_type.lower() == 'ipa':
                    static_db = StaticAnalyzerIPA.objects.filter(MD5=checksum)
                    if static_db.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS IPA)"
                        context = get_context_from_db_entry_ipa(static_db)
                        template = get_template(
                            "pdf/ios_binary_analysis_pdf.html")
                    else:
                        if api:
                            return {"report": "Report not Found"}
                        else:
                            return HttpResponse(json.dumps({"report": "Report not Found"}),
                                                content_type="application/json; charset=utf-8", status=500)
                elif scan_type.lower() == 'ioszip':
                    static_db = StaticAnalyzerIOSZIP.objects.filter(MD5=checksum)
                    if static_db.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS ZIP)"
                        context = get_context_from_db_entry_ios(static_db)
                        template = get_template(
                            "pdf/ios_source_analysis_pdf.html")
                    else:
                        if api:
                            return {"report": "Report not Found"}
                        else:
                            return HttpResponse(json.dumps({"report": "Report not Found"}),
                                                content_type="application/json; charset=utf-8", status=500)
            elif re.findall('appx', scan_type.lower()):
                if scan_type.lower() == 'appx':
                    db_entry = StaticAnalyzerWindows.objects.filter(# pylint: disable-msg=E1101
                        MD5=checksum
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
                if api:
                    return {"scan_type": "Type is not Allowed"}
                else:
                    return HttpResponse(json.dumps({"type": "Type is not Allowed"}),
                                        content_type="application/json; charset=utf-8", status=500)

            context['VT_RESULT'] = None
            if settings.VT_ENABLED:
                app_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
                vt = VirusTotal.VirusTotal()
                context['VT_RESULT'] = vt.get_result(
                    os.path.join(app_dir, checksum) + '.' + scan_type.lower(),
                    checksum
                )

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
                pdf_dat = pdfkit.from_string(html, False, options=options)
                if api:
                    return {"pdf_dat": pdf_dat}
                else:
                    return HttpResponse(pdf_dat, content_type='application/pdf')
            except Exception as exp:
                if api:
                    return {"error": "Cannot Generate PDF", "err_details": str(exp)}
                else:
                    return HttpResponse(json.dumps({"pdf_error": "Cannot Generate PDF",
                                                    "err_details": str(exp)}),
                                        content_type="application/json; charset=utf-8", status=500)

        else:
            if api:
                return {"error": "Invalid scan hash"}
            else:
                return HttpResponse(json.dumps({"md5": "Invalid MD5"}),
                                    content_type="application/json; charset=utf-8", status=500)
    except Exception as exp:
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def get_list_match_items(ruleset):
    """Get List of Match item"""
    match_list = []
    i = 1
    identifier = ruleset["type"]
    if ruleset["match"] == 'string_and_or':
        identifier = 'string_or'
    elif ruleset["match"] == 'string_or_and':
        identifier = 'string_and'
    while identifier + str(i) in ruleset:
        match_list.append(ruleset[identifier + str(i)])
        i = i + 1
        if identifier + str(i) in ruleset == False:
            break
    return match_list


def add_findings(findings, desc, file_path, level):
    """Add Code Analysis Findings"""
    if desc in findings:
        tmp_list = findings[desc]["path"]
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            findings[desc]["path"] = tmp_list
    else:
        findings[desc] = {"path": [escape(file_path)], "level": level}


def code_rule_matcher(findings, perms, data, file_path, code_rules):
    """Android Static Analysis Rule Matcher"""
    try:
        for rule in code_rules:

            # CASE CHECK
            if rule["input_case"] == "lower":
                tmp_data = data.lower()
            elif rule["input_case"] == "upper":
                tmp_data = data.upper()
            elif rule["input_case"] == "exact":
                tmp_data = data

            # MATCH TYPE
            if rule["type"] == "regex":
                if rule["match"] == 'single_regex':
                    if re.findall(rule["regex1"], tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'regex_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_findings(findings, rule[
                                         "desc"], file_path, rule["level"])
                            break
                elif rule["match"] == 'regex_and_perm':
                    if (rule["perm"] in perms) and (re.findall(rule["regex1"], tmp_data)):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                else:
                    print "\n[ERROR] Code Regex Rule Match Error\n" + rule

            elif rule["type"] == "string":
                if rule["match"] == 'single_string':
                    if rule["string1"] in tmp_data:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if match in tmp_data:
                            add_findings(findings, rule[
                                         "desc"], file_path, rule["level"])
                            break
                elif rule["match"] == 'string_and_or':
                    match_list = get_list_match_items(rule)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or_and':
                    match_list = get_list_match_items(rule)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_and_perm':
                    if (rule["perm"] in perms) and (rule["string1"] in tmp_data):
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                elif rule["match"] == 'string_or_and_perm':
                    match_list = get_list_match_items(rule)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (rule["perm"] in perms) and string_or_ps:
                        add_findings(findings, rule[
                                     "desc"], file_path, rule["level"])
                else:
                    print "\n[ERROR] Code String Rule Match Error\n" + rule
            else:
                print "\n[ERROR] Code Rule Error\n", + rule
    except:
        PrintException("[ERROR] Error in Code Rule Processing")


def add_apis(api_findings, desc, file_path):
    """Add API Findings"""
    if desc in api_findings:
        tmp_list = api_findings[desc]["path"]
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            api_findings[desc]["path"] = tmp_list
    else:
        api_findings[desc] = {"path": [escape(file_path)]}


def api_rule_matcher(api_findings, perms, data, file_path, api_rules):
    """Android API Analysis Rule Matcher"""
    try:
        for api in api_rules:

            # CASE CHECK
            if api["input_case"] == "lower":
                tmp_data = data.lower()
            elif api["input_case"] == "upper":
                tmp_data = data.upper()
            elif api["input_case"] == "exact":
                tmp_data = data

            # MATCH TYPE
            if api["type"] == "regex":
                if api["match"] == 'single_regex':
                    if re.findall(api["regex1"], tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'regex_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_apis(api_findings, api["desc"], file_path)
                            break
                elif api["match"] == 'regex_and_perm':
                    if (api["perm"] in perms) and (re.findall(api["regex1"], tmp_data)):
                        add_apis(api_findings, api["desc"], file_path)
                else:
                    print "\n[ERROR] API Regex Rule Match Error\n" + api

            elif api["type"] == "string":
                if api["match"] == 'single_string':
                    if api["string1"] in tmp_data:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if match in tmp_data:
                            add_apis(api_findings, api["desc"], file_path)
                            break
                elif api["match"] == 'string_and_or':
                    match_list = get_list_match_items(api)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or_and':
                    match_list = get_list_match_items(api)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_and_perm':
                    if (api["perm"] in perms) and (api["string1"] in tmp_data):
                        add_apis(api_findings, api["desc"], file_path)
                elif api["match"] == 'string_or_and_perm':
                    match_list = get_list_match_items(api)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (api["perm"] in perms) and string_or_ps:
                        add_apis(api_findings, api["desc"], file_path)
                else:
                    print "\n[ERROR] API String Rule Match Error\n" + api
            else:
                print "\n[ERROR] API Rule Error\n", + api
    except:
        PrintException("[ERROR] Error in API Rule Processing")


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code"""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])'
            ur'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE
    )
    urllist = re.findall(pattern, dat.lower())
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {"urls": urls, "path": escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w.]+')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {"emails": emails, "path": escape(relative_path)})
    return urllist, url_n_file, email_n_file
