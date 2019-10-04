# -*- coding: utf_8 -*-
"""
Shared Functions.

Module providing the shared functions for static analysis of iOS and Android
"""
import hashlib
import io
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse

import requests

import MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.http import HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from django.utils.html import escape

from MobSF import settings
from MobSF.utils import (print_n_send_error_response,
                         python_list,
                         upstream_proxy)

from StaticAnalyzer.models import (RecentScansDB, StaticAnalyzerAndroid,
                                   StaticAnalyzerIOSZIP, StaticAnalyzerIPA,
                                   StaticAnalyzerWindows)
from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry)
from StaticAnalyzer.views.comparer import generic_compare
from StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry_ios, get_context_from_db_entry_ipa)

logger = logging.getLogger(__name__)
try:
    import pdfkit
except ImportError:
    logger.warning(
        'wkhtmltopdf is not installed/configured properly.'
        ' PDF Report Generation is disabled')
logger = logging.getLogger(__name__)


def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def hash_gen(app_path) -> tuple:
    """Generate and return sha1 and sha256 as a tuple."""
    try:
        logger.info('Generating Hashes')
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
    except Exception:
        logger.exception('Generating Hashes')


def unzip(app_path, ext_path):
    logger.info('Unzipping')
    try:
        files = []
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, str):
                    filename = str(
                        filename, encoding='utf-8', errors='replace')
                files.append(filename)
                zipptr.extract(filename, ext_path)
        return files
    except Exception:
        logger.exception('Unzipping Error')
        if platform.system() == 'Windows':
            logger.info('Not yet Implemented.')
        else:
            logger.info('Using the Default OS Unzip Utility.')
            try:
                unzip_b = shutil.which('unzip')
                subprocess.call(
                    [unzip_b, '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
                dat = dat.decode('utf-8').split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception:
                logger.exception('Unzipping Error')


def pdf(request, api=False, jsonres=False):
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
                    logger.info(
                        'Fetching data from DB for '
                        'PDF Report Generation (Android)')
                    context = get_context_from_db_entry(static_db)
                    context['average_cvss'], context[
                        'security_score'] = score(context['findings'])
                    if scan_type.lower() == 'apk':
                        template = get_template(
                            'pdf/android_binary_analysis.pdf.html')
                    else:
                        template = get_template(
                            'pdf/android_source_analysis_pdf.html')
                else:
                    if api:
                        return {'report': 'Report not Found'}
                    else:
                        return HttpResponse(
                            json.dumps({'report': 'Report not Found'}),
                            content_type='application/json; charset=utf-8',
                            status=500)
            elif scan_type.lower() in ['ipa', 'ioszip']:
                if scan_type.lower() == 'ipa':
                    static_db = StaticAnalyzerIPA.objects.filter(MD5=checksum)
                    if static_db.exists():
                        logger.info(
                            'Fetching data from DB for '
                            'PDF Report Generation (IOS IPA)')
                        context = get_context_from_db_entry_ipa(static_db)
                        context['average_cvss'], context[
                            'security_score'] = score(context['bin_anal'])
                        template = get_template(
                            'pdf/ios_binary_analysis_pdf.html')
                    else:
                        if api:
                            return {'report': 'Report not Found'}
                        else:
                            return HttpResponse(
                                json.dumps({'report': 'Report not Found'}),
                                content_type='application/json; charset=utf-8',
                                status=500)
                elif scan_type.lower() == 'ioszip':
                    static_db = StaticAnalyzerIOSZIP.objects.filter(
                        MD5=checksum)
                    if static_db.exists():
                        logger.info(
                            'Fetching data from DB for '
                            'PDF Report Generation (IOS ZIP)')
                        context = get_context_from_db_entry_ios(static_db)
                        context['average_cvss'], context[
                            'security_score'] = score(context['insecure'])
                        template = get_template(
                            'pdf/ios_source_analysis_pdf.html')
                    else:
                        if api:
                            return {'report': 'Report not Found'}
                        else:
                            return HttpResponse(
                                json.dumps({'report': 'Report not Found'}),
                                content_type='application/json; charset=utf-8',
                                status=500)
            elif 'appx' == scan_type.lower():
                if scan_type.lower() == 'appx':
                    db_entry = StaticAnalyzerWindows.objects.filter(
                        MD5=checksum,
                    )
                    if db_entry.exists():
                        logger.info(
                            'Fetching data from DB for '
                            'PDF Report Generation (APPX)')

                        context = {
                            'title': db_entry[0].TITLE,
                            'name': db_entry[0].APP_NAME,
                            'pub_name': db_entry[0].PUB_NAME,
                            'size': db_entry[0].SIZE,
                            'md5': db_entry[0].MD5,
                            'sha1': db_entry[0].SHA1,
                            'sha256': db_entry[0].SHA256,
                            'bin_name': db_entry[0].BINNAME,
                            'version': db_entry[0].VERSION,
                            'arch': db_entry[0].ARCH,
                            'compiler_version': db_entry[0].COMPILER_VERSION,
                            'visual_studio_version':
                                db_entry[0].VISUAL_STUDIO_VERSION,
                            'visual_studio_edition':
                                db_entry[0].VISUAL_STUDIO_EDITION,
                            'target_os': db_entry[0].TARGET_OS,
                            'appx_dll_version': db_entry[0].APPX_DLL_VERSION,
                            'proj_guid': db_entry[0].PROJ_GUID,
                            'opti_tool': db_entry[0].OPTI_TOOL,
                            'target_run': db_entry[0].TARGET_RUN,
                            'files': python_list(db_entry[0].FILES),
                            'strings': python_list(db_entry[0].STRINGS),
                            'bin_an_results':
                                python_list(db_entry[0].BIN_AN_RESULTS),
                            'bin_an_warnings':
                                python_list(db_entry[0].BIN_AN_WARNINGS),
                        }
                        template = get_template(
                            'pdf/windows_binary_analysis_pdf.html')
            else:
                if api:
                    return {'scan_type': 'Type is not Allowed'}
                else:
                    return HttpResponse(
                        json.dumps({'type': 'Type is not Allowed'}),
                        content_type='application/json; charset=utf-8',
                        status=500)

            context['VT_RESULT'] = None
            if settings.VT_ENABLED:
                app_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
                vt = VirusTotal.VirusTotal()
                if 'zip' in scan_type.lower():
                    context['VT_RESULT'] = None
                else:
                    context['VT_RESULT'] = vt.get_result(
                        os.path.join(app_dir, checksum)
                        + '.' + scan_type.lower(),
                        checksum)
            try:
                if api and jsonres:
                    return {'report_dat': context}
                else:
                    options = {
                        'page-size': 'A4',
                        'quiet': '',
                        'no-collate': '',
                        'margin-top': '0.50in',
                        'margin-right': '0.50in',
                        'margin-bottom': '0.50in',
                        'margin-left': '0.50in',
                        'encoding': 'UTF-8',
                        'custom-header': [
                            ('Accept-Encoding', 'gzip'),
                        ],
                        'no-outline': None,
                    }
                    html = template.render(context)
                    pdf_dat = pdfkit.from_string(html, False, options=options)
                    if api:
                        return {'pdf_dat': pdf_dat}
                    return HttpResponse(pdf_dat,
                                        content_type='application/pdf')
            except Exception as exp:
                logger.exception('Error Generating PDF Report')
                if api:
                    return {
                        'error': 'Cannot Generate PDF/JSON',
                        'err_details': str(exp)}
                else:
                    return HttpResponse(
                        json.dumps({'pdf_error': 'Cannot Generate PDF',
                                    'err_details': str(exp)}),
                        content_type='application/json; charset=utf-8',
                        status=500)

        else:
            if api:
                return {'error': 'Invalid scan hash'}
            else:
                return HttpResponse(
                    json.dumps({'md5': 'Invalid MD5'}),
                    content_type='application/json; charset=utf-8', status=500)
    except Exception as exp:
        logger.exception('Error Generating PDF Report')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def get_list_match_items(ruleset):
    """Get List of Match item."""
    match_list = []
    i = 1
    identifier = ruleset['type']
    if ruleset['match'] == 'string_and_or':
        identifier = 'string_or'
    elif ruleset['match'] == 'string_or_and':
        identifier = 'string_and'
    while identifier + str(i) in ruleset:
        match_list.append(ruleset[identifier + str(i)])
        i = i + 1
        if not (identifier + str(i)) in ruleset:
            break
    return match_list


def add_findings(findings, desc, file_path, rule):
    """Add Code Analysis Findings."""
    if desc in findings:
        tmp_list = findings[desc]['path']
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            findings[desc]['path'] = tmp_list
    else:
        findings[desc] = {'path': [escape(file_path)],
                          'level': rule['level'],
                          'cvss': rule['cvss'],
                          'cwe': rule['cwe'],
                          'owasp': rule['owasp']}


def code_rule_matcher(findings, perms, data, file_path, code_rules):
    """Android Static Analysis Rule Matcher."""
    try:
        for rule in code_rules:

            # CASE CHECK
            if rule['input_case'] == 'lower':
                tmp_data = data.lower()
            elif rule['input_case'] == 'upper':
                tmp_data = data.upper()
            elif rule['input_case'] == 'exact':
                tmp_data = data

            # MATCH TYPE
            if rule['type'] == 'regex':
                if rule['match'] == 'single_regex':
                    if re.findall(rule['regex1'], tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'regex_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_findings(findings, rule[
                                         'desc'], file_path, rule)
                            break
                elif rule['match'] == 'regex_and_perm':
                    if (rule['perm'] in perms
                            and re.findall(rule['regex1'], tmp_data)):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                else:
                    logger.error('Code Regex Rule Match Error\n %s', rule)

            elif rule['type'] == 'string':
                if rule['match'] == 'single_string':
                    if rule['string1'] in tmp_data:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'string_or':
                    match_list = get_list_match_items(rule)
                    for match in match_list:
                        if match in tmp_data:
                            add_findings(findings, rule[
                                         'desc'], file_path, rule)
                            break
                elif rule['match'] == 'string_and_or':
                    match_list = get_list_match_items(rule)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'string_or_and':
                    match_list = get_list_match_items(rule)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'string_and_perm':
                    if (rule['perm'] in perms
                            and rule['string1'] in tmp_data):
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                elif rule['match'] == 'string_or_and_perm':
                    match_list = get_list_match_items(rule)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (rule['perm'] in perms) and string_or_ps:
                        add_findings(findings, rule[
                                     'desc'], file_path, rule)
                else:
                    logger.error('Code String Rule Match Error\n%s', rule)
            else:
                logger.error('Code Rule Error\n%s', rule)
    except Exception:
        logger.exception('Error in Code Rule Processing')


def add_apis(api_findings, desc, file_path):
    """Add API Findings."""
    if desc in api_findings:
        tmp_list = api_findings[desc]['path']
        if escape(file_path) not in tmp_list:
            tmp_list.append(escape(file_path))
            api_findings[desc]['path'] = tmp_list
    else:
        api_findings[desc] = {'path': [escape(file_path)]}


def api_rule_matcher(api_findings, perms, data, file_path, api_rules):
    """Android API Analysis Rule Matcher."""
    try:
        for api in api_rules:

            # CASE CHECK
            if api['input_case'] == 'lower':
                tmp_data = data.lower()
            elif api['input_case'] == 'upper':
                tmp_data = data.upper()
            elif api['input_case'] == 'exact':
                tmp_data = data

            # MATCH TYPE
            if api['type'] == 'regex':
                if api['match'] == 'single_regex':
                    if re.findall(api['regex1'], tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'regex_and':
                    and_match_rgx = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if bool(re.findall(match, tmp_data)) is False:
                            and_match_rgx = False
                            break
                    if and_match_rgx:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'regex_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if re.findall(match, tmp_data):
                            add_apis(api_findings, api['desc'], file_path)
                            break
                elif api['match'] == 'regex_and_perm':
                    if (api['perm'] in perms
                            and re.findall(api['regex1'], tmp_data)):
                        add_apis(api_findings, api['desc'], file_path)
                else:
                    logger.error('API Regex Rule Match Error\n %s', api)

            elif api['type'] == 'string':
                if api['match'] == 'single_string':
                    if api['string1'] in tmp_data:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'string_and':
                    and_match_str = True
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if (match in tmp_data) is False:
                            and_match_str = False
                            break
                    if and_match_str:
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'string_or':
                    match_list = get_list_match_items(api)
                    for match in match_list:
                        if match in tmp_data:
                            add_apis(api_findings, api['desc'], file_path)
                            break
                elif api['match'] == 'string_and_or':
                    match_list = get_list_match_items(api)
                    string_or_stat = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_stat = True
                            break
                    if string_or_stat and (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'string_or_and':
                    match_list = get_list_match_items(api)
                    string_and_stat = True
                    for match in match_list:
                        if match in tmp_data is False:
                            string_and_stat = False
                            break
                    if string_and_stat or (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'string_and_perm':
                    if (api['perm'] in perms) and (api['string1'] in tmp_data):
                        add_apis(api_findings, api['desc'], file_path)
                elif api['match'] == 'string_or_and_perm':
                    match_list = get_list_match_items(api)
                    string_or_ps = False
                    for match in match_list:
                        if match in tmp_data:
                            string_or_ps = True
                            break
                    if (api['perm'] in perms) and string_or_ps:
                        add_apis(api_findings, api['desc'], file_path)
                else:
                    logger.error('API String Rule Match Error\n%s', api)
            else:
                logger.error('API Rule Error\n%s', api)
    except Exception:
        logger.exception('Error in API Rule Processing')


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            r'((?:https?://|s?ftps?://|'
            r'file://|javascript:|data:|www\d{0,3}[.])'
            r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE)
    urllist = re.findall(pattern, dat)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {'urls': urls, 'path': escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w]{2,}')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {'emails': emails, 'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


# This is just the first sanity check that triggers generic_compare
def compare_apps(request, hash1: str, hash2: str):
    if hash1 == hash2:
        error_msg = 'Results with same hash cannot be compared'
        return print_n_send_error_response(request, error_msg, False)
    logger.info(
        'Starting App compare for %s and %s', hash1, hash2)
    return generic_compare(request, hash1, hash2)


def score(findings):
    # Score Apps based on AVG CVSS Score
    cvss_scores = []
    avg_cvss = 0
    app_score = 100
    if isinstance(findings, list):
        for finding in findings:
            if 'cvss' in finding:
                if finding['cvss'] != 0:
                    cvss_scores.append(finding['cvss'])
            if finding['level'] == 'high':
                app_score = app_score - 15
            elif finding['level'] == 'warning':
                app_score = app_score - 10
            elif finding['level'] == 'good':
                app_score = app_score + 5
    else:
        for _, finding in findings.items():
            if 'cvss' in finding:
                if finding['cvss'] != 0:
                    cvss_scores.append(finding['cvss'])
            if finding['level'] == 'high':
                app_score = app_score - 15
            elif finding['level'] == 'warning':
                app_score = app_score - 10
            elif finding['level'] == 'good':
                app_score = app_score + 5
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if app_score < 0:
        app_score = 10
    elif app_score > 100:
        app_score = 100
    return avg_cvss, app_score


def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TS=tms)


def open_firebase(url):
    # Detect Open Firebase Database
    try:
        purl = urlparse(url)
        base_url = '{}://{}/.json'.format(purl.scheme, purl.netloc)
        proxies, verify = upstream_proxy('https')
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
                           ' AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/39.0.2171.95 Safari/537.36')}
        resp = requests.get(base_url, headers=headers,
                            proxies=proxies, verify=verify)
        if resp.status_code == 200:
            return base_url, True
    except Exception:
        logger.warning('Open Firebase DB detection failed.')
    return url, False


def firebase_analysis(urls):
    # Detect Firebase URL
    firebase_db = []
    logger.info('Detecting Firebase URL(s)')
    for url in urls:
        if 'firebaseio.com' in url:
            returl, is_open = open_firebase(url)
            fbdic = {'url': returl, 'open': is_open}
            if fbdic not in firebase_db:
                firebase_db.append(fbdic)
    return firebase_db
