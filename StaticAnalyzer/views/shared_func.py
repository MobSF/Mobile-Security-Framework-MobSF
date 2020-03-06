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
                         upstream_proxy)

from StaticAnalyzer.models import (RecentScansDB,
                                   StaticAnalyzerAndroid,
                                   StaticAnalyzerIOS,
                                   StaticAnalyzerWindows)
from StaticAnalyzer.views.comparer import generic_compare
from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)
from StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_db_entry as wdb)

logger = logging.getLogger(__name__)
try:
    import pdfkit
except ImportError:
    logger.warning(
        'wkhtmltopdf is not installed/configured properly.'
        ' PDF Report Generation is disabled')
logger = logging.getLogger(__name__)
ctype = 'application/json; charset=utf-8'


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
        else:
            checksum = request.GET['md5']
        hash_match = re.match('^[0-9a-f]{32}$', checksum)
        if not hash_match:
            if api:
                return {'error': 'Invalid scan hash'}
            else:
                return HttpResponse(
                    json.dumps({'md5': 'Invalid scan hash'}),
                    content_type=ctype, status=500)
        # Do Lookups
        android_static_db = StaticAnalyzerAndroid.objects.filter(
            MD5=checksum)
        ios_static_db = StaticAnalyzerIOS.objects.filter(
            MD5=checksum)
        win_static_db = StaticAnalyzerWindows.objects.filter(
            MD5=checksum)

        if android_static_db.exists():
            context, template = handle_pdf_android(android_static_db)
        elif ios_static_db.exists():
            context, template = handle_pdf_ios(ios_static_db)
        elif win_static_db.exists():
            context, template = handle_pdf_win(win_static_db)
        else:
            if api:
                return {'report': 'Report not Found'}
            else:
                return HttpResponse(
                    json.dumps({'report': 'Report not Found'}),
                    content_type=ctype,
                    status=500)
        # Do VT Scan only on binaries
        context['virus_total'] = None
        ext = os.path.splitext(context['file_name'].lower())[1]
        if settings.VT_ENABLED and ext != '.zip':
            app_bin = os.path.join(
                settings.UPLD_DIR,
                checksum + '/',
                checksum + ext)
            vt = VirusTotal.VirusTotal()
            context['virus_total'] = vt.get_result(app_bin, checksum)
        # Get Local Base URL
        proto = 'file://'
        host_os = 'nix'
        if platform.system() == 'Windows':
            proto = 'file:///'
            host_os = 'windows'
        context['base_url'] = proto + settings.BASE_DIR
        context['dwd_dir'] = proto + settings.DWD_DIR
        context['host_os'] = host_os
        try:
            if api and jsonres:
                return {'report_dat': context}
            else:
                options = {
                    'page-size': 'Letter',
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
                # Added proxy support to wkhtmltopdf
                proxies, _ = upstream_proxy('https')
                if proxies['https']:
                    options['proxy'] = proxies['https']
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
                    content_type=ctype,
                    status=500)
    except Exception as exp:
        logger.exception('Error Generating PDF Report')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def handle_pdf_android(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (Android)')
    context = adb(static_db)
    context['average_cvss'], context[
        'security_score'] = score(context['code_analysis'])
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for android zip')
        template = get_template(
            'pdf/android_report.html')
    else:
        logger.info('Generating PDF report for android apk')
        template = get_template(
            'pdf/android_report.html')
    return context, template


def handle_pdf_ios(static_db):
    logger.info('Fetching data from DB for '
                'PDF Report Generation (IOS)')
    context = idb(static_db)
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for IOS zip')
        context['average_cvss'], context[
            'security_score'] = score(context['code_analysis'])
        template = get_template(
            'pdf/ios_report.html')
    else:
        logger.info('Generating PDF report for IOS ipa')
        context['average_cvss'], context[
            'security_score'] = score(
                context['binary_analysis'])
        template = get_template(
            'pdf/ios_report.html')
    return context, template


def handle_pdf_win(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (APPX)')
    context = wdb(static_db)
    template = get_template(
        'pdf/windows_report.html')
    return context, template


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
    """Static Analysis Rule Matcher."""
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
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)


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
