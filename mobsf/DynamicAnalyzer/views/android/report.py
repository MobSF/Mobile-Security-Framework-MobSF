# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
import ntpath
import os
import io
import math

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
from django.utils.html import escape

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.android.analysis import (
    generate_download,
    get_screenshots,
    run_analysis,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    droidmon_api_analysis,
)
from mobsf.DynamicAnalyzer.views.android.tests_frida import (
    apimon_analysis,
    dependency_analysis,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_md5,
    is_path_traversal,
    is_safe_path,
    key,
    print_n_send_error_response,
    read_sqlite,
)
from mobsf.DynamicAnalyzer.views.android.scoring import (
    scoring
)
from mobsf.DynamicAnalyzer.views.android.permission_scoring import (
    permissionScoring
)


logger = logging.getLogger(__name__)
register.filter('key', key)

# Added Frida Log Analysis Function
def filter_frida_logs(app_dir, keywords):
    """
    Filter Frida logs for a list of keywords and save to a file for log analysis (remove noisy data).

    param app_dir: Directory containing the log files.
    param keywords: A dictionary or list of keywords to filter. If a dictionary, the values must be booleans.
    """
    frida_log_file = os.path.join(app_dir, 'mobsf_frida_out.txt')
    log_analysis_file = os.path.join(app_dir, 'log_analysis.txt')

    if not os.path.exists(frida_log_file):
        logger.warning(f"Frida log file {frida_log_file} does not exist.")
        return

    written_lines = set()  # To store lines that have been written, prevents duplicate data from being displayed

    try:
        with open(frida_log_file, 'r') as frida_logs, open(log_analysis_file, 'w') as log_analysis:
            for line in frida_logs:
                if isinstance(keywords, dict):  # filtering and writing
                    if any(keyword in line for keyword, enabled in keywords.items() if enabled):
                        if line not in written_lines:
                            log_analysis.write(line)
                            written_lines.add(line)
                elif isinstance(keywords, list):
                    if any(keyword in line for keyword in keywords):
                        if line not in written_lines:
                            log_analysis.write(line)
                            written_lines.add(line)
                else:
                    raise ValueError("Keywords must be either a dictionary or a list.")
    except Exception as e:
        logger.error(f"An error occurred while filtering Frida logs: {e}")



def view_report(request, checksum, api=False):
    """Dynamic Analysis Report Generation."""
    logger.info('Dynamic Analysis Report Generation')
    try:
        droidmon = {}
        apimon = {}
        b64_strings = []
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        app_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
        download_dir = settings.DWD_DIR
        tools_dir = settings.TOOLS_DIR
        if not is_file_exists(os.path.join(app_dir, 'logcat.txt')):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg, api)
        fd_log = os.path.join(app_dir, 'mobsf_frida_out.txt')
        droidmon = droidmon_api_analysis(app_dir, package)
        apimon, b64_strings = apimon_analysis(app_dir)
        deps = dependency_analysis(package, app_dir)
        analysis_result = run_analysis(app_dir, checksum, package)
        domains = analysis_result['domains']
        trk = Trackers.Trackers(app_dir, tools_dir)
        trackers = trk.get_trackers_domains_or_deps(domains, deps)
        generate_download(app_dir, checksum, download_dir, package)
        images = get_screenshots(checksum, download_dir)
        # Frida Log Analysis
        filter_frida_logs(app_dir, settings.FRIDA_LOG_ANALYSIS_KEYWORDS)
        log_analysis_file = os.path.join(app_dir, 'log_analysis.txt')  
        if is_file_exists(log_analysis_file):
            with open(log_analysis_file, 'r') as file:
                log_analysis = file.read()
        else:
            log_analysis = None

        # Frida Log scoring system
        mobsf_frida_out_file = os.path.join(app_dir, 'mobsf_frida_out.txt')
        if is_file_exists(mobsf_frida_out_file):
            malware_score = scoring(mobsf_frida_out_file)
        else:
            malware_score = None

        # Permissions AI Scoring
        permission_score = permissionScoring(settings.CSV_DIR, mobsf_frida_out_file)

        context = {'hash': checksum,
                   'emails': analysis_result['emails'],
                   'urls': analysis_result['urls'],
                   'domains': domains,
                   'clipboard': analysis_result['clipboard'],
                   'xml': analysis_result['xml'],
                   'sqlite': analysis_result['sqlite'],
                   'others': analysis_result['other_files'],
                   'tls_tests': analysis_result['tls_tests'],
                   'screenshots': images['screenshots'],
                   'activity_tester': images['activities'],
                   'exported_activity_tester': images['exported_activities'],
                   'droidmon': droidmon,
                   'apimon': apimon,
                   'base64_strings': b64_strings,
                   'trackers': trackers,
                   'frida_logs': is_file_exists(fd_log),
                   'runtime_dependencies': list(deps),
                   'package': package,
                   'version': settings.MOBSF_VER,
                   'title': 'Dynamic Analysis',
                   'log_analysis': log_analysis,
                   'malware_score': malware_score['malware_score'],
                   'critical_score': malware_score['critical_score'],
                   'critical_score_max': malware_score['critical_score_max'],
                   'suspicious_score': malware_score['suspicious_score'],
                   'suspicious_score_max': malware_score['suspicious_score_max'],
                   'permission_prediction': permission_score['prediction'],
                   'permission_accuracy': permission_score['accuracy'],
                   'overall_score': round((malware_score['malware_score'] + (permission_score['prediction'] * permission_score['accuracy'] * 100)) / 2, 2)}
        template = 'dynamic_analysis/android/dynamic_report.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Generating Dynamic Analysis Report. ' + str(exp)
        return print_n_send_error_response(request, err, api)


def view_file(request, api=False):
    """View File."""
    logger.info('Viewing File')
    try:
        typ = ''
        rtyp = ''
        dat = ''
        sql_dump = {}
        if api:
            fil = request.POST['file']
            md5_hash = request.POST['hash']
            typ = request.POST['type']
        else:
            fil = request.GET['file']
            md5_hash = request.GET['hash']
            typ = request.GET['type']
        if not is_md5(md5_hash):
            return print_n_send_error_response(request,
                                               'Invalid Parameters',
                                               api)
        src = os.path.join(
            settings.UPLD_DIR,
            md5_hash,
            'DYNAMIC_DeviceData/')
        sfile = os.path.join(src, fil)
        if not is_safe_path(src, sfile) or is_path_traversal(fil):
            err = 'Path Traversal Attack Detected'
            return print_n_send_error_response(request, err, api)
        with io.open(
                sfile,  # lgtm [py/path-injection]
                mode='r',
                encoding='ISO-8859-1') as flip:
            dat = flip.read()
        if fil.endswith('.xml') and typ == 'xml':
            rtyp = 'xml'
        elif typ == 'db':
            dat = None
            sql_dump = read_sqlite(sfile)
            rtyp = 'asciidoc'
        elif typ == 'others':
            rtyp = 'asciidoc'
        else:
            err = 'File type not supported'
            return print_n_send_error_response(request, err, api)
        fil = escape(ntpath.basename(fil))
        context = {
            'title': fil,
            'file': fil,
            'data': dat,
            'sqlite': sql_dump,
            'type': rtyp,
            'version': settings.MOBSF_VER,
        }
        template = 'general/view.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Viewing File')
        return print_n_send_error_response(
            request,
            'Error Viewing File',
            api)