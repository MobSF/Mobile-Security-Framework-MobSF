# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
import ntpath
import os
import io

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
from django.utils.html import escape

from DynamicAnalyzer.views.android.analysis import (generate_download,
                                                    get_screenshots,
                                                    run_analysis)
from DynamicAnalyzer.views.android.operations import (is_attack_pattern,
                                                      is_md5,
                                                      is_path_traversal)
from DynamicAnalyzer.views.android.tests_xposed import droidmon_api_analysis
from DynamicAnalyzer.views.android.tests_frida import apimon_analysis

from MobSF.utils import (is_file_exists,
                         print_n_send_error_response,
                         read_sqlite)


logger = logging.getLogger(__name__)


@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)


def view_report(request):
    """Dynamic Analysis Report Generation."""
    logger.info('Dynamic Analysis Report Generation')
    try:
        md5_hash = request.GET['hash']
        package = request.GET['package']
        droidmon = {}
        apimon = {}
        if (is_attack_pattern(package)
                or not is_md5(md5_hash)):
            return print_n_send_error_response(request,
                                               'Invalid Parameters')
        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        download_dir = settings.DWD_DIR
        if not is_file_exists(os.path.join(app_dir, 'logcat.txt')):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg)
        fd_log = os.path.join(app_dir, 'mobsf_frida_out.txt')
        droidmon = droidmon_api_analysis(app_dir, package)
        apimon = apimon_analysis(app_dir)
        analysis_result = run_analysis(app_dir, md5_hash, package)
        generate_download(app_dir, md5_hash, download_dir, package)
        images = get_screenshots(md5_hash, download_dir)
        context = {'md5': md5_hash,
                   'emails': analysis_result['emails'],
                   'urls': analysis_result['urls'],
                   'domains': analysis_result['domains'],
                   'clipboard': analysis_result['clipboard'],
                   'xml': analysis_result['xml'],
                   'sqlite': analysis_result['sqlite'],
                   'others': analysis_result['other_files'],
                   'screenshots': images['screenshots'],
                   'acttest': images['activities'],
                   'expacttest': images['exported_activities'],
                   'droidmon': droidmon,
                   'apimon': apimon,
                   'fdlog': is_file_exists(fd_log),
                   'package': package,
                   'title': 'Dynamic Analysis'}
        template = 'dynamic_analysis/android/dynamic_report.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Geneating Dynamic Analysis Report. ' + str(exp)
        return print_n_send_error_response(request, err)


def view_file(request):
    """View File."""
    logger.info('Viewing File')
    try:
        typ = ''
        rtyp = ''
        dat = ''
        sql_dump = {}
        fil = request.GET['file']
        md5_hash = request.GET['md5']
        typ = request.GET['type']
        if not is_md5(md5_hash):
            return print_n_send_error_response(request,
                                               'Invalid Parameters')
        if is_path_traversal(fil):
            err = 'Path Traversal Attack Detected'
            return print_n_send_error_response(request, err)
        src = os.path.join(
            settings.UPLD_DIR,
            md5_hash,
            'DYNAMIC_DeviceData/')
        sfile = os.path.join(src, fil)
        with io.open(sfile, mode='r', encoding='ISO-8859-1') as flip:
            dat = flip.read()
        if fil.endswith('.xml') and typ == 'xml':
            rtyp = 'xml'
        elif typ == 'db':
            sql_dump = read_sqlite(sfile)
            rtyp = 'asciidoc'
        elif typ == 'others':
            rtyp = 'asciidoc'
        else:
            err = 'File type not supported'
            return print_n_send_error_response(request, err)
        fil = escape(ntpath.basename(fil))
        context = {'title': fil,
                   'file': fil,
                   'dat': dat,
                   'sql': sql_dump,
                   'type': rtyp}
        template = 'general/view.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Viewing File')
        return print_n_send_error_response(request, 'Error Viewing File')
