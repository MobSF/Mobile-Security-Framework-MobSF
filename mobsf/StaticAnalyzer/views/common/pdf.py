# -*- coding: utf_8 -*-
"""
Shared Functions.

PDF Generation
"""
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import platform

from django.http import HttpResponse
from django.template.loader import get_template

from xhtml2pdf import pisa
from xhtml2pdf.files import ResourceAccessPolicy

import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MobSF import settings
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
    get_ios_dashboard,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry as adb)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry as idb)
from mobsf.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_db_entry as wdb)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)
logging.getLogger('xhtml2pdf').setLevel(logging.ERROR)
ctype = 'application/json; charset=utf-8'


def get_pdf_resource_policy():
    """Return xhtml2pdf server policy confined to MobSF static and download dirs."""
    return ResourceAccessPolicy.server(
        base_dir=Path(settings.BASE_DIR) / 'static',
        extra_roots=(Path(settings.DWD_DIR),),
        allow_remote=False,
    )


def render_html_to_pdf(html):
    """Render HTML string to PDF bytes using xhtml2pdf."""
    output = BytesIO()
    status = pisa.CreatePDF(
        src=html,
        dest=output,
        encoding='UTF-8',
        resource_policy=get_pdf_resource_policy(),
    )
    if status.err:
        raise RuntimeError('xhtml2pdf reported errors while generating PDF')
    return output.getvalue()


@login_required
def pdf(request, checksum, api=False, jsonres=False):
    try:
        if not is_md5(checksum):
            if api:
                return {'error': 'Invalid Hash'}
            else:
                return HttpResponse(
                    json.dumps({'md5': 'Invalid Hash'}),
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
            vt = VirusTotal.VirusTotal(checksum)
            context['virus_total'] = vt.get_result(app_bin)
        # Get Local Base URL
        proto = 'file://'
        host_os = 'nix'
        if platform.system() == 'Windows':
            proto = 'file:///'
            host_os = 'windows'
        context['base_url'] = proto + Path(settings.BASE_DIR).as_posix()
        context['dwd_dir'] = proto + Path(settings.DWD_DIR).as_posix() + '/'
        context['host_os'] = host_os
        context['timestamp'] = RecentScansDB.objects.get(
            MD5=checksum).TIMESTAMP
        try:
            if api and jsonres:
                return {'report_dat': context}
            else:
                html = template.render(context)
                pdf_dat = render_html_to_pdf(html)
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
                err = {
                    'pdf_error': 'Cannot Generate PDF',
                    'err_details': str(exp)}
                return HttpResponse(
                    json.dumps(err),  # lgtm [py/stack-trace-exposure]
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
    context['average_cvss'] = get_avg_cvss(
        context['code_analysis'])
    context['appsec'] = get_android_dashboard(static_db)
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for android zip')
    else:
        logger.info('Generating PDF report for android apk')
    return context, get_template('pdf/android_report.html')


def handle_pdf_ios(static_db):
    logger.info('Fetching data from DB for '
                'PDF Report Generation (IOS)')
    context = idb(static_db)
    context['appsec'] = get_ios_dashboard(static_db)
    if context['file_name'].lower().endswith('.zip'):
        logger.info('Generating PDF report for IOS zip')
        context['average_cvss'] = get_avg_cvss(
            context['code_analysis'])
    else:
        logger.info('Generating PDF report for IOS ipa')
        context['average_cvss'] = get_avg_cvss(
            context['binary_analysis'])
    return context, get_template('pdf/ios_report.html')


def handle_pdf_win(static_db):
    logger.info(
        'Fetching data from DB for '
        'PDF Report Generation (APPX)')
    context = wdb(static_db)
    return context, get_template('pdf/windows_report.html')
