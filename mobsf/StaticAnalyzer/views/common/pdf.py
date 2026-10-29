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
from urllib.parse import unquote, urlparse

from django.http import HttpResponse
from django.template.loader import get_template

from xhtml2pdf import pisa

import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MobSF import settings
from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
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
_ALLOWED_PDF_ASSET_EXTS = {
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ttf', '.otf',
}


def _fallback_pdf_icon():
    """Return the trusted default icon path for PDF reports."""
    icon = Path(settings.BASE_DIR).resolve() / 'static' / 'img' / 'no_icon.png'
    return icon.as_posix() if icon.is_file() else ''


def _uri_to_local_path(uri_str):
    """Extract a local path string from a file:// or relative URI."""
    parsed = urlparse(uri_str)
    if parsed.scheme and parsed.scheme.lower() != 'file':
        return None
    raw_path = unquote(parsed.path or '')
    if (os.name == 'nt'
            and len(raw_path) >= 3
            and raw_path[0] == '/'
            and raw_path[2] == ':'):
        raw_path = raw_path[1:]
    return raw_path


def pdf_link_callback(uri, rel=None):
    """Resolve PDF resources strictly to contained local static/download files."""
    if not isinstance(uri, str) or not uri.strip():
        return ''
    raw = uri.strip()
    raw_path = _uri_to_local_path(raw)
    # Block all network schemes (http, https, ftp, data, etc.) to prevent SSRF
    if raw_path is None:
        if raw.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            return _fallback_pdf_icon()
        return ''

    static_url = getattr(settings, 'STATIC_URL', '/static/') or '/static/'
    base_root = Path(settings.BASE_DIR).resolve()
    static_root = (base_root / 'static').resolve()
    dwd_root = Path(settings.DWD_DIR).resolve()

    candidates = []
    # Resolve relative CSS asset paths (e.g. ../webfonts/fa-solid-900.ttf)
    if rel and not Path(raw_path).is_absolute() and not raw_path.startswith('/'):
        rel_local = _uri_to_local_path(str(rel))
        if rel_local:
            rel_base = Path(rel_local)
            if rel_base.suffix:
                rel_base = rel_base.parent
            try:
                resolved_rel = (rel_base / raw_path).resolve()
                for allowed_root in (static_root, dwd_root):
                    try:
                        rel_part = resolved_rel.relative_to(allowed_root).as_posix()
                    except ValueError:
                        continue
                    if not is_path_traversal(rel_part):
                        candidates.append((allowed_root, resolved_rel, rel_part))
            except OSError:
                pass

    if raw_path.startswith(static_url):
        rel_static = raw_path[len(static_url):].lstrip('/')
        if not is_path_traversal(rel_static):
            candidates.append((
                static_root,
                (static_root / rel_static).resolve(),
                rel_static,
            ))
    elif raw_path.startswith('/download/'):
        rel_dwd = raw_path[len('/download/'):].lstrip('/')
        if not is_path_traversal(rel_dwd):
            candidates.append((
                dwd_root,
                (dwd_root / rel_dwd).resolve(),
                rel_dwd,
            ))
    else:
        target = Path(raw_path)
        if (not target.is_absolute()
                and '..' not in raw_path
                and not is_path_traversal(raw_path)):
            candidates.append((
                static_root,
                (static_root / raw_path).resolve(),
                raw_path,
            ))
            candidates.append((
                dwd_root,
                (dwd_root / raw_path).resolve(),
                raw_path,
            ))
        elif target.is_absolute():
            resolved = target.resolve()
            for allowed_root in (static_root, dwd_root):
                try:
                    rel_part = resolved.relative_to(allowed_root).as_posix()
                except ValueError:
                    continue
                if not is_path_traversal(rel_part):
                    candidates.append((allowed_root, resolved, rel_part))

    for safe_root, resolved_path, rel_part in candidates:
        if (is_safe_path(safe_root, resolved_path, rel_part)
                and resolved_path.is_file()
                and not is_pipe_or_link(resolved_path)
                and resolved_path.suffix.lower() in _ALLOWED_PDF_ASSET_EXTS):
            return resolved_path.as_posix()

    if raw_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
        return _fallback_pdf_icon()
    return ''


def render_html_to_pdf(html):
    """Render HTML string to PDF bytes using xhtml2pdf."""
    output = BytesIO()
    status = pisa.CreatePDF(
        src=html,
        dest=output,
        encoding='UTF-8',
        link_callback=pdf_link_callback,
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
        context['base_url'] = proto + settings.BASE_DIR
        context['dwd_dir'] = proto + settings.DWD_DIR
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
