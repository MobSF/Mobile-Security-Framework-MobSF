# -*- coding: utf_8 -*-
"""View Source of a file."""
import logging
import ntpath
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape
from django.http import JsonResponse

from mobsf.MobSF.forms import FormUtil
from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    find_java_source_folder,
)
from mobsf.StaticAnalyzer.forms import (
    ViewSourceAndroidApiForm,
    ViewSourceAndroidForm,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


def send_json(data):
    return JsonResponse(data, safe=False)


def send_error(request, err, api_mode, json_resp, exp=None, status=400):
    """Send error message as dict or JSON."""
    if json_resp:
        res = print_n_send_error_response(request, err, True)
        return JsonResponse(res, safe=False, status=status)
    if exp:
        res = print_n_send_error_response(request, err, api_mode, exp)
    else:
        res = print_n_send_error_response(request, err, api_mode)
    if api_mode:
        res['_status_code'] = status
    else:
        res.status_code = status
    return res


def get_xml_root(base, checksum):
    """Get the XML root from validated scan metadata."""
    scan = RecentScansDB.objects.filter(MD5=checksum).first()
    analysis = StaticAnalyzerAndroid.objects.filter(MD5=checksum).first()
    if not scan or not analysis:
        return None

    scan_type = scan.SCAN_TYPE
    app_type = analysis.APP_TYPE
    if app_type == 'apk' and scan_type in {'apk', 'aab', 'apks', 'xapk'}:
        return base / 'apktool_out'
    if app_type == 'aar' and scan_type == 'aar':
        return base
    if app_type == 'studio' and scan_type == 'zip':
        return base / 'app' / 'src' / 'main'
    if app_type == 'eclipse' and scan_type == 'zip':
        return base
    return None


@login_required
def run(request, api=False):
    """View the source of a file."""
    json_resp = request.GET.get('json', '0') == '1'
    api_mode = api or json_resp
    try:
        logger.info('View Java Source File')
        exp = 'Error Description'
        if api:
            viewsource_form = ViewSourceAndroidApiForm(request.POST)
        else:
            viewsource_form = ViewSourceAndroidForm(request.GET)
        if not viewsource_form.is_valid():
            err = FormUtil.errors_message(viewsource_form)
            return send_error(request, err, api_mode, json_resp, exp)
        cleaned = viewsource_form.cleaned_data
        fil = cleaned['file']
        typ = cleaned['type']
        md5 = cleaned['hash'] if api else cleaned['md5']
        base = Path(settings.UPLD_DIR) / md5
        if typ == 'smali':
            src = base / 'smali_source'
            syntax = 'smali'
        elif typ == 'xml':
            src = get_xml_root(base, md5)
            if src is None:
                msg = 'XML viewing is not supported for this scan type'
                return send_error(request, msg, api_mode, json_resp)
            syntax = 'xml'
        else:
            try:
                src, syntax, _ = find_java_source_folder(base)
            except StopIteration:
                msg = 'Invalid directory or file extension'
                return send_error(request, msg, api_mode, json_resp)

        if (not src.exists()  # lgtm [py/path-injection]
                or not src.is_dir()  # lgtm [py/path-injection]
                or is_pipe_or_link(src)):
            msg = 'Source directory not found'
            return send_error(
                request, msg, api_mode, json_resp, status=404)
        sfile = src / fil
        if not is_safe_path(src, sfile.as_posix(), fil):
            msg = 'Path Traversal Detected!'
            return send_error(request, msg, api_mode, json_resp)
        if (not sfile.exists()  # lgtm [py/path-injection]
                or not sfile.is_file()  # lgtm [py/path-injection]
                or is_pipe_or_link(sfile)):
            msg = 'Source file not found'
            return send_error(
                request, msg, api_mode, json_resp, status=404)
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'data': sfile.read_text(  # lgtm [py/path-injection]
                'utf-8', 'ignore'),
            'type': syntax,
            'sqlite': {},
            'version': settings.MOBSF_VER,
        }
        template = 'general/view.html'
        if json_resp:
            return send_json(context)
        if api_mode:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Error Viewing Source')
        return send_error(
            request, 'Error Viewing Source', api_mode, json_resp)
