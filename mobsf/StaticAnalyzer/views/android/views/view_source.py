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
from mobsf.MobSF.utils import (
    is_safe_path,
    print_n_send_error_response,
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


def send_error(request, err, api_mode, json_resp, exp=None):
    """Send error message as dict or JSON."""
    if exp:
        res = print_n_send_error_response(request, err, api_mode, exp)
    else:
        res = print_n_send_error_response(request, err, api_mode)
    if json_resp:
        return send_json(res)
    return res


@login_required
def run(request, api=False):
    """View the source of a file."""
    json_resp = request.GET.get('json', '0') == '1'
    api_mode = api or json_resp
    try:
        logger.info('View Java Source File')
        exp = 'Error Description'
        if api:
            fil = request.POST['file']
            md5 = request.POST['hash']
            typ = request.POST['type']
            viewsource_form = ViewSourceAndroidApiForm(request.POST)
        else:
            fil = request.GET['file']
            md5 = request.GET['md5']
            typ = request.GET['type']
            viewsource_form = ViewSourceAndroidForm(request.GET)
        if not viewsource_form.is_valid():
            err = FormUtil.errors_message(viewsource_form)
            return send_error(request, err, api_mode, json_resp, exp)
        base = Path(settings.UPLD_DIR) / md5
        if typ == 'smali':
            src = base / 'smali_source'
            syntax = 'smali'
        else:
            try:
                src, syntax, _ = find_java_source_folder(base)
            except StopIteration:
                msg = 'Invalid directory or file extension'
                return send_error(request, msg, api_mode, json_resp)

        sfile = src / fil
        if not is_safe_path(src, sfile.as_posix(), fil):
            msg = 'Path Traversal Detected!'
            return send_error(request, msg, api_mode, json_resp)
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'data': sfile.read_text('utf-8', 'ignore'),
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
    except Exception as exp:
        logger.exception('Error Viewing Source')
        msg = str(exp)
        exp = exp.__doc__
        return send_error(request, msg, api_mode, json_resp, exp)
