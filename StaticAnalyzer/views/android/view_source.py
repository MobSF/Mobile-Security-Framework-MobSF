# -*- coding: utf_8 -*-
"""View Source of a file."""

import logging
import ntpath
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from MobSF.forms import FormUtil
from MobSF.utils import (
    is_safe_path,
    print_n_send_error_response)

from StaticAnalyzer.forms import (ViewSourceAndroidApiForm,
                                  ViewSourceAndroidForm)

logger = logging.getLogger(__name__)


def run(request, api=False):
    """View the source of a file."""
    try:
        logger.info('View Android Source File')
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
            if api:
                return err
            return print_n_send_error_response(request, err, False, exp)

        base = Path(settings.UPLD_DIR) / md5
        syntax = 'java'
        if fil.endswith(('.java', '.kt')):
            if typ == 'eclipse':
                src = base / 'src'
            elif typ == 'studio':
                src = base / 'app' / 'src' / 'main' / 'java'
                kt = base / 'app' / 'src' / 'main' / 'kotlin'
                if not src.exists() and kt.exists():
                    src = kt
                    syntax = 'kotlin'
            elif typ == 'apk':
                src = base / 'java_source'
        elif fil.endswith('.smali'):
            src = base / 'smali_source'
            syntax = 'smali'
        else:
            msg = 'Not Found'
            doc = 'File not Found!'
            is_api = False
            if api:
                is_api = True
            return print_n_send_error_response(request, msg, is_api, doc)
        sfile = src / fil
        if not is_safe_path(src, sfile.as_posix()):
            msg = 'Path Traversal Detected!'
            if api:
                return {'error': 'Path Traversal Detected!'}
            return print_n_send_error_response(request, msg, False, exp)
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'dat': sfile.read_text('utf-8', 'ignore'),
            'type': syntax,
            'sql': {},
            'version': settings.MOBSF_VER,
        }
        template = 'general/view.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Error Viewing Source')
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)
