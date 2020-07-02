# -*- coding: utf_8 -*-
"""View Source of a file."""

import io
import logging
import ntpath
import os

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
        if fil.endswith(('.java', '.kt')):
            if typ == 'eclipse':
                src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
            elif typ == 'studio':
                src = os.path.join(
                    settings.UPLD_DIR, md5 + '/app/src/main/java/')
            elif typ == 'apk':
                src = os.path.join(
                    settings.UPLD_DIR, md5 + '/java_source/')
        elif fil.endswith('.smali'):
            src = os.path.join(settings.UPLD_DIR,
                               md5 + '/smali_source/')
        else:
            msg = 'Not Found'
            doc = 'File not Found!'
            is_api = False
            if api:
                is_api = True
            return print_n_send_error_response(request, msg, is_api, doc)
        sfile = os.path.join(src, fil)
        if not is_safe_path(src, sfile):
            msg = 'Path Traversal Detected!'
            if api:
                return {'error': 'Path Traversal Detected!'}
            return print_n_send_error_response(request, msg, False, exp)
        dat = ''
        with io.open(
            sfile,
            mode='r',
            encoding='utf8',
            errors='ignore',
        ) as file_pointer:
            dat = file_pointer.read()
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'dat': dat,
            'type': 'java',
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
