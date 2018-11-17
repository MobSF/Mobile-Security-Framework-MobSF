# -*- coding: utf_8 -*-
"""View Source of a file."""

import io
import ntpath
import re
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from StaticAnalyzer.forms import (
    ViewSourceAndroidApiForm,
    ViewSourceAndroidForm
)

from MobSF.forms import (
    FormUtil
)

from MobSF.utils import (
    print_n_send_error_response
)



def run(request, api=False):
    """View the source of a file."""
    try:
        print("[INFO] View Android Source File")
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
            context = {
                'title': 'Error',
                'exp': 'Error Description',
                'doc': err
            }
            template = "general/error.html"
            return render(request, template, context, status=400)
        if fil.endswith('.java'):
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
            src = os.path.join(settings.UPLD_DIR,
                                md5 + '/')
        sfile = os.path.join(src, fil)
        dat = ''
        with io.open(
            sfile,
            mode='r',
            encoding="utf8",
            errors="ignore"
        ) as file_pointer:
            dat = file_pointer.read()
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'dat': dat
        }
        template = "static_analysis/view_source.html"
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)
