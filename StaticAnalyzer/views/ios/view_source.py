# -*- coding: utf_8 -*-
"""iOS View Source."""
import io
import json
import logging
import ntpath
import os

import biplist

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.html import escape

from MobSF.forms import FormUtil
from MobSF.utils import (is_file_exists,
                         print_n_send_error_response,
                         read_sqlite)

from StaticAnalyzer.forms import ViewSourceIOSApiForm, ViewSourceIOSForm

logger = logging.getLogger(__name__)


def set_ext_api(file_path):
    """Smart Function to set Extenstion."""
    ext = file_path.split('.')[-1]
    if ext == 'plist':
        return 'plist'
    elif ext == 'xml':
        return 'xml'
    elif ext in ['sqlitedb', 'db', 'sqlite']:
        return 'db'
    elif ext == 'm':
        return 'm'
    else:
        return 'txt'


def run(request, api=False):
    """View iOS Files."""
    try:
        logger.info('View iOS Source File')
        file_format = 'cpp'
        if api:
            fil = request.POST['file']
            md5_hash = request.POST['hash']
            mode = request.POST['type']
            viewsource_form = ViewSourceIOSApiForm(request.POST)
        else:
            fil = request.GET['file']
            md5_hash = request.GET['md5']
            mode = request.GET['type']
            viewsource_form = ViewSourceIOSForm(request.GET)
        typ = set_ext_api(fil)
        if not viewsource_form.is_valid():
            err = FormUtil.errors_message(viewsource_form)
            if api:
                return err
            context = {
                'title': 'Error',
                'exp': 'Error Description',
                'doc': err,
            }
            template = 'general/error.html'
            return render(request, template, context, status=400)
        if mode == 'ipa':
            src = os.path.join(settings.UPLD_DIR,
                               md5_hash + '/Payload/')
        elif mode == 'ios':
            src = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        sfile = os.path.join(src, fil)
        dat = ''
        sql_dump = {}
        if typ == 'm':
            file_format = 'cpp'
            with io.open(sfile,
                         mode='r',
                         encoding='utf8',
                         errors='ignore') as flip:
                dat = flip.read()
        elif typ == 'xml':
            file_format = 'xml'
            with io.open(sfile,
                         mode='r',
                         encoding='utf8',
                         errors='ignore') as flip:
                dat = flip.read()
        elif typ == 'plist':
            file_format = 'json'
            dat = biplist.readPlist(sfile)
            try:
                dat = json.dumps(dat, indent=4, sort_keys=True)
            except Exception:
                pass
        elif typ == 'db':
            file_format = 'asciidoc'
            sql_dump = read_sqlite(sfile)
        elif typ == 'txt' and fil == 'classdump.txt':
            file_format = 'cpp'
            app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
            cls_dump_file = os.path.join(app_dir, 'classdump.txt')
            if is_file_exists(cls_dump_file):
                with io.open(cls_dump_file,
                             mode='r',
                             encoding='utf8',
                             errors='ignore') as flip:
                    dat = flip.read()
            else:
                dat = 'Class Dump result not Found'
        elif typ == 'txt':
            file_format = 'text'
            with io.open(sfile,
                         mode='r',
                         encoding='utf8',
                         errors='ignore') as flip:
                dat = flip.read()
        else:
            if api:
                return {'error': 'Invalid Parameters'}
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'type': file_format,
                   'dat': dat,
                   'sql': sql_dump}
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
