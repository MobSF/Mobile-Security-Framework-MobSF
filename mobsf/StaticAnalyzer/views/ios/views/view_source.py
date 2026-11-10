# -*- coding: utf_8 -*-
"""iOS View Source."""
import io
import json
import logging
import ntpath
import os
import plistlib
from pathlib import Path

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.html import escape

from mobsf.MobSF.forms import FormUtil
from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    print_n_send_error_response,
    read_sqlite,
)
from mobsf.StaticAnalyzer.forms import (
    ViewSourceIOSApiForm,
    ViewSourceIOSForm,
)
from mobsf.StaticAnalyzer.views.common.js_analysis import (
    read_js_source_window,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


def set_ext_api(file_path):
    """Smart Function to set Extension."""
    ext = file_path.split('.')[-1]
    if ext in ('plist', 'entitlements'):
        return 'plist'
    elif ext == 'xml':
        return 'xml'
    elif ext in ['sqlitedb', 'db', 'sqlite']:
        return 'db'
    elif ext == 'm':
        return 'm'
    elif ext in ('js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs',
                 'bundle', 'jsbundle', 'html', 'htm', 'vue', 'svelte'):
        return 'js'
    else:
        return 'txt'


@login_required
def run(request, api=False):
    """View iOS Files."""
    try:
        logger.info('View iOS Source File')
        exp = 'Error Description'
        file_format = None
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
            return print_n_send_error_response(request, err, False, exp)
        base = Path(settings.UPLD_DIR) / md5_hash
        if mode == 'ipa':
            src1 = base / 'payload'
            src2 = base / 'Payload'
            if src1.exists():
                src = src1
            elif src2.exists():
                src = src2
            else:
                raise Exception('MobSF cannot find Payload directory')
        elif mode == 'ios':
            src = base
        sfile = src / fil
        sfile = sfile.as_posix()
        if not is_safe_path(src, sfile, fil) or is_pipe_or_link(sfile):
            msg = 'Path Traversal Detected!'
            if api:
                return {'error': 'Path Traversal Detected!'}
            return print_n_send_error_response(request, msg, False, exp)
        dat = ''
        win = {
            'start_line': 1,
            'end_line': 1,
            'total_lines': 1,
            'window_lines': 2000,
            'is_paged': False,
        }
        sql_dump = {}
        if typ == 'm':
            file_format = 'cpp'
            with io.open(sfile,
                         mode='r',
                         encoding='utf8',
                         errors='ignore') as flip:
                dat = flip.read()
        elif typ == 'js':
            file_format = 'javascript'
            win = read_js_source_window(
                Path(sfile),
                lines_param=request.GET.get('lines'),
                line_start=request.GET.get('line_start'),
                search_term=request.GET.get('q'),
            )
            dat = win['data']
        elif typ == 'xml':
            file_format = 'xml'
            with io.open(sfile,
                         mode='r',
                         encoding='utf8',
                         errors='ignore') as flip:
                dat = flip.read()
        elif typ == 'plist':
            file_format = 'json'
            try:
                with open(sfile, 'rb') as f:
                    # Attempt to load the plist, binary or XML
                    dat = plistlib.load(f)
                    # Convert the plist data to JSON for output
                    dat = json.dumps(dat, indent=4, sort_keys=True)
            except plistlib.InvalidFileException:
                # Handle invalid plist files (e.g., if it isn't binary or XML)
                file_format = 'xml'
                dat = Path(sfile).read_text()
            except Exception:
                dat = None
        elif typ == 'db':
            file_format = 'asciidoc'
            sql_dump = read_sqlite(sfile)
        elif typ == 'txt' and fil == 'classdump.txt':
            file_format = 'cpp'
            app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
            cls_dump_file = os.path.join(app_dir, 'classdump.txt')
            if is_file_exists(cls_dump_file):
                with io.open(cls_dump_file,  # lgtm [py/path-injection]
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
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'file_path': escape(fil),
            'app_type': escape(mode),
            'md5': md5_hash,
            'type': file_format,
            'data': dat,
            'start_line': win['start_line'],
            'end_line': win['end_line'],
            'total_lines': win['total_lines'],
            'window_lines': win['window_lines'],
            'is_paged': win['is_paged'],
            'sqlite': sql_dump,
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
        return print_n_send_error_response(request, msg, False, exp)
