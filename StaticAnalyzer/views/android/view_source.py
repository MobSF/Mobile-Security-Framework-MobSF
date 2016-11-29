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

from MobSF.utils import (
    PrintException
)

def run(request):
    """View the source of a file."""
    try:
        fil = ''
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if match and (
                request.GET['file'].endswith('.java') or
                request.GET['file'].endswith('.smali')
        ):
            fil = request.GET['file']
            md5 = request.GET['md5']
            if ("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil):
                return HttpResponseRedirect('/error/')
            else:
                if fil.endswith('.java'):
                    typ = request.GET['type']
                    if typ == 'eclipse':
                        src = os.path.join(settings.UPLD_DIR, md5+'/src/')
                    elif typ == 'studio':
                        src = os.path.join(settings.UPLD_DIR, md5+'/app/src/main/java/')
                    elif typ == 'apk':
                        src = os.path.join(settings.UPLD_DIR, md5+'/java_source/')
                    else:
                        return HttpResponseRedirect('/error/')
                elif fil.endswith('.smali'):
                    src = os.path.join(settings.UPLD_DIR, md5+'/smali_source/')
                sfile = os.path.join(src, fil)
                dat = ''
                with io.open(
                    sfile,
                    mode='r',
                    encoding="utf8",
                    errors="ignore"
                ) as file_pointer:
                    dat = file_pointer.read()
        else:
            return HttpResponseRedirect('/error/')
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'dat': dat
        }
        template = "static_analysis/view_source.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Viewing Source")
        return HttpResponseRedirect('/error/')
