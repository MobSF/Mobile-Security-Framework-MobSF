# -*- coding: utf_8 -*-
"""List all java files."""

import re
import shutil
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)

def run(request, is_api=False):
    """Show the javacode."""
    md5_key = 'hash' if is_api  else 'md5'
    match = re.match('^[0-9a-f]{32}$', request.GET[md5_key])
    typ = request.GET['type']
    if not match:
        return HttpResponseNotFound()
    md5 = request.GET[md5_key]
    src = get_src(typ, md5)
    if not src:
        if is_api:
            return HttpResponseBadRequest()
        return HttpResponseRedirect('/error/')
    result = []
    # pylint: disable=unused-variable
    # Needed by os.walk
    for dir_name, sub_dir, files in os.walk(src):
        for jfile in files:
            if jfile.endswith(".java"):
                file_path = os.path.join(src, dir_name, jfile)
                if "+" in jfile:
                    fp2 = os.path.join(src, dir_name, jfile.replace("+", "x"))
                    shutil.move(file_path, fp2)
                    file_path = fp2
                fileparam = file_path.replace(src, '')
                if not any(re.search(cls, fileparam) for cls in settings.SKIP_CLASSES):
                    result.append(escape(fileparam))

    context = {
        'title': 'Java Source',
        'files': result,
        'md5': md5,
        'type': typ,
    }

    if not is_api:
        template = "static_analysis/java.html"
        return render(request, template, context)
    
    return JsonResponse(context)


def get_src(typ, md5):
    if typ == 'eclipse':
        src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
    elif typ == 'studio':
        src = os.path.join(settings.UPLD_DIR, md5 + '/app/src/main/java/')
    elif typ == 'apk':
        src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
    else:
        src = None
    return src

