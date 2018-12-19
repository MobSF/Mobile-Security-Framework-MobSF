# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import re
import shutil
import io
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponseNotFound, HttpResponseBadRequest, JsonResponse
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)

def run(request, is_api=False):
    """Find in source files."""
    try:
        md5_key = 'hash' if is_api else 'md5'
        match = re.match('^[0-9a-f]{32}$', request.POST[md5_key])
        include_path = request.POST.get('include_path', None)
        if not match:
            return HttpResponseNotFound()
        md5 = request.POST[md5_key]
        query = request.POST['q']
        code = request.POST['code']
        matches = []
        if code == 'java':
            src = os.path.join(settings.UPLD_DIR, md5+'/java_source/')
            ext = '.java'
        elif code == 'smali':
            src = os.path.join(settings.UPLD_DIR, md5+'/smali_source/')
            ext = '.smali'
        else:
            if is_api:
                return HttpResponseBadRequest()
            return HttpResponseRedirect('/error/')
        # pylint: disable=unused-variable
        # Needed by os.walk
        if include_path:
            include_path = include_path.split(',')
        for dir_name, sub_dir, files in os.walk(src):
            if is_api and include_path and len(include_path) > 0:
                if not filter_path(dir_name, include_path):
                    continue
            for jfile in files:
                if jfile.endswith(ext):
                    file_path = os.path.join(src, dir_name, jfile)
                    if "+" in jfile:
                        fp2 = os.path.join(src, dir_name, jfile.replace("+", "x"))
                        shutil.move(file_path, fp2)
                        file_path = fp2
                    fileparam = file_path.replace(src, '')
                    with io.open(
                        file_path,
                        mode='r',
                        encoding="utf8",
                        errors="ignore"
                    ) as file_pointer:
                        dat = file_pointer.read()
                    if query in dat:
                        matches.append(escape(fileparam))

        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': matches,
            'md5': md5,
            'term': query,
            'found' : str(flz)
        }

        if not is_api:
            template = "general/search.html"
            return render(request, template, context)

        return JsonResponse(context)
        
    except:
        PrintException("[ERROR] Searching Failed")
        return HttpResponseRedirect('/error/')


def filter_path(dir_name, include_path):
    for path in include_path:
        if path.strip() in dir_name:
            return True
    return False