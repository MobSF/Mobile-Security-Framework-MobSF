# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import re
import shutil
import io
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)

def run(request):
    """Find in source files."""
    try:
        match = re.match('^[0-9a-f]{32}$', request.POST['md5'])
        if match:
            md5 = request.POST['md5']
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
                return HttpResponseRedirect('/error/')
            # pylint: disable=unused-variable
            # Needed by os.walk
            for dir_name, sub_dir, files in os.walk(src):
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
                            matches.append(
                                "<a href='../ViewSource/?file=" + escape(fileparam) +
                                "&md5=" + md5 +
                                "&type=apk'>" + escape(fileparam) + "</a>"
                            )
        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': matches,
            'term': query,
            'found' : str(flz)
        }
        template = "general/search.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Searching Failed")
        return HttpResponseRedirect('/error/')
