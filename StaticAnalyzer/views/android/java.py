# -*- coding: utf_8 -*-
"""List all java files."""

import re
import shutil
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)

def run(request):
    """Show the java code."""
    try:
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        typ = request.GET['type']
        if match:
            md5 = request.GET['md5']
            if typ == 'eclipse':
                src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
            elif typ == 'studio':
                src = os.path.join(settings.UPLD_DIR, md5 + '/app/src/main/java/')
            elif typ == 'apk':
                src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
            else:
                return HttpResponseRedirect('/error/')
            html = ''
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
                        if any(re.search(cls, fileparam) for cls in settings.SKIP_CLASSES) is False:
                            html += (
                                "<tr><td><a href='../ViewSource/?file=" + escape(fileparam) +
                                "&md5=" + md5 +
                                "&type=" + typ + "'>" +
                                escape(fileparam) + "</a></td></tr>"
                            )
        context = {
            'title': 'Java Source',
            'files': html,
            'md5': md5,
            'type': typ,
        }

        template = "static_analysis/java.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Getting Java Files")
        return HttpResponseRedirect('/error/')
