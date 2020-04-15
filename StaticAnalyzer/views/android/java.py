# -*- coding: utf_8 -*-
"""List all java files."""

import logging
import os
import re
import shutil

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from MobSF.utils import print_n_send_error_response

logger = logging.getLogger(__name__)


def run(request):
    """Show the java code."""
    try:
        logger.info('Listing Java files')
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        typ = request.GET['type']
        if not match:
            return print_n_send_error_response(request, 'Scan hash not found')
        java_files = []
        md5 = request.GET['md5']
        if typ == 'eclipse':
            src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
        elif typ == 'studio':
            src = os.path.join(settings.UPLD_DIR, md5
                               + '/app/src/main/java/')
        elif typ == 'apk':
            src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
        else:
            return print_n_send_error_response(
                request,
                'Invalid Directory Structure')
        # pylint: disable=unused-variable
        # Needed by os.walk
        for dir_name, _sub_dir, files in os.walk(src):
            for jfile in files:
                if jfile.endswith('.java'):
                    file_path = os.path.join(src, dir_name, jfile)
                    if '+' in jfile:
                        fp2 = os.path.join(
                            src, dir_name, jfile.replace('+', 'x'))
                        shutil.move(file_path, fp2)
                        file_path = fp2
                    fileparam = file_path.replace(src, '')
                    if (any(re.search(cls, fileparam)
                            for cls in settings.SKIP_CLASSES) is False):
                        java_files.append(escape(fileparam))
        context = {
            'title': 'Java Source',
            'files': java_files,
            'hash': md5,
            'type': typ,
            'version': settings.MOBSF_VER,
        }
        template = 'static_analysis/java.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Java Files')
        return print_n_send_error_response(request, 'Error Getting Java Files')
