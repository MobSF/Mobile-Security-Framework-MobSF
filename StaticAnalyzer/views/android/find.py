# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import io
import logging
import os
import re
import shutil
import json

from django.conf import settings
from django.http import JsonResponse
from django.utils.html import escape

from MobSF.utils import print_n_send_error_response

logger = logging.getLogger(__name__)


def run(request):
    """Find Filename/Content in source files."""
    try:
        match = re.match('^[0-9a-f]{32}$', request.POST['md5'])
        if not match:
            raise ValueError('Invalid MD5 hash')
        md5 = request.POST['md5']
        query = request.POST['q']
        code = request.POST['code']
        search_type = request.POST['search_type']
        if search_type not in ['content', 'filename']:
            print_n_send_error_response(request, "Unknown search type")

        matches = []
        if code == 'java':
            src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
            ext = '.java'
        elif code == 'smali':
            src = os.path.join(settings.UPLD_DIR, md5 + '/smali_source/')
            ext = '.smali'
        else:
            err = 'Only Java/Smali files are allowed'
            return print_n_send_error_response(request,
                                               err)
        # pylint: disable=unused-variable
        # Needed by os.walk
        for dir_name, _sub_dir, files in os.walk(src):
            for jfile in files:
                if jfile.endswith(ext):
                    filename = jfile
                    file_path = os.path.join(src, dir_name, jfile)
                    if '+' in jfile:
                        filename = jfile.replace('+', 'x')
                        fp2 = os.path.join(
                            src, dir_name, filename)
                        shutil.move(file_path, fp2)
                        file_path = fp2
                    fileparam = escape(file_path.replace(src, ''))
                    if search_type == 'content':
                        with io.open(
                            file_path,
                            mode='r',
                            encoding='utf8',
                            errors='ignore',
                        ) as file_pointer:
                            dat = file_pointer.read()
                        if query in dat:
                            matches.append(fileparam)
                    elif search_type == 'filename':
                        if query in filename:
                            matches.append(fileparam)

        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': matches,
            'term': query,
            'found': str(flz),
            'search_type': search_type,
            'version': settings.MOBSF_VER,
        }
        return JsonResponse(json.dumps(context), safe=False)
    except Exception:
        logger.exception('Searching Failed')
        return print_n_send_error_response(request, 'Searching Failed')
