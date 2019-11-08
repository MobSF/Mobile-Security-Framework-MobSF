# -*- coding: utf_8 -*-
"""List all smali files."""

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
    """Show the smali code."""
    try:
        logger.info('Listing Smali files')
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if match:
            md5 = request.GET['md5']
            src = os.path.join(settings.UPLD_DIR, md5 + '/smali_source/')
            html = ''
            # pylint: disable=unused-variable
            # Needed by os.walk
            for dir_name, _sub_dir, files in os.walk(src):
                for jfile in files:
                    if jfile.endswith('.smali'):
                        file_path = os.path.join(src, dir_name, jfile)
                        if '+' in jfile:
                            fp2 = os.path.join(
                                src, dir_name, jfile.replace('+', 'x'))
                            shutil.move(file_path, fp2)
                            file_path = fp2
                        fileparam = file_path.replace(src, '')
                        html += ('<tr><td><a href="../ViewSource/?'
                                 'file={}&type=apk&md5={}">{}</a>'
                                 '</td></tr>').format(
                                     escape(fileparam),
                                     md5,
                                     escape(fileparam))
        context = {
            'title': 'Smali Source',
            'files': html,
            'md5': md5,
        }

        template = 'static_analysis/smali.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Smali Files')
        return print_n_send_error_response(
            request,
            'Error Getting Smali Files')
