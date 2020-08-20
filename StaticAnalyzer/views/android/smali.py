# -*- coding: utf_8 -*-
"""List all smali files."""

import logging
import re
from pathlib import Path

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
        if not match:
            return print_n_send_error_response(request, 'Scan hash not found')
        skip_path = settings.SKIP_CLASS_PATH
        md5 = request.GET['md5']
        src = Path(settings.UPLD_DIR) / md5 / 'smali_source'
        smali_files = []
        for smali_file in src.rglob('*.smali'):
            smali_file = smali_file.as_posix()
            if any(skp in smali_file for skp in skip_path) is False:
                relative_path = smali_file.replace(src.as_posix() + '/', '')
                smali_files.append(escape(relative_path))
        context = {
            'title': 'Smali Source',
            'files': smali_files,
            'type': 'apk',
            'hash': md5,
            'version': settings.MOBSF_VER,
        }
        template = 'static_analysis/smali.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Smali Files')
        return print_n_send_error_response(
            request,
            'Error Getting Smali Files')
