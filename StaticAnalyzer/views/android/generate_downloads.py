# -*- coding: utf_8 -*-
"""Generate Zipped downloads."""

import logging
import os
import re
import shutil

from django.conf import settings
from django.shortcuts import redirect

from MobSF.utils import print_n_send_error_response

logger = logging.getLogger(__name__)


def run(request):
    """Generate downloads for apk, java and smali."""
    try:
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        match = re.match('^[0-9a-f]{32}$', md5)
        if not match and file_type not in ['apk', 'smali', 'java']:
            logger.exception('Invalid options')
            return print_n_send_error_response(request,
                                               'Invalid options')
        app_dir = os.path.join(settings.UPLD_DIR, md5)
        file_name = ''
        if file_type == 'java':
            # For Java
            file_name = md5 + '-java'
            directory = os.path.join(app_dir, 'java_source/')
            dwd_dir = os.path.join(settings.DWD_DIR, file_name)
            shutil.make_archive(dwd_dir, 'zip', directory)
            file_name = file_name + '.zip'
        elif file_type == 'smali':
            # For Smali
            file_name = md5 + '-smali'
            directory = os.path.join(app_dir, 'smali_source/')
            dwd_dir = os.path.join(settings.DWD_DIR, file_name)
            shutil.make_archive(dwd_dir, 'zip', directory)
            file_name = file_name + '.zip'
        elif file_type == 'apk':
            file_name = md5 + '.apk'
            src = os.path.join(app_dir, file_name)
            dst = os.path.join(settings.DWD_DIR, file_name)
            shutil.copy2(src, dst)
        return redirect('/download/' + file_name)
    except Exception:
        logger.exception('Generating Downloads')
        return print_n_send_error_response(request,
                                           'Generating Downloads')
