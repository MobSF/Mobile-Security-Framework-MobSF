# -*- coding: utf_8 -*-
"""Generate Zipped downloads."""

import logging
import re
import shutil
from pathlib import Path

from django.conf import settings
from django.shortcuts import redirect

from mobsf.MobSF.utils import print_n_send_error_response

logger = logging.getLogger(__name__)


def run(request):
    """Generate downloads for apk, jar, aar, java zip and smali zip."""
    try:
        allowed = ('apk', 'smali', 'java', 'jar', 'aar')
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        match = re.match('^[0-9a-f]{32}$', md5)
        if (not match
                or file_type not in allowed):
            msg = 'Invalid download type or hash'
            logger.exception(msg)
            return print_n_send_error_response(request, msg)
        app_dir = Path(settings.UPLD_DIR) / md5
        dwd_dir = Path(settings.DWD_DIR)
        file_name = ''
        if file_type == 'java':
            # For Java zipped source code
            directory = app_dir / 'java_source'
            dwd_file = dwd_dir / f'{md5}-java'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-java.zip'
        elif file_type == 'smali':
            # For Smali zipped source code
            directory = app_dir / 'smali_source'
            dwd_file = dwd_dir / f'{md5}-smali'
            shutil.make_archive(
                dwd_file.as_posix(), 'zip', directory.as_posix())
            file_name = f'{md5}-smali.zip'
        elif file_type in ('apk', 'ipa', 'jar', 'aar'):
            # Binaries
            file_name = f'{md5}.{file_type}'
            src = app_dir / file_name
            dst = dwd_dir / file_name
            shutil.copy2(src.as_posix(), dst.as_posix())
        return redirect(f'/download/{file_name}')
    except Exception:
        msg = 'Generating Downloads'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
