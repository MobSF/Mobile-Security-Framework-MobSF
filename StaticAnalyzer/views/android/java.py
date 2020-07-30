# -*- coding: utf_8 -*-
"""List all java files."""

import logging
import re
from pathlib import Path

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
        skip_path = settings.SKIP_CLASS_PATH
        md5 = request.GET['md5']
        upl = Path(settings.UPLD_DIR) / md5
        if typ == 'eclipse':
            src = upl / 'src'
        elif typ == 'studio':
            src = upl / 'app' / 'src' / 'main' / 'java'
            kt = upl / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'apk':
            src = upl / 'java_source'
        else:
            return print_n_send_error_response(
                request,
                'Invalid Directory Structure')
        for java_file in src.rglob('*'):
            if (
                (java_file.suffix in ('.java', '.kt')
                    and any(skp in java_file.as_posix()
                            for skp in skip_path) is False)
            ):
                relative_path = java_file.as_posix().replace(
                    src.as_posix() + '/', '')
                java_files.append(escape(relative_path))
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
