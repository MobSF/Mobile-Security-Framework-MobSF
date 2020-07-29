# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import logging
import re
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from MobSF.utils import print_n_send_error_response

logger = logging.getLogger(__name__)


def run(request):
    """Find in source files."""
    try:
        if not re.match('^[0-9a-f]{32}$', request.POST['md5']):
            return print_n_send_error_response(request, 'Searching Failed')
        md5 = request.POST['md5']
        query = request.POST['q']
        code = request.POST['code']
        matches = set()
        base = Path(settings.UPLD_DIR) / md5
        ext = '*.java'
        if code == 'eclipse':
            src = base / 'src'
        elif code == 'studio':
            src = base / 'app' / 'src' / 'main' / 'java'
            kt = base / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
                ext = '*.kt'
        elif code == 'apk':
            src = base / 'java_source'
        elif code == 'smali':
            src = base / 'smali_source'
            ext = '*.smali'
        else:
            err = 'Only Java/Kotlin/Smali files are allowed'
            return print_n_send_error_response(request, err)
        for fname in src.rglob(ext):
            file_path = fname.as_posix()
            rpath = file_path.replace(src.as_posix() + '/', '')
            dat = fname.read_text('utf-8', 'ignore')
            if query in dat:
                matches.add(escape(rpath))
        context = {
            'title': 'Search Results',
            'matches': matches,
            'term': query,
            'md5': md5,
            'typ': code,
            'found': str(len(matches)),
            'version': settings.MOBSF_VER,
        }
        template = 'general/search.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Searching Failed')
        return print_n_send_error_response(request, 'Searching Failed')
