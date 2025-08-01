# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import logging
import json
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.utils.html import escape

from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    find_java_source_folder,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)


@login_required
def run(request):
    """Find filename/content in source files (ajax response)."""
    try:
        if not is_md5(request.POST['md5']):
            raise ValueError('Invalid Hash')
        md5 = request.POST['md5']
        query = request.POST['q']
        code = request.POST['code']
        search_type = request.POST['search_type']
        if search_type not in ['content', 'filename']:
            return print_n_send_error_response(request,
                                               'Unknown search type',
                                               True)
        matches = set()
        base = Path(settings.UPLD_DIR) / md5
        if code == 'smali':
            src = base / 'smali_source'
        else:
            try:
                src = find_java_source_folder(base)[0]
            except StopIteration:
                msg = 'Invalid Directory Structure'
                return print_n_send_error_response(request, msg, True)

        exts = ['.java', '.kt', '.smali']
        files = [p for p in src.rglob('*') if p.suffix in exts]
        for fname in files:
            file_path = fname.as_posix()
            rpath = file_path.replace(src.as_posix(), '')
            rpath = rpath[1:]
            if search_type == 'content':
                dat = fname.read_text('utf-8', 'ignore')
                if query.lower() in dat.lower():
                    matches.add(escape(rpath))
            elif search_type == 'filename' and \
                    query.lower() in fname.name.lower():
                matches.add(escape(rpath))

        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': list(matches),
            'term': query,
            'found': str(flz),
            'search_type': search_type,
            'version': settings.MOBSF_VER,
        }
        return JsonResponse(json.dumps(context), safe=False)
    except Exception:
        logger.exception('Searching Failed')
        return print_n_send_error_response(
            request,
            'Searching Failed',
            True)
