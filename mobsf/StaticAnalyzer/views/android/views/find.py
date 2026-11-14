# -*- coding: utf_8 -*-
"""Find in java or smali files."""

import logging
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.utils.html import escape

from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.android.views.source_tree import (
    get_source_root,
)
from mobsf.StaticAnalyzer.views.common.js_analysis import (
    cached_js_source_files,
    list_js_source_files,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)
SOURCE_EXTS = ('.java', '.kt', '.smali')
READ_CHUNK = 4 * 1024 * 1024
SEARCH_WORKERS = min(8, os.cpu_count() or 2)
OPEN_FLAGS = (os.O_RDONLY | getattr(os, 'O_BINARY', 0)
              | getattr(os, 'O_NOFOLLOW', 0))


def _iter_source_files(src):
    """Yield regular source files under src without following links."""
    stack = [src.as_posix()]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif (entry.is_file(follow_symlinks=False)
                            and entry.name.endswith(SOURCE_EXTS)):
                        yield Path(entry.path)
        except OSError:
            continue


def _make_matcher(query):
    """Return (match(bytes) -> bool, overlap) for a case-insensitive query."""
    raw = query.encode('utf-8')
    overlap = max(len(raw) - 1, 0)
    if query.isascii():
        # bytes.lower() + `in` is several times faster than re.IGNORECASE
        needle = raw.lower()
        return (lambda buf: needle in buf.lower()), overlap
    needle = query.lower()
    return (lambda buf: needle in buf.decode('utf-8', 'ignore').lower()), (
        overlap)


def _file_contains(fpath, match, overlap):
    # os.read avoids the per-file overhead of Python file objects
    try:
        fd = os.open(fpath, OPEN_FLAGS)
    except OSError:
        return False
    try:
        tail = b''
        while True:
            chunk = os.read(fd, READ_CHUNK)
            if not chunk:
                return False
            buf = tail + chunk
            if match(buf):
                return True
            tail = buf[-overlap:] if overlap else b''
    except OSError:
        return False
    finally:
        os.close(fd)


def _content_search(files, query):
    """Return the files containing query, searched in parallel."""
    match, overlap = _make_matcher(query)

    def search_slice(part):
        return [f for f in part if _file_contains(f, match, overlap)]
    slices = [files[i::SEARCH_WORKERS] for i in range(SEARCH_WORKERS)]
    with ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        return [f for hits in executor.map(search_slice, slices)
                for f in hits]


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
        base = Path(settings.UPLD_DIR) / md5
        if code == 'js':
            src = base
            files = [
                base / rel for rel in list_js_source_files(
                    base, cached_js_source_files(md5))
            ]
        else:
            src = get_source_root(base, md5, code)
            if not src:
                msg = 'Invalid Directory Structure'
                return print_n_send_error_response(request, msg, True)
            files = None
        if files is None:
            files = list(_iter_source_files(src))
        if search_type == 'content':
            found = _content_search(files, query) if query else []
        else:
            q_lower = query.lower()
            found = [f for f in files if q_lower in f.name.lower()]
        matches = sorted({escape(f.relative_to(src).as_posix())
                          for f in found})
        context = {
            'title': 'Search Results',
            'matches': matches,
            'term': query,
            'found': str(len(matches)),
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
