# -*- coding: utf_8 -*-
"""List all java files."""

import logging
import re
from pathlib import Path

from django.conf import settings
from django.shortcuts import (
    loader,
    render,
)

from mobsf.MobSF.utils import (
    api_key,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    find_java_source_folder,
)

logger = logging.getLogger(__name__)


# Generator that uses 2 template files in order to make the main template
def tree_index_maker(root_dir: Path, original_root_dir_len: int):
    def _index(root, root_len):
        for mfile in root.iterdir():
            if mfile.is_dir():
                yield loader.render_to_string(
                    'static_analysis/treeview_folder.html',
                    {'file': mfile.name,
                     'subfiles': _index(mfile, root_len)},
                )
                continue
            yield loader.render_to_string(
                'static_analysis/treeview_file.html',
                {'file': mfile.name,
                 'path': mfile.as_posix()[root_len + 1: -len(mfile.name)]},
            )
    return _index(root_dir, original_root_dir_len)


def run(request):
    """Source Tree - Java/Smali view."""
    try:
        logger.info('Listing Source files')
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if not match:
            return print_n_send_error_response(request, 'Scan hash not found')
        md5 = request.GET['md5']
        typ = request.GET['type']
        base = Path(settings.UPLD_DIR) / md5
        if typ == 'smali':
            src = base / 'smali_source'
        else:
            try:
                src = find_java_source_folder(base)[0]
            except StopIteration:
                return print_n_send_error_response(
                    request,
                    'Invalid Directory Structure')

        tree_index = tree_index_maker(src, len(src.as_posix()))
        context = {
            'subfiles': tree_index,
            'title': f'{typ.capitalize()} Source',
            'hash': md5,
            'source_type': typ,
            'version': settings.MOBSF_VER,
            'api_key': api_key(),
        }
        template = 'static_analysis/source_tree.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Source Files')
        return print_n_send_error_response(
            request,
            'Error Getting Source Files')
