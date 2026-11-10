# -*- coding: utf_8 -*-
"""List all java files."""

import logging
from pathlib import Path

from django.conf import settings
from django.shortcuts import (
    loader,
    render,
)

from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.js_analysis import (
    list_js_source_files,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    android_source_root,
    find_java_source_folder,
)
from mobsf.MobSF.views.authentication import (
    login_required,
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


def _js_tree_from_paths(rel_paths):
    """Build nested jsTree HTML from a sorted list of relative file paths."""
    root_tree = {}
    for rel in rel_paths:
        parts = rel.split('/')
        cur = root_tree
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = rel

    def _render(node, prefix=''):
        for name, val in sorted(node.items()):
            if isinstance(val, dict):
                yield loader.render_to_string(
                    'static_analysis/treeview_folder.html',
                    {
                        'file': name,
                        'subfiles': _render(val, f'{prefix}{name}/'),
                    },
                )
            else:
                yield loader.render_to_string(
                    'static_analysis/treeview_file.html',
                    {
                        'file': name,
                        'path': prefix,
                    },
                )

    return _render(root_tree)


@login_required
def run(request):
    """Source Tree - Java/Smali/JS view."""
    try:
        logger.info('Listing Source files')
        if not is_md5(request.GET['md5']):
            return print_n_send_error_response(request, 'Scan hash not found')
        md5 = request.GET['md5']
        typ = request.GET['type']
        base = Path(settings.UPLD_DIR) / md5
        if typ == 'js':
            rel_paths = list_js_source_files(base)
            tree_index = _js_tree_from_paths(rel_paths)
            title = 'JavaScript / Hybrid Source'
        else:
            if typ == 'smali':
                src = base / 'smali_source'
            else:
                try:
                    src = find_java_source_folder(
                        android_source_root(base, md5))[0]
                except StopIteration:
                    return print_n_send_error_response(
                        request,
                        'Invalid Directory Structure')
            tree_index = tree_index_maker(src, len(src.as_posix()))
            title = f'{typ.capitalize()} Source'

        context = {
            'subfiles': tree_index,
            'title': title,
            'hash': md5,
            'source_type': typ,
            'version': settings.MOBSF_VER,
        }
        template = 'static_analysis/source_tree.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Source Files')
        return print_n_send_error_response(
            request,
            'Error Getting Source Files')
