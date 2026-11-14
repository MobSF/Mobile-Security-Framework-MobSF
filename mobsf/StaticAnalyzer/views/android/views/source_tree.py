# -*- coding: utf_8 -*-
"""Source Tree - Java/Smali/JS view."""

import json
import logging
import os
from pathlib import Path

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.views.common.js_analysis import (
    cached_js_source_files,
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
SOURCE_TYPES = {
    'java': 'Java Source',
    'smali': 'Smali Source',
    'js': 'JavaScript / Hybrid Source',
}
TREE_ROOT = '#'
MORE_PREFIX = '#more:'
MAX_TREE_NODE_IDS = 2000
MAX_CHILDREN_PAGE = 1000
FOLDER_ICON = 'fa fa-folder'
FILE_ICON = '/static/jsTree/themes/default/file.png'
MORE_ICON = 'fa fa-ellipsis-h'


def get_source_root(base, md5, typ):
    """Return the Java/Kotlin or Smali source folder, or None."""
    if typ == 'smali':
        return base / 'smali_source'
    try:
        return find_java_source_folder(android_source_root(base, md5))[0]
    except StopIteration:
        return None


def _folder_node(rel, name, children=True):
    return {
        'id': rel,
        'text': name,
        'children': children,
        'icon': FOLDER_ICON,
        'li_attr': {'class': 'dir'},
    }


def _file_node(rel, name):
    return {
        'id': rel,
        'text': name,
        'icon': FILE_ICON,
        'li_attr': {'class': 'file'},
    }


def _sort_nodes(dirs, files):
    def key(node):
        return node['text'].lower()
    return sorted(dirs, key=key) + sorted(files, key=key)


def _more_node(rel, offset, remaining):
    return {
        'id': f'{MORE_PREFIX}{offset}:{rel}',
        'text': f'... {remaining} more (click to load)',
        'icon': MORE_ICON,
        'li_attr': {'class': 'more'},
    }


def _page_children(root, node_id):
    """Return one page of children for a folder or a load-more node id."""
    rel, offset = node_id, 0
    if node_id.startswith(MORE_PREFIX):
        offset_str, _, rel = node_id[len(MORE_PREFIX):].partition(':')
        if not offset_str.isdigit() or len(offset_str) > 9:
            return []
        offset = int(offset_str)
        rel = rel or TREE_ROOT
    children = _list_children(root, rel)
    page = children[offset:offset + MAX_CHILDREN_PAGE]
    remaining = len(children) - offset - len(page)
    if remaining > 0:
        page.append(_more_node(
            '' if rel == TREE_ROOT else rel,
            offset + MAX_CHILDREN_PAGE,
            remaining))
    return page


def _list_children(root, rel):
    """Return jsTree nodes for the direct children of root/rel."""
    folder = root
    if rel != TREE_ROOT:
        folder = root / rel
        if (is_path_traversal(rel)
                or not is_safe_path(root, folder, rel)):
            return []
    else:
        rel = ''
    if not folder.is_dir() or is_pipe_or_link(folder):
        return []
    dirs, files = [], []
    with os.scandir(folder) as entries:
        for entry in entries:
            if entry.is_symlink():
                continue
            child = f'{rel}/{entry.name}' if rel else entry.name
            if entry.is_dir(follow_symlinks=False):
                dirs.append(_folder_node(child, entry.name))
            elif entry.is_file(follow_symlinks=False):
                files.append(_file_node(child, entry.name))
    return _sort_nodes(dirs, files)


def _js_tree(rel_paths):
    """Build a fully expanded jsTree node list from relative file paths."""
    root = {}
    for rel in rel_paths:
        cur = root
        parts = rel.split('/')
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = rel

    def build(node, prefix):
        dirs, files = [], []
        for name, val in node.items():
            if isinstance(val, dict):
                dirs.append(_folder_node(
                    f'{prefix}{name}', name, build(val, f'{prefix}{name}/')))
            else:
                files.append(_file_node(val, name))
        return _sort_nodes(dirs, files)
    return build(root, '')


@login_required
def run(request):
    """Source Tree - Java/Smali/JS view."""
    try:
        md5 = request.GET['md5']
        typ = request.GET['type']
        if not is_md5(md5) or typ not in SOURCE_TYPES:
            return print_n_send_error_response(request, 'Scan hash not found')
        context = {
            'title': SOURCE_TYPES[typ],
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


@login_required
@require_http_methods(['POST'])
def nodes(request):
    """Return jsTree children for the requested folder ids (ajax)."""
    try:
        md5 = request.POST['md5']
        typ = request.POST['type']
        ids = json.loads(request.POST['ids'])
        if (not is_md5(md5)
                or typ not in SOURCE_TYPES
                or not isinstance(ids, list)
                or len(ids) > MAX_TREE_NODE_IDS
                or not all(isinstance(i, str) for i in ids)):
            return JsonResponse({'error': 'Invalid request'}, status=400)
        base = Path(settings.UPLD_DIR) / md5
        result = {}
        if typ == 'js':
            if TREE_ROOT in ids:
                result[TREE_ROOT] = _js_tree(list_js_source_files(
                    base, cached_js_source_files(md5)))
            return JsonResponse(result)
        root = get_source_root(base, md5, typ)
        if not root or not root.is_dir() or is_pipe_or_link(root):
            return JsonResponse(result)
        for node_id in ids:
            result[node_id] = _page_children(root, node_id)
        return JsonResponse(result)
    except Exception:
        logger.exception('Listing source tree nodes')
        return JsonResponse({'error': 'Listing failed'}, status=500)
