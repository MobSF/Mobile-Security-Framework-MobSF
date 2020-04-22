# -*- coding: utf_8 -*-
"""List all java files."""

import logging
import os
import re
import shutil

from django.conf import settings
from django.shortcuts import render, loader
from django.utils.html import escape

from MobSF.utils import print_n_send_error_response, api_key

logger = logging.getLogger(__name__)


# Generator that uses 2 template files in order to make the main template
def tree_index_maker(root_dir):
    def _index(root):
        files = os.listdir(root)
        for mfile in files:
            t = os.path.join(root, mfile)
            if os.path.isdir(t):
                yield loader.render_to_string('static_analysis/treeview_folder.html',
                                              {'file': mfile,
                                               'subfiles': _index(os.path.join(root, t))})
                continue
            yield loader.render_to_string('static_analysis/treeview_file.html',
                                          {'file': mfile,
                                           'path': t[t.find('java_source') + 12: -len(mfile)]
                                           })
    return _index(root_dir)


def run(request):
    """Show the java code."""
    try:
        logger.info('Listing Java files')
        match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        typ = request.GET['type']
        if not match:
            return print_n_send_error_response(request, 'Scan hash not found')
        md5 = request.GET['md5']
        if typ == 'eclipse':
            src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
        elif typ == 'studio':
            src = os.path.join(settings.UPLD_DIR, md5
                               + '/app/src/main/java/')
        elif typ == 'apk':
            src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
        elif typ == 'smali':
            src = os.path.join(settings.UPLD_DIR, md5 + '/smali_source/')
        else:
            return print_n_send_error_response(
                request,
                'Invalid Directory Structure')

        tree_index = tree_index_maker(src)
        context = {
            'subfiles': tree_index,
            'title': 'Smali Source' if typ == 'smali' else 'Java Source',
            'hash': md5,
            'type': typ,
            'source_type': 'smali' if typ == 'smali' else 'java',
            'version': settings.MOBSF_VER,
            'api_key': api_key()
        }
        template = 'static_analysis/source_tree.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Getting Source Files')
        return print_n_send_error_response(request, 'Error Getting Source Files')
