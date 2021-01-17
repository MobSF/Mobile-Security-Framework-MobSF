# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
import os
import re
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import print_n_send_error_response
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    get_manifest_file,
)

logger = logging.getLogger(__name__)


def run(request):
    """View the manifest."""
    try:
        directory = settings.BASE_DIR  # BASE DIR
        md5 = request.GET['md5']  # MD5
        typ = request.GET['type']  # APK or SOURCE
        binary = request.GET['bin']
        match = re.match('^[0-9a-f]{32}$', md5)
        if (match
            and (typ in ['eclipse', 'studio', 'apk'])
                and (binary in ['1', '0'])):
            app_dir = os.path.join(
                settings.UPLD_DIR, md5 + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                directory, 'StaticAnalyzer/tools/')  # TOOLS DIR
            if binary == '1':
                is_binary = True
            elif binary == '0':
                is_binary = False
            app_path = os.path.join(app_dir, md5 + '.apk')
            manifest_file = get_manifest_file(
                app_dir,
                app_path,
                tools_dir,
                typ,
                is_binary)
            mfile = Path(manifest_file)
            if mfile.exists():
                manifest = mfile.read_text('utf-8', 'ignore')
            else:
                manifest = ''
            context = {
                'title': 'AndroidManifest.xml',
                'file': 'AndroidManifest.xml',
                'data': manifest,
                'type': 'xml',
                'sqlite': {},
                'version': settings.MOBSF_VER,
            }
            template = 'general/view.html'
            return render(request, template, context)
    except Exception:
        logger.exception('Viewing AndroidManifest.xml')
        return print_n_send_error_response(request,
                                           'Error Viewing AndroidManifest.xml')
