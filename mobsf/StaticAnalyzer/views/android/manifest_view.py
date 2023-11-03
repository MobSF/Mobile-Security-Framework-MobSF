# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
import os
import re
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import print_n_send_error_response
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest_file,
)

logger = logging.getLogger(__name__)


def run(request, checksum):
    """View the manifest."""
    try:
        directory = settings.BASE_DIR  # BASE DIR
        typ = request.GET['type']  # APK or SOURCE
        match = re.match('^[0-9a-f]{32}$', checksum)
        if match and (typ in ['eclipse', 'studio', 'apk', 'aar']):
            app_dir = os.path.join(
                settings.UPLD_DIR, checksum + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                directory, 'StaticAnalyzer/tools/')  # TOOLS DIR
            app_path = os.path.join(app_dir, checksum + '.apk')
            manifest_file = get_manifest_file(
                app_dir,
                app_path,
                tools_dir,
                typ)
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
        return print_n_send_error_response(
            request,
            'Error Viewing AndroidManifest.xml')
