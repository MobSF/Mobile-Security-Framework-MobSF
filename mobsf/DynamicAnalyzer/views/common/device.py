# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
import ntpath
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.utils import (
    is_md5,
    is_path_traversal,
    is_safe_path,
    print_n_send_error_response,
    read_sqlite,
)

from biplist import (
    writePlistToString,
)


logger = logging.getLogger(__name__)


@login_required
def view_file(request, api=False):
    """View File in app data directory."""
    logger.info('Viewing File')
    try:
        typ = ''
        rtyp = ''
        dat = ''
        sql_dump = {}
        if api:
            fil = request.POST['file']
            md5_hash = request.POST['hash']
            typ = request.POST['type']
        else:
            fil = request.GET['file']
            md5_hash = request.GET['hash']
            typ = request.GET['type']
        if not is_md5(md5_hash):
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        src = Path(settings.UPLD_DIR) / md5_hash / 'DYNAMIC_DeviceData'
        sfile = src / fil
        src = src.as_posix()
        if not is_safe_path(src, sfile.as_posix()) or is_path_traversal(fil):
            err = 'Path Traversal Attack Detected'
            return print_n_send_error_response(request, err, api)
        dat = sfile.read_text('ISO-8859-1')
        if fil.endswith('.plist') and dat.startswith('bplist0'):
            dat = writePlistToString(dat).decode('utf-8', 'ignore')
        if fil.endswith(('.xml', '.plist')) and typ in ['xml', 'plist']:
            rtyp = 'xml'
        elif typ == 'db':
            dat = None
            sql_dump = read_sqlite(sfile.as_posix())
            rtyp = 'asciidoc'
        elif typ == 'others':
            rtyp = 'asciidoc'
        else:
            err = 'File type not supported'
            return print_n_send_error_response(request, err, api)
        fil = escape(ntpath.basename(fil))
        context = {
            'title': fil,
            'file': fil,
            'data': dat,
            'sqlite': sql_dump,
            'type': rtyp,
            'version': settings.MOBSF_VER,
        }
        template = 'general/view.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Viewing File')
        return print_n_send_error_response(
            request,
            'Error Viewing File',
            api)
