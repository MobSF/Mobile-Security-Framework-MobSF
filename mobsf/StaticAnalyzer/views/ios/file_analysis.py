# -*- coding: utf_8 -*-
"""iOS File Analysis."""

import os
import shutil
import logging
from pathlib import Path

from django.utils.html import escape

from mobsf.StaticAnalyzer.views.ios.plist_analysis import (
    convert_bin_xml,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def ios_list_files(md5_hash, src, binary_form, mode):
    """List iOS files."""
    try:
        msg = 'iOS File Analysis and Normalization'
        logger.info(msg)
        append_scan_status(md5_hash, msg)
        # Multi function, Get Files, BIN Plist -> XML, normalize + to x
        filez = []
        certz = []
        sfiles = []
        full_paths = []
        database = []
        plist = []
        for dirname, _, files in os.walk(src):
            for jfile in files:
                if not jfile.endswith('.DS_Store'):

                    file_path = os.path.join(src, dirname, jfile)
                    if '__MACOSX' in file_path:
                        continue
                    if '+' in jfile:
                        plus2x = os.path.join(
                            src, dirname, jfile.replace('+', 'x'))
                        shutil.move(file_path, plus2x)
                        file_path = plus2x
                    fileparam = file_path.replace(src, '')
                    filez.append(fileparam)
                    full_paths.append(file_path)
                    ext = Path(jfile).suffix
                    if ext in ('.cer', '.pem', '.cert', '.crt',
                               '.pub', '.key', '.pfx', '.p12', '.der'):
                        certz.append({
                            'file_path': escape(file_path.replace(src, '')),
                            'type': None,
                            'hash': None,
                        })
                    if ext in ('.db', '.sqlitedb', '.sqlite', '.sqlite3'):
                        database.append({
                            'file_path': escape(fileparam),
                            'type': mode,
                            'hash': md5_hash,
                        })

                    if jfile.endswith('.plist'):
                        if binary_form:
                            convert_bin_xml(file_path)
                        plist.append({
                            'file_path': escape(fileparam),
                            'type': mode,
                            'hash': md5_hash,
                        })

        if len(database) > 0:
            sfiles.append({
                'issue': 'SQLite Files',
                'files': database,
            })
        if len(plist) > 0:
            sfiles.append({
                'issue': 'Plist Files',
                'files': plist,
            })
        if len(certz) > 0:
            sfiles.append({
                'issue': 'Certificate/Key Files Hardcoded inside the App.',
                'files': certz,
            })
        return {'files_short': filez,
                'files_long': full_paths,
                'special_files': sfiles}
    except Exception as exp:
        msg = 'iOS File Analysis'
        logger.exception(msg)
        append_scan_status(md5_hash, msg, repr(exp))
