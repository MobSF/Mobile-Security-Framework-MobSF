# -*- coding: utf_8 -*-
"""iOS File Analysis."""

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


def ios_list_files(md5_hash, src, mode):
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

        mode = 'ios' if mode == 'zip' else 'ipa'

        # Walk through the directory
        for file_path in Path(src).rglob('*'):
            if (file_path.is_file()
                    and not (file_path.name.endswith('.DS_Store')
                             or '__MACOSX' in str(file_path))):
                # Normalize '+' in file names
                if '+' in file_path.name:
                    normalized_path = file_path.with_name(
                        file_path.name.replace('+', 'x'))
                    shutil.move(file_path, normalized_path)
                    file_path = normalized_path

                # Append file details
                relative_path = file_path.relative_to(src)
                filez.append(str(relative_path))
                full_paths.append(str(file_path))

                ext = file_path.suffix.lower()

                # Categorize files by type
                if ext in {'.cer', '.pem', '.cert', '.crt', '.pub',
                           '.key', '.pfx', '.p12', '.der'}:
                    certz.append({
                        'file_path': escape(str(relative_path)),
                        'type': None,
                        'hash': None,
                    })
                elif ext in {'.db', '.sqlitedb', '.sqlite', '.sqlite3'}:
                    database.append({
                        'file_path': escape(str(relative_path)),
                        'type': mode,
                        'hash': md5_hash,
                    })
                elif ext in {'.plist', '.json'}:
                    if mode == 'ipa' and ext == '.plist':
                        convert_bin_xml(file_path.as_posix())
                    plist.append({
                        'file_path': escape(str(relative_path)),
                        'type': mode,
                        'hash': md5_hash,
                    })

        # Group special files
        if database:
            sfiles.append({
                'issue': 'SQLite Files',
                'files': database,
            })
        if plist:
            sfiles.append({
                'issue': 'Plist Files',
                'files': plist,
            })
        if certz:
            sfiles.append({
                'issue': 'Certificate/Key Files Hardcoded inside the App.',
                'files': certz,
            })

        return {
            'files_short': filez,
            'files_long': full_paths,
            'special_files': sfiles,
        }
    except Exception as exp:
        msg = 'iOS File Analysis'
        logger.exception(msg)
        append_scan_status(md5_hash, msg, repr(exp))
