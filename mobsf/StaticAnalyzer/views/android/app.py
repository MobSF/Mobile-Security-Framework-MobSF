# -*- coding: utf_8 -*-
"""Module for apk analysis."""
import os
import re
import logging
from pathlib import Path

from mobsf.StaticAnalyzer.tools.androguard4 import (
    apk,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def parse_apk(checksum, app_path):
    """Androguard APK."""
    try:
        msg = 'Parsing APK with androguard'
        logger.info(msg)
        append_scan_status(checksum, msg)
        return apk.APK(app_path)
    except Exception as exp:
        msg = 'Failed to parse APK with androguard'
        append_scan_status(checksum, msg, repr(exp))
        return None


def get_app_name(a, app_dir, is_apk):
    """Get app name."""
    base = Path(app_dir)
    if is_apk:
        if a:
            return a.get_app_name()
        else:
            val = base / 'apktool_out' / 'res' / 'values'
            if val.exists():
                return get_app_name_from_values_folder(val.as_posix())
    else:
        strings_path = base / 'app' / 'src' / 'main' / 'res' / 'values'
        eclipse_path = base / 'res' / 'values'
        if strings_path.exists():
            return get_app_name_from_values_folder(
                strings_path.as_posix())
        elif eclipse_path.exists():
            return get_app_name_from_values_folder(
                eclipse_path.as_posix())
    logger.warning('Cannot find values folder.')
    return ''


def get_app_name_from_values_folder(values_dir):
    """Get all the files in values folder and checks them for app_name."""
    files = [f for f in os.listdir(values_dir) if
             (os.path.isfile(os.path.join(values_dir, f)))
             and (f.endswith('.xml'))]
    for f in files:
        # Look through each file, searching for app_name.
        app_name = get_app_name_from_file(os.path.join(values_dir, f))
        if app_name:
            return app_name  # we found an app_name, lets return it.
    return ''  # Didn't find app_name, returning empty string.


def get_app_name_from_file(file_path):
    """Looks for app_name in specific file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()

    app_name_match = re.search(
        r'<string name=\"app_name\">(.{0,300})</string>',
        data)

    if (not app_name_match) or (len(app_name_match.group()) <= 0):
        # Did not find app_name in current file.
        return ''

    # Found app_name!
    return app_name_match.group(app_name_match.lastindex)
