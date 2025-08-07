# -*- coding: utf_8 -*-
"""Module for apk analysis."""
import os
import re
import logging
from pathlib import Path

from mobsf.StaticAnalyzer.tools.androguard4 import (
    apk,
)
from mobsf.StaticAnalyzer.views.android import (
    aapt,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def aapt_parse(app_dict):
    """Extract features from APK using aapt/aapt2."""
    checksum = app_dict['md5']
    app_dict['apk_features'] = {}
    app_dict['apk_strings'] = []
    try:
        msg = 'Extracting APK features using aapt/aapt2'
        logger.info(msg)
        append_scan_status(checksum, msg)
        aapt_obj = aapt.AndroidAAPT(app_dict['app_path'])
        app_dict['apk_features'] = aapt_obj.get_apk_features()
        if not app_dict.get('files'):
            app_dict['files'] = aapt_obj.get_apk_files()
        app_dict['apk_strings'] = aapt_obj.get_apk_strings()
    except FileNotFoundError:
        msg = 'aapt and aapt2 not found, skipping APK feature extraction'
        logger.warning(msg)
        append_scan_status(checksum, msg)
    except Exception as exp:
        msg = 'Failed to extract APK features using aapt/aapt2'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))


def androguard_parse(app_dict):
    """Extract features from APK using androguard."""
    checksum = app_dict['md5']
    app_dict['androguard_apk'] = None
    app_dict['androguard_manifest_xml'] = None
    app_dict['androguard_apk_resources'] = None
    app_dict['androguard_apk_name'] = None
    app_dict['androguard_apk_icon'] = None
    try:
        msg = 'Parsing APK with androguard'
        logger.info(msg)
        append_scan_status(checksum, msg)
        a = apk.APK(app_dict['app_path'])
        if not a:
            msg = 'Failed to parse APK with androguard'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return
        app_dict['androguard_apk'] = a
        try:
            app_dict['androguard_apk_name'] = a.get_app_name()
        except Exception as exp:
            msg = 'Failed to get app name with androguard'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            app_dict['androguard_apk_icon'] = a.get_app_icon(max_dpi=0xFFFE - 1)
        except Exception as exp:
            msg = 'Failed to get app icon with androguard'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            xml = a.get_android_manifest_axml().get_xml()
            app_dict['androguard_manifest_xml'] = xml
        except Exception as exp:
            msg = 'Failed to parse AndroidManifest.xml with androguard'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            app_dict['androguard_apk_resources'] = a.get_android_resources()
        except Exception as exp:
            msg = 'Failed to parse resources with androguard'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
    except Exception as exp:
        msg = 'Failed to parse APK with androguard'
        logger.error(msg)
        append_scan_status(checksum, msg, repr(exp))


def get_apk_name(app_dic):
    """Get app name."""
    real_name = ''
    base = Path(app_dic['app_dir'])

    # Check if it's an APK and try to retrieve the app name
    if app_dic.get('androguard_apk_name') or app_dic.get('apk_features'):
        app_name = (
            app_dic.get('androguard_apk_name')
            or app_dic.get('apk_features', {}).get('application_label')
        )
        if app_name:
            real_name = app_name
        else:
            # Fallback: Look for app_name in the values folder
            values_path = base / 'apktool_out' / 'res' / 'values'
            if values_path.exists():
                try:
                    real_name = get_app_name_from_values_folder(values_path.as_posix())
                except Exception:
                    logger.error('Failed to get app name from values folder')

    # Check if it's source code and try to retrieve the app name
    else:
        try:
            # Check paths for values folders
            paths_to_check = [
                base / 'app' / 'src' / 'main' / 'res' / 'values',
                base / 'res' / 'values',
            ]
            for path in paths_to_check:
                if path.exists():
                    real_name = get_app_name_from_values_folder(path.as_posix())
                    break
        except Exception:
            logger.error('Failed to get app name from source code')

    if not real_name:
        logger.warning('Cannot find app name')

    # Update the app dictionary
    app_dic['real_name'] = real_name


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
