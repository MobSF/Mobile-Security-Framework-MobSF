# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import logging
import os
import plistlib

from biplist import (
    InvalidPlistException,
    readPlist,
    writePlistToString,
)

from MobSF.utils import is_file_exists

from StaticAnalyzer.views.ios.permission_analysis import check_permissions
from StaticAnalyzer.views.ios.app_transport_security import (
    check_transport_security)

logger = logging.getLogger(__name__)


def convert_bin_xml(bin_xml_file):
    """Convert Binary XML to Readable XML."""
    try:
        plist_obj = readPlist(bin_xml_file)
        data = writePlistToString(plist_obj)
        return data
    except InvalidPlistException:
        logger.warning('Failed to convert plist')


def plist_analysis(src, is_source):
    """Plist Analysis."""
    try:
        logger.info('iOS Info.plist Analysis Started')
        plist_info = {
            'bin_name': '',
            'bin': '',
            'id': '',
            'version': '',
            'build': '',
            'sdk': '',
            'pltfm': '',
            'min': '',
            'plist_xml': '',
            'permissions': [],
            'inseccon': [],
            'bundle_name': '',
            'build_version_name': '',
            'bundle_url_types': [],
            'bundle_supported_platforms': [],
        }
        plist_file = None
        if is_source:
            logger.info('Finding Info.plist in iOS Source')
            for dirpath, _dirnames, files in os.walk(src):
                for name in files:
                    if (not any(x in dirpath for x in ['__MACOSX', 'Pods'])
                            and name == 'Info.plist'):
                        plist_file = os.path.join(dirpath, name)
                        break
        else:
            logger.info('Finding Info.plist in iOS Binary')
            dirs = os.listdir(src)
            dot_app_dir = ''
            for dir_ in dirs:
                if dir_.endswith('.app'):
                    dot_app_dir = dir_
                    break
            bin_dir = os.path.join(src, dot_app_dir)  # Full Dir/Payload/x.app
            plist_file = os.path.join(bin_dir, 'Info.plist')
        if not is_file_exists(plist_file):
            logger.warning(
                'Cannot find Info.plist file. Skipping Plist Analysis.')
        else:
            # Generic Plist Analysis
            plist_obj = plistlib.readPlist(plist_file)
            plist_info['plist_xml'] = plistlib.writePlistToBytes(
                plist_obj).decode('utf-8', 'ignore')
            plist_info['bin_name'] = (plist_obj.get('CFBundleDisplayName', '')
                                      or plist_obj.get('CFBundleName', ''))
            if not plist_info['bin_name'] and not is_source:
                # For iOS IPA
                plist_info['bin_name'] = dot_app_dir.replace('.app', '')
            plist_info['bin'] = plist_obj.get('CFBundleExecutable', '')
            plist_info['id'] = plist_obj.get('CFBundleIdentifier', '')
            plist_info['build'] = plist_obj.get('CFBundleVersion', '')
            plist_info['sdk'] = plist_obj.get('DTSDKName', '')
            plist_info['pltfm'] = plist_obj.get('DTPlatformVersion', '')
            plist_info['min'] = plist_obj.get('MinimumOSVersion', '')
            plist_info['bundle_name'] = plist_obj.get('CFBundleName', '')
            plist_info['bundle_version_name'] = plist_obj.get(
                'CFBundleShortVersionString', '')
            plist_info['bundle_url_types'] = plist_obj.get(
                'CFBundleURLTypes', [])
            plist_info['bundle_supported_platforms'] = plist_obj.get(
                'CFBundleSupportedPlatforms', [])
            # Check for app-permissions
            plist_info['permissions'] = check_permissions(plist_obj)
            # Check for ats misconfigurations
            plist_info['inseccon'] = check_transport_security(plist_obj)
        return plist_info
    except Exception:
        logger.exception('Reading from Info.plist')
