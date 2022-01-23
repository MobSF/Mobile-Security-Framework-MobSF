# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import logging
import os
from plistlib import (
    dumps,
    load,
)
from re import sub

from biplist import (
    InvalidPlistException,
    readPlist,
    writePlistToString,
)

from mobsf.MobSF.utils import is_file_exists
from mobsf.StaticAnalyzer.views.ios.permission_analysis import (
    check_permissions,
)
from mobsf.StaticAnalyzer.views.ios.app_transport_security import (
    check_transport_security,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    is_secret,
)

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
            'permissions': {},
            'inseccon': [],
            'bundle_name': '',
            'build_version_name': '',
            'bundle_url_types': [],
            'bundle_supported_platforms': [],
            'bundle_version_name': '',
        }
        plist_file = None
        plist_files = []
        if is_source:
            logger.info('Finding Info.plist in iOS Source')
            for dirpath, _dirnames, files in os.walk(src):
                for name in files:
                    if (not any(x in dirpath for x in ['__MACOSX', 'Pods'])
                            and name.endswith('.plist')):
                        plist_files.append(os.path.join(dirpath, name))
                        if name == 'Info.plist':
                            plist_file = os.path.join(dirpath, name)
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
            plist_files = [plist_file]

        # Skip Plist Analysis if there is no Info.plist
        if not plist_file or not is_file_exists(plist_file):
            logger.warning(
                'Cannot find Info.plist file. Skipping Plist Analysis.')
            return plist_info

        # Generic Plist Analysis
        plist_obj = {}
        with open(plist_file, 'rb') as fp:
            plist_obj = load(fp)
        plist_info['plist_xml'] = dumps(
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
        btype = plist_obj.get('CFBundleURLTypes', [])
        if btype and isinstance(btype, dict):
            # Fixes bugs like # 1885
            btype = [btype]
        plist_info['bundle_url_types'] = btype
        plist_info['bundle_supported_platforms'] = plist_obj.get(
            'CFBundleSupportedPlatforms', [])
        logger.info('Checking Permissions')
        logger.info('Checking for Insecure Connections')
        for plist_file_ in plist_files:
            plist_obj_ = {}
            with open(plist_file_, 'rb') as fp:
                plist_obj_ = load(fp)
            # Check for app-permissions
            plist_info['permissions'].update(check_permissions(plist_obj_))
            # Check for ats misconfigurations
            plist_info['inseccon'] += check_transport_security(plist_obj_)
        return plist_info
    except Exception:
        logger.exception('Reading from Info.plist')


def get_plist_secrets(xml_string):
    """Get possible hardcoded secrets from plist."""
    result_list = []

    def _remove_tags(data):
        """Remove tags from input."""
        return sub('<[^<]+>', '', data).strip()

    xml_list = xml_string.split('\n')

    for index, line in enumerate(xml_list):
        if '<key>' in line and is_secret(_remove_tags(line)):
            nxt = index + 1
            value = (
                _remove_tags(xml_list[nxt])if nxt < len(xml_list) else False)
            if value:
                result_list.append(
                    f'{_remove_tags(line)} : {_remove_tags(value)}')
    return result_list
