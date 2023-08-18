# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import logging
import os
from plistlib import (
    dumps,
    load,
    loads,
)
from pathlib import Path
from re import sub

from openstep_parser import OpenStepDecoder

from biplist import (
    InvalidPlistException,
    readPlist,
    writePlistToString,
)

from mobsf.MobSF.utils import (
    find_key_in_dict,
    is_file_exists,
)
from mobsf.StaticAnalyzer.views.ios.permission_analysis import (
    check_permissions,
)
from mobsf.StaticAnalyzer.views.ios.app_transport_security import (
    check_transport_security,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    is_secret_key,
)

logger = logging.getLogger(__name__)
SKIP_PATH = {'__MACOSX', 'Pods'}
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'


def get_bundle_id(pobj, src):
    """Get iOS Bundle ID from source.

    Look up in Info.plist, entitlements, pbxproj
    """
    possible_ids = set()
    skip_chars = {'$(', '${'}

    # From old Info.plist
    bundle_id_og = pobj.get('CFBundleIdentifier', '')
    if (not any(tmpl in bundle_id_og for tmpl in skip_chars)
            and len(bundle_id_og) > 1):
        possible_ids.add(bundle_id_og)

    # Look in entitlements, only present in newer iOS source
    path = Path(src)
    for p in path.rglob('*.entitlements'):
        if any(x in p.resolve().as_posix() for x in SKIP_PATH):
            continue
        try:
            ent = loads(p.read_bytes())
            groups = ent.get('com.apple.security.application-groups')
            if not groups:
                continue
            for i in groups:
                t = i.replace('.group', '').replace('group.', '')
                possible_ids.add(t.strip())
        except Exception:
            logger.warning('Error in parsing .entitlements')

    # Look in project.pbxproj
    for p in path.rglob('*.pbxproj'):
        if any(x in p.resolve().as_posix() for x in SKIP_PATH):
            continue
        try:
            search = 'PRODUCT_BUNDLE_IDENTIFIER'
            parsed = OpenStepDecoder.ParseFromString(p.read_text())
            if not parsed:
                continue
            for i in find_key_in_dict(search, parsed):
                if i.startswith(skip_chars):
                    continue
                for spl in skip_chars:
                    tc = f'.{spl}'
                    if tc in i:
                        i = i.split(tc)[0]
                possible_ids.add(i)
        except Exception:
            logger.warning('Error in parsing .pbxproj')
    if possible_ids:
        possible_ids = filter(None, possible_ids)
        # Fuzzy logic: return the shortest bundle id string
        return min(possible_ids, key=len)
    return ''


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
            'inseccon': {},
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
                    if (not any(x in dirpath for x in SKIP_PATH)
                            and name.endswith('.plist')):
                        plist_files.append(os.path.join(dirpath, name))
                        if name == 'GoogleService-Info.plist':
                            continue
                        if name == 'Info.plist' or '-Info.plist' in name:
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
        plist_info['id'] = get_bundle_id(plist_obj, src)
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
        ats = []
        for plist_file_ in plist_files:
            plist_obj_ = {}
            with open(plist_file_, 'rb') as fp:
                plist_obj_ = load(fp)
            # Check for app-permissions
            plist_info['permissions'].update(check_permissions(plist_obj_))
            # Check for ats misconfigurations
            ats += check_transport_security(plist_obj_)
        plist_info['inseccon'] = {
            'ats_findings': ats,
            'ats_summary': get_summary(ats),
        }
        return plist_info
    except Exception:
        logger.exception('Reading from Info.plist')


def get_summary(ats):
    """Get ATS finding summary."""
    if len(ats) == 0:
        return {}
    summary = {HIGH: 0, WARNING: 0, INFO: 0, SECURE: 0}
    for i in ats:
        if i['severity'] == HIGH:
            summary[HIGH] += 1
        elif i['severity'] == WARNING:
            summary[WARNING] += 1
        elif i['severity'] == INFO:
            summary[INFO] += 1
        elif i['severity'] == SECURE:
            summary[SECURE] += 1
    return summary


def get_plist_secrets(app_dir):
    """Get possible hardcoded secrets from plist files."""
    result_list = set()

    def _remove_tags(data):
        """Remove tags from input."""
        return sub('<[^<]+>', '', data).strip()

    for i in Path(app_dir).rglob('*.plist'):
        xml_string = i.read_text('utf-8', 'ignore')
        xml_list = xml_string.split('\n')
        for index, line in enumerate(xml_list):
            if '<key>' in line and is_secret_key(_remove_tags(line)):
                nxt = index + 1
                value = (
                    _remove_tags(
                        xml_list[nxt])if nxt < len(xml_list) else False)
                if value and ' ' not in value:
                    result_list.add(
                        f'{_remove_tags(line)} : {_remove_tags(value)}')
    return list(result_list)
