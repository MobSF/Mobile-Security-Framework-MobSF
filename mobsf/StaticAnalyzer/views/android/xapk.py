# -*- coding: utf_8 -*-
"""Handle XAPK File."""
import logging
from json import load
from shutil import move

from mobsf.StaticAnalyzer.views.common.shared_func import unzip
from mobsf.MobSF.utils import is_safe_path

logger = logging.getLogger(__name__)


def handle_xapk(app_dic):
    """Unzip and Extract APK."""
    data = None
    checksum = app_dic['md5']
    xapk = app_dic['app_dir'] / f'{checksum}.xapk'
    apk = app_dic['app_dir'] / f'{checksum}.apk'
    files = unzip(xapk.as_posix(), app_dic['app_dir'])
    if 'manifest.json' not in files:
        logger.error('Manifest file not found in XAPK')
        return False
    manifest = app_dic['app_dir'] / 'manifest.json'
    with open(manifest, encoding='utf8', errors='ignore') as f:
        data = load(f)
    if not data:
        logger.error('Manifest file is empty')
        return False
    apks = data.get('split_apks')
    if not apks:
        logger.error('Split APKs not found')
        return False
    for a in apks:
        if a['id'] == 'base':
            base_apk = app_dic['app_dir'] / a['file']
            if is_safe_path(app_dic['app_dir'], base_apk):
                move(base_apk, apk)
                return True
    return None


def handle_split_apk(app_dic):
    """Unzip and Extract Split APKs."""
    checksum = app_dic['md5']
    apks = app_dic['app_dir'] / f'{checksum}.apk'
    # Check if previously extracted
    manifest = app_dic['app_dir'] / 'AndroidManifest.xml'
    if manifest.exists():
        return True
    files = unzip(apks.as_posix(), app_dic['app_dir'])
    for apk in files:
        if not apk.startswith('config.') and apk.endswith('.apk'):
            full_path = app_dic['app_dir'] / apk
            if is_safe_path(app_dic['app_dir'], full_path):
                move(full_path, apks)
                return True
    return None
