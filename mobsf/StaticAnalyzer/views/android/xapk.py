# -*- coding: utf_8 -*-
"""Handle XAPK File."""
import logging
from json import load
from shutil import move

from mobsf.StaticAnalyzer.views.shared_func import unzip

logger = logging.getLogger(__name__)


def handle_xapk(app_dic):
    """Unzip and Extract APK."""
    data = None
    xapk = app_dic['app_dir'] / (app_dic['md5'] + '.xapk')
    apk = app_dic['app_dir'] / (app_dic['md5'] + '.apk')
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
            move(base_apk, apk)
            return True
    return None
