# -*- coding: utf_8 -*-
"""Handle XAPK File."""
import logging
import subprocess
from json import load
from shutil import move
from pathlib import Path

from django.conf import settings

from mobsf.StaticAnalyzer.views.common.shared_func import unzip
from mobsf.MobSF.utils import (
    append_scan_status,
    find_java_binary,
    is_file_exists,
    is_safe_path,
)

logger = logging.getLogger(__name__)


def handle_xapk(app_dic):
    """Unzip and Extract APK."""
    data = None
    checksum = app_dic['md5']
    xapk = app_dic['app_dir'] / f'{checksum}.xapk'
    apk = app_dic['app_dir'] / f'{checksum}.apk'
    files = unzip(
        checksum,
        xapk.as_posix(),
        app_dic['app_dir'])
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
    for apk in unzip(checksum, apks.as_posix(), app_dic['app_dir']):
        full_path = app_dic['app_dir'] / apk
        safe_path = is_safe_path(app_dic['app_dir'], full_path)
        if (not apk.startswith('config.')
                and apk.endswith('.apk')
                and safe_path):
            move(full_path, apks)
            return True
    return None


def handle_aab(app_dic):
    """Convert AAB to APK using bundletool."""
    try:
        checksum = app_dic['md5']
        aab_path = app_dic['app_dir'] / f'{checksum}.aab'
        apks = aab_path.with_suffix('.apks')
        apk = aab_path.with_suffix('.apk')
        tools_dir = app_dic['tools_dir']
        # Check if previously converted
        manifest = app_dic['app_dir'] / 'AndroidManifest.xml'
        if manifest.exists():
            return True
        msg = 'Converting AAB to APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        if (getattr(settings, 'BUNDLE_TOOL', '')
                and len(settings.BUNDLE_TOOL) > 0
                and is_file_exists(settings.BUNDLE_TOOL)):
            bundletool = settings.BUNDLE_TOOL
        else:
            bundletool = Path(tools_dir) / 'bundletool-all-1.16.0.jar'
            bundletool = bundletool.as_posix()
        args = [
            find_java_binary(),
            '-jar',
            bundletool,
            'build-apks',
            f'--bundle={aab_path.as_posix()}',
            f'--output={apks.as_posix()}',
            '--mode=universal',
        ]
        if not apks.exists() and aab_path.exists():
            # Convert AAB to APKS
            subprocess.run(args, timeout=300)
            # Remove AAB
            aab_path.unlink()
        # Extract APK from APKS
        for apk_file in unzip(checksum, apks.as_posix(), app_dic['app_dir']):
            full_path = app_dic['app_dir'] / apk_file
            safe_path = is_safe_path(app_dic['app_dir'], full_path)
            if apk_file == 'universal.apk' and safe_path:
                move(full_path, apk)
                apks.unlink()
                return True
        raise Exception('Unable to convert AAB to APK')
    except subprocess.TimeoutExpired as exp:
        msg = 'Converting AAB to APK timed out'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    except Exception as exp:
        msg = 'Failed to convert AAB to APK'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return None
