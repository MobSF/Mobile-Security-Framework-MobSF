# -*- coding: utf_8 -*-
"""Handle XAPK File."""
import logging
import subprocess
from json import load
from shutil import move
from pathlib import Path

from django.conf import settings

from mobsf.StaticAnalyzer.views.common.shared_func import unzip
from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    find_java_binary,
    is_file_exists,
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
            if is_safe_path(app_dic['app_dir'], base_apk, a['file']):
                move(base_apk, apk)
                return True
    return None


def _regular_file(path):
    """Return True for a regular file that is not a symlink or FIFO."""
    try:
        if is_pipe_or_link(path):
            return False
    except OSError:
        return False
    return Path(path).is_file()


def _collect_split_apks(app_dir, members):
    """Return the primary APK and sibling APKs that were actually written."""
    base_apk = None
    fallback_apk = None
    splits = []
    app_dir = Path(app_dir)
    for apk in members:
        if not isinstance(apk, str) or not apk.endswith('.apk'):
            continue
        full_path = app_dir / apk
        if not is_safe_path(app_dir, full_path, apk):
            continue
        if not _regular_file(full_path):
            continue
        splits.append(full_path)
        if apk.endswith('base.apk'):
            base_apk = full_path
        elif 'config.' not in apk.lower() and fallback_apk is None:
            fallback_apk = full_path
    return base_apk or fallback_apk, splits


def _split_extract_dir(app_dir, split_apk):
    """Return an extract directory inside the upload root, or None."""
    dest_name = split_apk.stem
    if (not dest_name or dest_name in {'.', '..'}
            or is_path_traversal(dest_name)):
        return None
    dest = Path(app_dir) / 'split_apks' / dest_name
    if not is_safe_path(app_dir, dest, dest_name):
        return None
    return dest


def _extract_sibling_splits(checksum, app_dir, primary, splits, size_budget):
    """Extract non-primary splits under one uncompressed-size budget."""
    limit = settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE
    for split_apk in splits:
        if split_apk == primary:
            continue
        if size_budget['used'] >= limit:
            logger.error('Split APK uncompressed size budget exhausted')
            break
        if not _regular_file(split_apk):
            logger.warning(
                'Skipping unextracted split APK %s',
                sanitize_for_logging(split_apk.name))
            continue
        dest = _split_extract_dir(app_dir, split_apk)
        if dest is None:
            logger.warning(
                'Skipping unsafe split APK %s',
                sanitize_for_logging(split_apk.name))
            continue
        unzip(
            checksum,
            split_apk.as_posix(),
            dest.as_posix(),
            size_budget)


def handle_split_apk(app_dic):
    """Unzip split APKs and extract sibling splits for native libraries."""
    checksum = app_dic['md5']
    app_dir = app_dic['app_dir']
    apks = app_dir / f'{checksum}.apk'
    # Check if previously extracted
    manifest = app_dir / 'AndroidManifest.xml'
    if manifest.exists():
        return True
    primary, splits = _collect_split_apks(
        app_dir,
        unzip(checksum, apks.as_posix(), app_dir),
    )
    if primary is None:
        return None
    move(primary, apks)
    # Sibling contents share one cap. The container unzip above keeps its
    # own cap, matching the previous single-archive limit.
    _extract_sibling_splits(
        checksum,
        app_dir,
        primary,
        splits,
        {'used': 0},
    )
    return True


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
            bundletool = Path(tools_dir) / 'bundletool-all-1.17.2.jar'
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
        # Extract APK from APKS
        for apk_file in unzip(checksum, apks.as_posix(), app_dic['app_dir']):
            full_path = app_dic['app_dir'] / apk_file
            safe_path = is_safe_path(app_dic['app_dir'], full_path, apk_file)
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
