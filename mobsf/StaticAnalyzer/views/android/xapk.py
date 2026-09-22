# -*- coding: utf_8 -*-
"""Handle XAPK File."""
import logging
import os
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


def _contained_path(root, candidate):
    """Return candidate's normalized path when it stays inside root.

    The prefix check runs on the normalized path. ``is_safe_path`` still
    rejects symlink escapes.
    """
    try:
        root_norm = os.path.normpath(root)
        candidate_norm = os.path.normpath(candidate)
    except (TypeError, ValueError):
        return None
    prefix = root_norm if root_norm.endswith(os.sep) else root_norm + os.sep
    if not candidate_norm.startswith(prefix):
        return None
    raw_name = os.path.basename(candidate_norm)
    if not is_safe_path(root, candidate_norm, raw_name):
        return None
    return candidate_norm


def _regular_file(root, path):
    """Return True for a regular file inside root that is not a link or FIFO."""
    contained = _contained_path(root, path)
    if contained is None:
        return False
    root_norm = os.path.normpath(root)
    prefix = root_norm if root_norm.endswith(os.sep) else root_norm + os.sep
    candidate_norm = os.path.normpath(contained)
    if candidate_norm.startswith(prefix):
        try:
            if is_pipe_or_link(candidate_norm):
                return False
        except OSError:
            return False
        return os.path.isfile(candidate_norm)
    return False


def _collect_split_apks(app_dir, members):
    """Return the primary APK and sibling APKs that were actually written."""
    base_apk = None
    fallback_apk = None
    splits = []
    for apk in members:
        if not isinstance(apk, str) or not apk.endswith('.apk'):
            continue
        full_path = _contained_path(app_dir, Path(app_dir) / apk)
        if full_path is None or not _regular_file(app_dir, full_path):
            continue
        splits.append(full_path)
        if apk.endswith('base.apk'):
            base_apk = full_path
        elif 'config.' not in apk.lower() and fallback_apk is None:
            fallback_apk = full_path
    return base_apk or fallback_apk, splits


def _split_extract_dir(app_dir, split_apk):
    """Return an extract directory inside the upload root, or None."""
    dest_name = Path(split_apk).stem
    if (not dest_name or dest_name in {'.', '..'}
            or is_path_traversal(dest_name)):
        return None
    return _contained_path(app_dir, Path(app_dir) / 'split_apks' / dest_name)


def _extract_sibling_splits(checksum, app_dir, primary, splits, size_budget):
    """Extract non-primary splits under one uncompressed-size budget."""
    limit = settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE
    for split_apk in splits:
        if os.path.normpath(split_apk) == os.path.normpath(primary):
            continue
        if size_budget['used'] >= limit:
            logger.error('Split APK uncompressed size budget exhausted')
            break
        archive = _contained_path(app_dir, split_apk)
        if archive is None or not _regular_file(app_dir, archive):
            logger.warning(
                'Skipping unextracted split APK %s',
                sanitize_for_logging(Path(split_apk).name))
            continue
        dest = _split_extract_dir(app_dir, archive)
        root_norm = os.path.normpath(app_dir)
        prefix = root_norm if root_norm.endswith(os.sep) else root_norm + os.sep
        archive_norm = os.path.normpath(archive)
        if dest is None or not archive_norm.startswith(prefix):
            logger.warning(
                'Skipping unsafe split APK %s',
                sanitize_for_logging(Path(archive).name))
            continue
        dest_norm = os.path.normpath(dest)
        if archive_norm.startswith(prefix) and dest_norm.startswith(prefix):
            unzip(checksum, archive_norm, dest_norm, size_budget)


def handle_split_apk(app_dic):
    """Unzip split APKs and extract sibling splits for native libraries."""
    checksum = app_dic['md5']
    app_dir = app_dic['app_dir']
    apks = app_dir / f'{checksum}.apk'
    # Check if previously extracted
    manifest = app_dir / 'AndroidManifest.xml'
    if manifest.exists():
        return True
    archive = _contained_path(app_dir, apks)
    if archive is None:
        return None
    primary, splits = _collect_split_apks(
        app_dir,
        unzip(checksum, archive, app_dir),
    )
    if primary is None:
        return None
    destination = _contained_path(app_dir, apks)
    if destination is None or not _regular_file(app_dir, primary):
        return None
    root_norm = os.path.normpath(app_dir)
    prefix = root_norm if root_norm.endswith(os.sep) else root_norm + os.sep
    primary_norm = os.path.normpath(primary)
    destination_norm = os.path.normpath(destination)
    if primary_norm.startswith(prefix) and destination_norm.startswith(prefix):
        move(primary_norm, destination_norm)
        # Sibling contents share one cap. The container unzip above keeps its
        # own cap, matching the previous single-archive limit.
        _extract_sibling_splits(
            checksum,
            app_dir,
            primary_norm,
            splits,
            {'used': 0},
        )
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
