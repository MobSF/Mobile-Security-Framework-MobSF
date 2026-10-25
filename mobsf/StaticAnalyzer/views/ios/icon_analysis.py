# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import glob
import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def get_icon_from_ipa(app_dict):
    """Get app icon from IPA."""
    try:
        binary = app_dict['infoplist'].get('bin')
        md5 = app_dict['md5_hash']
        scan_root = Path(app_dict['app_dir'])
        payload_root = Path(app_dict['bin_dir'])
        app_root = Path(app_dict['app_root'])
        msg = 'Fetching IPA icon path'
        logger.info(msg)
        append_scan_status(md5, msg)
        if binary and is_path_traversal(binary):
            logger.warning('Unsafe CFBundleExecutable value')
            return

        try:
            app_relative = app_root.relative_to(scan_root)
            payload_relative = app_root.relative_to(payload_root)
        except ValueError:
            logger.warning('Application bundle escapes scan directory')
            return
        if (not is_safe_path(scan_root, app_root, app_relative)
                or not is_safe_path(
                    payload_root, app_root, payload_relative)
                or not app_root.is_dir()
                or is_pipe_or_link(app_root)):
            logger.warning('Unsafe application bundle path')
            return

        icons = []
        for icon in glob.glob((app_root / 'AppIcon*png').as_posix()):
            icon_file = Path(icon)
            try:
                relative_icon = icon_file.relative_to(app_root)
            except ValueError:
                continue
            if (is_safe_path(app_root, icon_file, relative_icon)
                    and icon_file.exists()
                    and icon_file.is_file()
                    and not is_pipe_or_link(icon_file)):
                icons.append(icon_file)
        if not icons:
            logger.warning('Could not find app icon')
            return
        icon_file = icons.pop()
        outfile = Path(settings.DWD_DIR) / f'{md5}-icon.png'
        app_dict['icon_path'] = outfile.name
        tools_dir = Path(settings.BASE_DIR) / 'StaticAnalyzer' / 'tools' / 'ios'
        arch = platform.machine()
        system = platform.system()
        # Uncrush PNG. CgBI -> PNG
        # https://iphonedevwiki.net/index.php/CgBI_file_format
        if system == 'Darwin':
            args = ['xcrun', '-sdk', 'iphoneos', 'pngcrush', '-q',
                    '-revert-iphone-optimizations',
                    icon_file.as_posix(), outfile.as_posix()]
            try:
                out = subprocess.run(args, capture_output=True)
                if b'libpng error:' in out.stdout:
                    # PNG looks normal
                    raise ValueError('PNG is not CgBI')
            except Exception:
                shutil.copy2(icon_file.as_posix(), outfile.as_posix())
        else:
            # Windows/Linux
            cgbipng_bin = None
            if system == 'Windows' and arch in ('AMD64', 'x86'):
                cgbipng_bin = 'CgbiPngFix.exe'
            elif system == 'Linux' and arch == 'x86_64':
                cgbipng_bin = 'CgbiPngFix_amd64'
            elif system == 'Linux' and arch == 'aarch64':
                cgbipng_bin = 'CgbiPngFix_arm64'
            if cgbipng_bin:
                cbin = tools_dir / 'CgbiPngFix' / cgbipng_bin
                args = [cbin.as_posix(), '-i',
                        icon_file.as_posix(), '-o', outfile.as_posix()]
                try:
                    out = subprocess.run(args, capture_output=True)
                except Exception:
                    # Fails or PNG is not crushed
                    shutil.copy2(icon_file.as_posix(), outfile.as_posix())
            else:
                logger.warning('CgbiPngFix not available for %s %s', system, arch)
                shutil.copy2(icon_file.as_posix(), outfile.as_posix())
    except Exception as exp:
        msg = 'Error Fetching IPA icon'
        logger.exception(msg)
        append_scan_status(md5, msg, repr(exp))


def get_icon_source(app_dict):
    checksum = app_dict['md5_hash']
    src_dir = Path(app_dict['app_dir'])
    """Get app icon from iOS ZIP."""
    msg = 'Fetching icon path'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        appiconset = []
        for dirname, _, files in os.walk(src_dir):
            for img in files:
                full_path = Path(dirname) / img
                if '__MACOSX' in full_path.as_posix():
                    continue
                try:
                    relative_icon = full_path.relative_to(src_dir)
                except ValueError:
                    continue
                if ('.appiconset' in full_path.as_posix()
                        and img.endswith('.png')
                        and is_safe_path(
                            src_dir, full_path, relative_icon)
                        and full_path.exists()
                        and full_path.is_file()
                        and not is_pipe_or_link(full_path)):
                    appiconset.append(full_path)
        if not appiconset:
            return
        icon_file = appiconset[0]
        outfile = Path(settings.DWD_DIR) / f'{checksum}-icon.png'
        shutil.copy2(icon_file.as_posix(), outfile.as_posix())
        app_dict['icon_path'] = outfile.name
    except Exception as exp:
        msg = 'Error Fetching icon'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
