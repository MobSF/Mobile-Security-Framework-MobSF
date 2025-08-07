# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import logging
import glob
import os
import platform
import shutil
import subprocess
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    is_dir_exists,
)

logger = logging.getLogger(__name__)


def get_icon_from_ipa(app_dict):
    """Get app icon from IPA."""
    try:
        binary = app_dict['infoplist'].get('bin')
        md5 = app_dict['md5_hash']
        bin_dir = app_dict['bin_dir']
        msg = 'Fetching IPA icon path'
        logger.info(msg)
        append_scan_status(md5, msg)
        bin_path = os.path.join(bin_dir, binary + '.app')
        if not is_dir_exists(bin_path):
            logger.warning('Could not find app binary directory')
            return
        icons = glob.glob(bin_path + '/AppIcon*png')
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
                    icon_file, outfile.as_posix()]
            try:
                out = subprocess.run(args, capture_output=True)
                if b'libpng error:' in out.stdout:
                    # PNG looks normal
                    raise ValueError('PNG is not CgBI')
            except Exception:
                shutil.copy2(icon_file, outfile.as_posix())
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
                        icon_file, '-o', outfile.as_posix()]
                try:
                    out = subprocess.run(args, capture_output=True)
                except Exception:
                    # Fails or PNG is not crushed
                    shutil.copy2(icon_file, outfile.as_posix())
            else:
                logger.warning('CgbiPngFix not available for %s %s', system, arch)
                shutil.copy2(icon_file, outfile.as_posix())
    except Exception as exp:
        msg = 'Error Fetching IPA icon'
        logger.exception(msg)
        append_scan_status(md5, msg, repr(exp))


def get_icon_source(app_dict):
    checksum = app_dict['md5_hash']
    src_dir = app_dict['app_dir']
    """Get app icon from iOS ZIP."""
    msg = 'Fetching icon path'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        appiconset = []
        for dirname, _, files in os.walk(src_dir):
            for img in files:
                full_path = os.path.join(src_dir, dirname, img)
                if '__MACOSX' in full_path:
                    continue
                if '.appiconset' in full_path and img.endswith('.png'):
                    appiconset.append(full_path)
        if not appiconset:
            return
        icon_file = appiconset[0]
        outfile = Path(settings.DWD_DIR) / f'{checksum}-icon.png'
        shutil.copy2(icon_file, outfile.as_posix())
        app_dict['icon_path'] = outfile.name
    except Exception as exp:
        msg = 'Error Fetching icon'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
