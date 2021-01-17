# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import logging
import glob
import os
import platform
import shutil
import subprocess

from django.conf import settings

from mobsf.MobSF.utils import is_dir_exists

logger = logging.getLogger(__name__)


def get_icon(md5, bin_dir, binary):
    """Get app icon from IPA."""
    try:
        logger.info('Fetching icon path')
        bin_path = os.path.join(bin_dir, binary + '.app')
        if not is_dir_exists(bin_path):
            logger.warning('Could not find app binary directory')
            return False
        icons = glob.glob(bin_path + '/AppIcon*png')
        if not icons:
            logger.warning('Could not find app icon')
            return False
        icon_file = icons.pop()
        outfile = os.path.join(settings.DWD_DIR, md5 + '-icon.png')
        if platform.system() == 'Darwin':
            args = ['xcrun', '-sdk', 'iphoneos', 'pngcrush', '-q',
                    '-revert-iphone-optimizations',
                    icon_file, outfile]
            # Uncrush PNG. CgBI -> PNG, Mac only
            # https://iphonedevwiki.net/index.php/CgBI_file_format
            try:
                out = subprocess.run(args, capture_output=True)
                if b'libpng error:' in out.stdout:
                    # PNG looks normal
                    raise ValueError('PNG is not CgBI')
            except Exception:
                shutil.copy2(icon_file, outfile)
        else:
            shutil.copy2(icon_file, outfile)
        return True
    except Exception:
        logger.exception('Error Fetching icon')
        return False


def get_icon_source(md5, src_dir):
    """Get app icon from iOS ZIP."""
    logger.info('Fetching icon path')
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
            return False
        icon_file = appiconset[0]
        outfile = os.path.join(settings.DWD_DIR, md5 + '-icon.png')
        shutil.copy2(icon_file, outfile)
        return True
    except Exception:
        logger.exception('Error Fetching icon')
        return False
