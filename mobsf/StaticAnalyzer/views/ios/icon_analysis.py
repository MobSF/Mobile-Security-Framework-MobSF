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

from mobsf.MobSF.utils import is_dir_exists

logger = logging.getLogger(__name__)


def get_icon_from_ipa(app_dict, binary):
    """Get app icon from IPA."""
    try:
        md5 = app_dict['md5_hash']
        bin_dir = app_dict['bin_dir']
        logger.info('Fetching icon path')
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
        if platform.system() == 'Darwin':
            args = ['xcrun', '-sdk', 'iphoneos', 'pngcrush', '-q',
                    '-revert-iphone-optimizations',
                    icon_file, outfile.as_posix()]
            # Uncrush PNG. CgBI -> PNG, Mac only
            # https://iphonedevwiki.net/index.php/CgBI_file_format
            try:
                out = subprocess.run(args, capture_output=True)
                if b'libpng error:' in out.stdout:
                    # PNG looks normal
                    raise ValueError('PNG is not CgBI')
            except Exception:
                shutil.copy2(icon_file, outfile.as_posix())
        else:
            shutil.copy2(icon_file, outfile.as_posix())
        app_dict['icon_path'] = outfile.name
    except Exception:
        logger.exception('Error Fetching icon')


def get_icon_source(app_dict):
    md5 = app_dict['md5_hash']
    src_dir = app_dict['app_dir']
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
            return
        icon_file = appiconset[0]
        outfile = Path(settings.DWD_DIR) / f'{md5}-icon.png'
        shutil.copy2(icon_file, outfile.as_posix())
        app_dict['icon_path'] = outfile.name
    except Exception:
        logger.exception('Error Fetching icon')
