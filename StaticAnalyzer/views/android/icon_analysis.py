# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import fnmatch
import logging
import os

from androguard.core.bytecodes import apk

logger = logging.getLogger(__name__)


# relative to res folder
KNOWN_PATHS = [
    'mipmap-hdpi',
    'mipmap-xhdpi',
    'drawable-hdpi',
    'drawable-xhdpi',
    'mipmap-mdpi',
    'drawable-mdpi',
    'mipmap-hdpi-v4',
]

KNOWN_MIPMAP_SIZES = [
    '-hdpi',
    '-hdpi-v4',
    '-xhdpi',
    '-xhdpi-v4',
    '-mdpi',
    '-mdpi-v4',
]


def search_folder(src, file_pattern):
    matches = []
    for root, _, filenames in os.walk(src):
        for filename in fnmatch.filter(filenames, file_pattern):
            matches.append(os.path.join(root, filename))
    return matches


def guess_icon_path(res_dir):
    icon_folders = [
        'mipmap-hdpi',
        'mipmap-hdpi-v4',
        'drawable',
    ]
    for icon_path in icon_folders:
        guessed_icon_path = os.path.join(res_dir, icon_path, 'ic_launcher.png')
        if os.path.exists(guessed_icon_path):
            return guessed_icon_path

    for guess in search_folder(res_dir, 'ic_launcher.*'):
        return guess

    for guess in search_folder(res_dir, 'ic_launcher*'):
        return guess

    return ''


def find_icon_path_zip(res_dir, icon_paths_from_manifest):
    """
    Find icon.

    Tries to find an icon, based on paths
    fetched from the manifest and by global search
    returns an empty string on fail or a full path
    """
    global KNOWN_MIPMAP_SIZES
    try:
        logger.info('Guessing icon path')
        for icon_path in icon_paths_from_manifest:
            if icon_path.startswith('@'):
                path_array = icon_path.strip('@').split(os.sep)
                rel_path = os.sep.join(path_array[1:])
                for size_str in KNOWN_MIPMAP_SIZES:
                    tmp_path = os.path.join(
                        res_dir, path_array[0] + size_str, rel_path + '.png')
                    if os.path.exists(tmp_path):
                        return tmp_path
            else:
                if icon_path.starswith('res/') or icon_path.starswith('/res/'):
                    stripped_relative_path = icon_path.strip(
                        '/res')  # Works for neither /res and res
                    full_path = os.path.join(res_dir, stripped_relative_path)
                    if os.path.exists(full_path):
                        return full_path
                    full_path += '.png'
                    if os.path.exists(full_path):
                        return full_path

            file_name = icon_path.split(os.sep)[-1]
            if file_name.endswith('.png'):
                file_name += '.png'

            for guess in search_folder(res_dir, file_name):
                if os.path.exists(guess):
                    return guess

        # If didn't find, try the default name.. returns empty if not find
        return guess_icon_path(res_dir)

    except Exception:
        logger.exception('Guessing icon path')


def get_icon(apk_path, res_dir):
    """
    Returns a dict with isHidden boolean and a relative path.

    path is a full path (not relative to resource folder)
    """
    try:
        logger.info('Fetching icon path')
        a = apk.APK(apk_path)
        icon_resolution = 0xFFFE - 1
        icon_name = a.get_app_icon(max_dpi=icon_resolution)
        if icon_name:
            if '.xml' in icon_name:
                return {
                    'path': guess_icon_path(res_dir),
                    'hidden': False,
                }
            else:
                return {
                    'path': os.path.join(os.path.dirname(apk_path), icon_name),
                    'hidden': False,
                }
        return {
            'path': guess_icon_path(res_dir),
            'hidden': True,
        }
    except Exception:
        logger.exception('Fetching icon function')
