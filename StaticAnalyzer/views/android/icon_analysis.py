# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import subprocess
import re
import os
import platform
import fnmatch
import string

from django.conf import settings

# relative to res folder
KNOWN_PATHS = [
    'mipmap-hdpi',
    'mipmap-xhdpi',
    'drawable-hdpi',
    'drawable-xhdpi',
    'mipmap-mdpi',
    'drawable-mdpi',
    'mipmap-hdpi-v4'
]

KNOWN_MIPMAP_SIZES = [
    '-hdpi',
    '-hdpi-v4',
    '-xhdpi',
    '-xhdpi-v4',
    '-mdpi',
    '-mdpi-v4'
]

from MobSF.utils import (
    PrintException
)


def search_folder(src, file_pattern):
    matches = []
    for root, _, filenames in os.walk(src):
        for filename in fnmatch.filter(filenames, file_pattern):
            matches.append(os.path.join(root, filename))
    return matches


def get_aapt(tools_dir):
    if os.path.exists(settings.ADB_BINARY):
        return settings.ADB_BINARY
    platform_system = platform.system()
    if platform_system == 'Darwin':
        return os.path.join(tools_dir, 'aapt', 'mac', 'aapt')
    elif platform_system == 'Linux':
        return os.path.join(tools_dir, 'aapt', 'linux', 'aapt')
    return os.path.join(tools_dir, 'aapt', 'windows', 'aapt.exe')


def guess_icon_path(res_dir):
    icon_folders = [
        'mipmap-hdpi',
        'mipmap-hdpi-v4',
        'drawable'
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


def get_icon(apk_path, res_dir, tools_dir):
    """Returns a dict with isHidden boolean and a relative path
        path is a full path (not relative to resource folder) """
    try:
        print "[INFO] Fetching icon path"

        aapt_binary = get_aapt(tools_dir)
        args = [aapt_binary, 'd', 'badging', apk_path]
        if platform.system() == "Linux":
            env = {"LD_LIBRARY_PATH": str(os.path.join(
                settings.BASE_DIR, "DynamicAnalyzer/tools/adb/linux/lib64/"))}
            aapt_output = subprocess.check_output(args, env=env)
        else:
            aapt_output = subprocess.check_output(args)
        regex = re.compile(r"application:[^\n]+icon='(.*)'.*")
        found_regex = regex.findall(aapt_output)
        if len(found_regex) > 0:
            if found_regex[0]:
                return {
                    'path': os.path.join(os.path.dirname(apk_path), found_regex[0]),
                    'hidden': False
                }
        return {
            'path': guess_icon_path(res_dir),
            'hidden': True
        }
    except:
        PrintException("[ERROR] Get icon function")


def find_icon_path_zip(res_dir, icon_paths_from_manifest):
    """Tries to find an icon, based on paths fetched from the manifest and by global search
        returns an empty string on fail or a full path"""
    global KNOWN_MIPMAP_SIZES
    try:
        print "[INFO] Fetching icon path"
        for icon_path in icon_paths_from_manifest:
            if icon_path.startswith('@'):
                path_array = icon_path.strip('@').split(os.sep)
                rel_path = string.join(path_array[1:], os.sep)
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

    except:
        PrintException("[ERROR] Get icon function")
