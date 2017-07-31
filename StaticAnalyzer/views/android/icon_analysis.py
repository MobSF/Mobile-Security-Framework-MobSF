# -*- coding: utf_8 -*-
"""Module holding the functions for icon analysis."""

import subprocess
import re
import os
import platform
import fnmatch
import os


from MobSF.utils import (
    PrintException
)

def search_folder(src, file_pattern):
    matches = []
    for root, dirnames, filenames in os.walk(src):
        for filename in fnmatch.filter(filenames, file_pattern):
            matches.append(os.path.join(root, filename))
    return matches


def get_aapt(tools_dir):
    platform_system = platform.system()
    if platform_system == 'Darwin':
        return os.path.join(tools_dir, 'aapt', 'mac', 'aapt')
    elif platform_system == 'Linux':
        return os.path.join(tools_dir, 'aapt', 'linux', 'aapt')
    return os.path.join(tools_dir, 'aapt', 'windows', 'aapt.exe')


def guess_icon_path(res_dir):
    icon_folders =[
        'minimap-hdpi',
        'minimap-hdpi-v4',
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
