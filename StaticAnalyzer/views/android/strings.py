# -*- coding: utf_8 -*-
"""Module for strings-method for java."""

import io
import subprocess

from django.conf import settings

from MobSF.utils import (
    PrintException
)


def strings(app_file, app_dir, tools_dir):
    """Extract the strings from an app."""
    try:
        print "[INFO] Extracting Strings from APK"
        strings_jar = tools_dir + 'strings_from_apk.jar'
        args = [
            settings.JAVA_PATH + 'java',
            '-jar', strings_jar, app_dir + app_file, app_dir
        ]
        subprocess.call(args)
        dat = ''
        try:
            with io.open(
                app_dir + 'strings.json',
                mode='r',
                encoding="utf8",
                errors="ignore"
            ) as file_pointer:
                dat = file_pointer.read()
        except:
            pass
        dat = dat[1:-1].split(",")
        return dat
    except:
        PrintException("[ERROR] Extracting Strings from APK")
