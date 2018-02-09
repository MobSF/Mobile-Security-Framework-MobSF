# -*- coding: utf_8 -*-
"""Module for strings-method for java."""

import io
import subprocess
from androguard.core.bytecodes import apk

from django.conf import settings

from MobSF.utils import (
    PrintException
)


def strings(app_file, app_dir, tools_dir):
    """Extract the strings from an app."""
    try:
        print "[INFO] Extracting Strings from APK"

        a = apk.APK(app_dir+app_file)

        rsrc = a.get_android_resources() 

        pkg = rsrc.get_packages_names()[0]

        dat = []

        rsrc.get_strings_resources() 

        for i in rsrc.values[pkg].keys():
            for duo in rsrc.values[pkg][i]['string']:
                dat.append('"'+duo[0]+'" : "'+duo[1]+'"') 

        return dat
    except:
        PrintException("[ERROR] Extracting Strings from APK")
