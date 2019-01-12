# -*- coding: utf_8 -*-
"""Module for strings-method for java."""

import io
import os
import logging
import subprocess
from androguard.core.bytecodes import apk

from django.conf import settings

from MobSF.utils import (
    PrintException
)
logger = logging.getLogger(__name__)


def strings_jar(app_file, app_dir):
    """Extract the strings from an app."""
    try:
        logger.info("Extracting Strings from APK")
        dat = []
        apk_file = os.path.join(app_dir, app_file)
        and_a = apk.APK(apk_file)
        rsrc = and_a.get_android_resources() 
        pkg = rsrc.get_packages_names()[0]
        rsrc.get_strings_resources()
        for i in rsrc.values[pkg].keys():
            string = rsrc.values[pkg][i].get('string')
            if string is None:
                return dat
            for duo in string:
                dat.append('"'+duo[0]+'" : "'+duo[1]+'"') 
        return dat
    except:
        PrintException("[ERROR] Extracting Strings from APK")
