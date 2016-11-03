# -*- coding: utf_8 -*-
"""Holds the different winfixes."""

import os

from django.conf import settings

from MobSF.utils import (
    PrintException
)

def win_fix_java(tools_dir):
    """Runn JAVA path fix in Windows"""
    try:
        print "[INFO] Running JAVA path fix in Windows"
        dmy = os.path.join(tools_dir, 'd2j2/d2j_invoke.tmp')
        org = os.path.join(tools_dir, 'd2j2/d2j_invoke.bat')
        dat = ''
        with open(dmy, 'r') as file_pointer:
            dat = file_pointer.read().replace("[xxx]", settings.JAVA_PATH + "java")
        with open(org, 'w') as file_pointer:
            file_pointer.write(dat)
    except:
        PrintException("[ERROR] Running JAVA path fix in Windows")


def win_fix_python3(tools_dir):
    """Runn Python 3 path fix in Windows."""
    try:
        print "[INFO] Running Python 3 path fix in Windows"
        python3_path = ""
        if len(settings.PYTHON3_PATH) > 2:
            python3_path = settings.python3_path
        else:
            pathenv = os.environ["path"]
            if pathenv:
                paths = pathenv.split(";")
                for path in paths:
                    if "python3" in path.lower():
                        python3_path = path
        python3 = "\"" + os.path.join(python3_path, "python") + "\""
        dmy = os.path.join(tools_dir, 'enjarify/enjarify.tmp')
        org = os.path.join(tools_dir, 'enjarify/enjarify.bat')
        dat = ''
        with open(dmy, 'r') as file_pointer:
            dat = file_pointer.read().replace("[xxx]", python3)
        with open(org, 'w') as file_pointer:
            file_pointer.write(dat)
    except:
        PrintException("[ERROR] Running Python 3 path fix in Windows")
