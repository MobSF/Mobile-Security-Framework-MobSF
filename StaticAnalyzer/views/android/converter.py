# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import platform
import subprocess
import os

from django.conf import settings

from StaticAnalyzer.views.android.win_fixes import (
    win_fix_python3,
    win_fix_java
)

from MobSF.utils import (
    PrintException,
    isFileExists,
    isDirExists
)


def dex_2_jar(app_path, app_dir, tools_dir):
    """Run dex2jar."""
    try:
        print "[INFO] DEX -> JAR"
        working_dir = None
        args = []
        if settings.JAR_CONVERTER == "d2j":
            print "[INFO] Using JAR converter - dex2jar"
            if len(settings.DEX2JAR_BINARY) > 0 and isFileExists(settings.DEX2JAR_BINARY):
                d2j = settings.DEX2JAR_BINARY
            else:
                if platform.system() == "Windows":
                    win_fix_java(tools_dir)
                    d2j = os.path.join(tools_dir, 'd2j2/d2j-dex2jar.bat')
                else:
                    inv = os.path.join(tools_dir, 'd2j2/d2j_invoke.sh')
                    d2j = os.path.join(tools_dir, 'd2j2/d2j-dex2jar.sh')
                    subprocess.call(["chmod", "777", d2j])
                    subprocess.call(["chmod", "777", inv])
            args = [
                d2j,
                app_dir + 'classes.dex',
                '-f',
                '-o',
                app_dir + 'classes.jar'
            ]
        elif settings.JAR_CONVERTER == "enjarify":
            print "[INFO] Using JAR converter - Google enjarify"
            if len(settings.ENJARIFY_DIRECTORY) > 0 and isDirExists(settings.ENJARIFY_DIRECTORY):
                working_dir = settings.ENJARIFY_DIRECTORY
            else:
                working_dir = os.path.join(tools_dir, 'enjarify/')
            if platform.system() == "Windows":
                win_fix_python3(tools_dir)
                enjarify = os.path.join(working_dir, 'enjarify.bat')
                args = [enjarify, app_path, "-f",
                        "-o", app_dir + 'classes.jar']
            else:
                if len(settings.PYTHON3_PATH) > 2:
                    python3 = os.path.join(settings.PYTHON3_PATH, "python3")
                else:
                    python3 = "python3"
                args = [
                    python3,
                    "-O",
                    "-m",
                    "enjarify.main",
                    app_path,
                    "-f",
                    "-o",
                    app_dir + 'classes.jar'
                ]
        if working_dir:
            subprocess.call(args, cwd=working_dir)
        else:
            subprocess.call(args)
    except:
        PrintException("[ERROR] Converting Dex to JAR")


def dex_2_smali(app_dir, tools_dir):
    """Run dex2smali"""
    try:
        print "[INFO] DEX -> SMALI"
        dex_path = app_dir + 'classes.dex'
        if len(settings.BACKSMALI_BINARY) > 0 and isFileExists(settings.BACKSMALI_BINARY):
            bs_path = settings.BACKSMALI_BINARY
        else:
            bs_path = os.path.join(tools_dir, 'baksmali.jar')
        output = os.path.join(app_dir, 'smali_source/')
        args = [
            settings.JAVA_PATH + 'java',
            '-jar', bs_path, dex_path, '-o', output
        ]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting DEX to SMALI")


def jar_2_java(app_dir, tools_dir):
    """Conver jar to java."""
    try:
        print "[INFO] JAR -> JAVA"
        jar_path = app_dir + 'classes.jar'
        output = os.path.join(app_dir, 'java_source/')
        if settings.DECOMPILER == 'jd-core':
            if (
                    len(settings.JD_CORE_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.JD_CORE_DECOMPILER_BINARY)
            ):
                jd_path = settings.JD_CORE_DECOMPILER_BINARY
            else:
                jd_path = os.path.join(tools_dir, 'jd-core.jar')
            args = [settings.JAVA_PATH + 'java',
                    '-jar', jd_path, jar_path, output]
        elif settings.DECOMPILER == 'cfr':
            if (
                    len(settings.CFR_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.CFR_DECOMPILER_BINARY)
            ):
                jd_path = settings.CFR_DECOMPILER_BINARY
            else:
                jd_path = os.path.join(tools_dir, 'cfr_0_119.jar')
            args = [settings.JAVA_PATH + 'java', '-jar',
                    jd_path, jar_path, '--outputdir', output]
        elif settings.DECOMPILER == "procyon":
            if (
                    len(settings.PROCYON_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.PROCYON_DECOMPILER_BINARY)
            ):
                pd_path = settings.PROCYON_DECOMPILER_BINARY
            else:
                pd_path = os.path.join(
                    tools_dir, 'procyon-decompiler-0.5.30.jar')
            args = [settings.JAVA_PATH + 'java',
                    '-jar', pd_path, jar_path, '-o', output]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting JAR to JAVA")
