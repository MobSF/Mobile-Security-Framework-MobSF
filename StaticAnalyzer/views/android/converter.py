# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import platform
import subprocess
import os
import glob

from django.conf import settings

from StaticAnalyzer.views.android.win_fixes import (
    win_fix_python3,
    win_fix_java
)

from MobSF.utils import (
    PrintException,
    isFileExists,
    isDirExists,
    get_python
)

def get_dex_files(app_dir):
    """Get all Dex Files for analysis"""
    glob_pattern = app_dir + "*.dex"
    return glob.glob(glob_pattern)

def get_jar_files(app_dir):
    """Get all Dex Files for analysis"""
    glob_pattern = app_dir + "*.jar"
    return glob.glob(glob_pattern)

def dex_2_jar(app_path, app_dir, tools_dir):
    """Run dex2jar."""
    try:
        print("[INFO] DEX -> JAR")
        working_dir = None
        args = []

        if settings.JAR_CONVERTER == "d2j":
            print("[INFO] Using JAR converter - dex2jar")
            dexes = get_dex_files(app_dir)
            for idx, dex in enumerate(dexes):
                print ("[INFO] Converting " + dex + " to JAR")
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
                    dex,
                    '-f',
                    '-o',
                    app_dir + 'classes'+str(idx)+'.jar'
                ]
                subprocess.call(args)

        elif settings.JAR_CONVERTER == "enjarify":
            print("[INFO] Using JAR converter - Google enjarify")
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
                    python3 = get_python()
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
            subprocess.call(args, cwd=working_dir)
    except:
        PrintException("[ERROR] Converting Dex to JAR")


def dex_2_smali(app_dir, tools_dir):
    """Run dex2smali"""
    try:
        print("[INFO] DEX -> SMALI")
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            print("[INFO] Converting " + dex_path + " to Smali Code")
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
        print("[INFO] JAR -> JAVA")
        jar_files = get_jar_files(app_dir)
        output = os.path.join(app_dir, 'java_source/')
        for jar_path in jar_files:
            print ("[INFO] Decompiling " + jar_path + " to Java Code")
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
                    jd_path = os.path.join(tools_dir, 'cfr_0_128.jar')
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
