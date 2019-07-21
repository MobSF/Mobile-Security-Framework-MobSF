# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import glob
import logging
import os
import platform
import subprocess

from django.conf import settings

from MobSF.utils import (filename_from_path, get_python, is_dir_exists,
                         is_file_exists)

from StaticAnalyzer.views.android.win_fixes import (win_fix_java,
                                                    win_fix_python3)

logger = logging.getLogger(__name__)


def get_dex_files(app_dir):
    """Get all Dex Files for analysis."""
    glob_pattern = app_dir + '*.dex'
    return glob.glob(glob_pattern)


def get_jar_files(app_dir):
    """Get all Dex Files for analysis."""
    glob_pattern = app_dir + '*.jar'
    return glob.glob(glob_pattern)


def dex_2_jar(app_path, app_dir, tools_dir):
    """Run dex2jar."""
    try:
        logger.info('DEX -> JAR')
        working_dir = None
        args = []

        if settings.JAR_CONVERTER == 'd2j':
            logger.info('Using JAR converter - dex2jar')
            dexes = get_dex_files(app_dir)
            for idx, dex in enumerate(dexes):
                logger.info('Converting %s to JAR',
                            filename_from_path(dex))
                if (len(settings.DEX2JAR_BINARY) > 0
                        and is_file_exists(settings.DEX2JAR_BINARY)):
                    d2j = settings.DEX2JAR_BINARY
                else:
                    if platform.system() == 'Windows':
                        win_fix_java(tools_dir)
                        d2j = os.path.join(tools_dir, 'd2j2/d2j-dex2jar.bat')
                    else:
                        inv = os.path.join(tools_dir, 'd2j2/d2j_invoke.sh')
                        d2j = os.path.join(tools_dir, 'd2j2/d2j-dex2jar.sh')
                        os.chmod(d2j, 0o777)
                        os.chmod(inv, 0o777)
                args = [
                    d2j,
                    dex,
                    '-f',
                    '-o',
                    app_dir + 'classes' + str(idx) + '.jar',
                ]
                subprocess.call(args)

        elif settings.JAR_CONVERTER == 'enjarify':
            logger.info('Using JAR converter - Google enjarify')
            if (len(settings.ENJARIFY_DIRECTORY) > 0
                    and is_dir_exists(settings.ENJARIFY_DIRECTORY)):
                working_dir = settings.ENJARIFY_DIRECTORY
            else:
                working_dir = os.path.join(tools_dir, 'enjarify/')
            if platform.system() == 'Windows':
                win_fix_python3(tools_dir)
                enjarify = os.path.join(working_dir, 'enjarify.bat')
                args = [enjarify, app_path, '-f',
                        '-o', app_dir + 'classes.jar']
            else:
                if len(settings.PYTHON3_PATH) > 2:
                    python3 = os.path.join(settings.PYTHON3_PATH, 'python3')
                else:
                    python3 = get_python()
                args = [
                    python3,
                    '-O',
                    '-m',
                    'enjarify.main',
                    app_path,
                    '-f',
                    '-o',
                    app_dir + 'classes.jar',
                ]
            subprocess.call(args, cwd=working_dir)
    except Exception:
        logger.exception('Converting Dex to JAR')


def dex_2_smali(app_dir, tools_dir):
    """Run dex2smali."""
    try:
        logger.info('DEX -> SMALI')
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            logger.info('Converting %s to Smali Code',
                        filename_from_path(dex_path))
            if (len(settings.BACKSMALI_BINARY) > 0
                    and is_file_exists(settings.BACKSMALI_BINARY)):
                bs_path = settings.BACKSMALI_BINARY
            else:
                bs_path = os.path.join(tools_dir, 'baksmali-2.2.7.jar')
            output = os.path.join(app_dir, 'smali_source/')
            args = [
                settings.JAVA_BINARY,
                '-jar',
                bs_path,
                'd',
                dex_path,
                '-o',
                output,
            ]
            subprocess.call(args)
    except Exception:
        logger.exception('Converting DEX to SMALI')


def jar_2_java(app_dir, tools_dir):
    """Conver jar to java."""
    try:
        logger.info('JAR -> JAVA')
        jar_files = get_jar_files(app_dir)
        output = os.path.join(app_dir, 'java_source/')
        for jar_path in jar_files:
            logger.info(
                'Decompiling %s to Java Code',
                filename_from_path(jar_path))
            if settings.DECOMPILER == 'jd-core':
                ext_jdcore = settings.JD_CORE_DECOMPILER_BINARY
                if (len(ext_jdcore) > 0
                        and is_file_exists(ext_jdcore)):
                    jd_path = ext_jdcore
                else:
                    jd_path = os.path.join(tools_dir, 'jd-core.jar')
                args = [settings.JAVA_BINARY,
                        '-jar',
                        jd_path,
                        jar_path,
                        output]
            elif settings.DECOMPILER == 'cfr':
                ext_cfr = settings.CFR_DECOMPILER_BINARY
                if (len(ext_cfr) > 0
                        and is_file_exists(ext_cfr)):
                    jd_path = ext_cfr
                else:
                    jd_path = os.path.join(tools_dir, 'cfr-0.144.jar')
                args = [settings.JAVA_BINARY,
                        '-jar',
                        jd_path,
                        jar_path,
                        '--outputdir',
                        output,
                        '--silent',
                        'true']
            elif settings.DECOMPILER == 'procyon':
                ext_proc = settings.PROCYON_DECOMPILER_BINARY
                if (len(ext_proc) > 0
                        and is_file_exists(ext_proc)):
                    pd_path = ext_proc
                else:
                    pd_path = os.path.join(
                        tools_dir, 'procyon-decompiler-0.5.34.jar')
                args = [settings.JAVA_BINARY,
                        '-jar',
                        pd_path,
                        jar_path,
                        '-o',
                        output]
            subprocess.call(args)
    except Exception:
        logger.exception('Converting JAR to JAVA')
