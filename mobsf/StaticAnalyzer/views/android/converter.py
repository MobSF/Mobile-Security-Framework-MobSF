# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import glob
import logging
import os
import platform
import shutil
import subprocess
import threading
import stat

from django.conf import settings

from mobsf.MobSF.utils import (
    filename_from_path,
    find_java_binary,
    is_file_exists,
    settings_enabled,
)


logger = logging.getLogger(__name__)


def get_dex_files(app_dir):
    """Get all Dex Files for analysis."""
    glob_pattern = app_dir + '*.dex'
    return glob.glob(glob_pattern)


def dex_2_smali(app_dir, tools_dir):
    """Run dex2smali."""
    try:
        if not settings_enabled('DEX2SMALI_ENABLED'):
            return
        logger.info('DEX -> SMALI')
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            try:
                logger.info('Converting %s to Smali Code',
                            filename_from_path(dex_path))
                if (len(settings.BACKSMALI_BINARY) > 0
                        and is_file_exists(settings.BACKSMALI_BINARY)):
                    bs_path = settings.BACKSMALI_BINARY
                else:
                    bs_path = os.path.join(tools_dir, 'baksmali-2.5.2.jar')
                output = os.path.join(app_dir, 'smali_source/')
                smali = [
                    find_java_binary(),
                    '-jar',
                    bs_path,
                    'd',
                    dex_path,
                    '-o',
                    output,
                ]
                trd = threading.Thread(target=subprocess.call, args=(smali,))
                trd.daemon = True
                trd.start()
            except Exception:
                # Fixes a bug #2014
                pass
    except Exception:
        logger.exception('Converting DEX to SMALI')


def apk_2_java(app_path, app_dir, tools_dir):
    """Run jadx."""
    try:
        logger.info('APK -> JAVA')
        args = []
        output = os.path.join(app_dir, 'java_source/')
        logger.info('Decompiling to Java with jadx')

        if os.path.exists(output):
            # ignore WinError3 in Windows
            shutil.rmtree(output, ignore_errors=True)

        if (len(settings.JADX_BINARY) > 0
                and is_file_exists(settings.JADX_BINARY)):
            jadx = settings.JADX_BINARY
        elif platform.system() == 'Windows':
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx.bat')
        else:
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx')
        # Set execute permission, if JADX is not executable
        if not os.access(jadx, os.X_OK):
            os.chmod(jadx, stat.S_IEXEC)
        args = [
            jadx,
            '-ds',
            output,
            '-q',
            '-r',
            '--show-bad-code',
            app_path,
        ]
        fnull = open(os.devnull, 'w')
        subprocess.run(args,
                       stdout=fnull,
                       stderr=subprocess.STDOUT,
                       timeout=settings.JADX_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.warning('Decompiling with jadx timed out')
    except Exception:
        logger.exception('Decompiling to JAVA')
