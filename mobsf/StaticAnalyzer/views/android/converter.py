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
from pathlib import Path
from tempfile import gettempdir

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
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


def dex_2_smali(checksum, app_dir, tools_dir):
    """Run dex2smali."""
    try:
        if not settings_enabled('DEX2SMALI_ENABLED'):
            return
        msg = 'Converting DEX to Smali'
        logger.info(msg)
        append_scan_status(checksum, msg)
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            try:
                logger.info('Converting %s to Smali Code',
                            filename_from_path(dex_path))
                if (len(settings.BACKSMALI_BINARY) > 0
                        and is_file_exists(settings.BACKSMALI_BINARY)):
                    bs_path = settings.BACKSMALI_BINARY
                else:
                    bs_path = os.path.join(tools_dir, 'baksmali-3.0.8-dev-fat.jar')
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
    except Exception as exp:
        msg = 'Failed to convert DEX to Smali'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def apk_2_java(checksum, app_path, app_dir, dwd_tools_dir):
    """Run JADX to decompile APK or all DEX files to Java source code."""
    try:
        jadx_version = '1.5.0'
        jadx_base_path = Path(dwd_tools_dir) / 'jadx' / f'jadx-{jadx_version}' / 'bin'
        output_dir = Path(app_dir) / 'java_source'

        msg = 'Decompiling APK to Java with JADX'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # Clean output directory if it exists
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)

        # Determine JADX executable path
        if (len(settings.JADX_BINARY) > 0
                and is_file_exists(settings.JADX_BINARY)):
            jadx = Path(settings.JADX_BINARY)
        elif platform.system() == 'Windows':
            jadx = jadx_base_path / 'jadx.bat'
        else:
            jadx = jadx_base_path / 'jadx'

        # Ensure JADX has execute permissions
        if not os.access(str(jadx), os.X_OK):
            os.chmod(str(jadx), stat.S_IEXEC)

        # Prepare the base arguments for JADX
        def run_jadx(arguments):
            """Run JADX command with the specified arguments."""
            with open(os.devnull, 'w') as fnull:
                return subprocess.run(
                    arguments,
                    stdout=fnull,
                    stderr=subprocess.STDOUT,
                    timeout=settings.JADX_TIMEOUT)

        # First attempt to decompile APK
        args = [
            str(jadx), '-ds', str(output_dir),
            '-q', '-r', '--show-bad-code', app_path]
        result = run_jadx(args)
        if result.returncode == 0:
            return  # Success

        # If APK decompilation fails, attempt to decompile all DEX files recursively
        msg = 'Decompiling with JADX failed, attempting on all DEX files'
        logger.warning(msg)
        append_scan_status(checksum, msg)

        dex_files = Path(app_path).parent.rglob('*.dex')
        decompile_failed = False

        for dex_file in dex_files:
            msg = f'Decompiling {dex_file.name} with JADX'
            logger.info(msg)
            append_scan_status(checksum, msg)

            # Update argument to point to the current DEX file
            args[-1] = str(dex_file)
            result_dex = run_jadx(args)

            if result_dex.returncode != 0:
                decompile_failed = True
                msg = f'Decompiling with JADX failed for {dex_file.name}'
                logger.error(msg)
                append_scan_status(checksum, msg)

        if decompile_failed:
            msg = 'Some DEX files failed to decompile'
            logger.error(msg)
            append_scan_status(checksum, msg)

    except subprocess.TimeoutExpired as exp:
        msg = 'Decompiling with JADX timed out'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    except Exception as exp:
        msg = 'Decompiling with JADX failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def run_apktool(app_path, app_dir, tools_dir):
    """Get readable AndroidManifest.xml from APK."""
    try:
        if (len(settings.APKTOOL_BINARY) > 0
                and Path(settings.APKTOOL_BINARY).exists()):
            apktool_path = Path(settings.APKTOOL_BINARY)
        else:
            apktool_path = tools_dir / 'apktool_2.10.0.jar'

        # Prepare output directory and manifest file paths
        output_dir = app_dir / 'apktool_out'
        # Run apktool to extract AndroidManifest.xml
        args = [find_java_binary(),
                '-jar',
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                str(apktool_path),
                '--match-original',
                '--frame-path',
                gettempdir(),
                '-f', '-s', 'd',
                str(app_path),
                '-o',
                str(output_dir)]
        logger.info('Converting AXML to XML with apktool')
        with open(os.devnull, 'w') as fnull:
            subprocess.run(
                args,
                stdout=fnull,
                stderr=subprocess.STDOUT,
                timeout=settings.JADX_TIMEOUT)
    except Exception:
        logger.warning('apktool failed to extract AndroidManifest.xml')
