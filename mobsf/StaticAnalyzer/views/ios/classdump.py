# -*- coding: utf_8 -*-
"""Handle Classdump for iOS binaries."""

import logging
import os
import platform
import stat
import subprocess

from django.conf import settings

from mobsf.MobSF.utils import is_file_exists


logger = logging.getLogger(__name__)


def classdump_mac(clsdmp_bin, tools_dir, ipa_bin):
    """Run Classdump for Objective-C/Swift."""
    if clsdmp_bin == 'class-dump-swift':
        logger.info('Running class-dump-swift against binary')
        external = settings.CLASSDUMP_SWIFT_BINARY
    else:
        logger.info('Running class-dump against binary')
        external = settings.CLASSDUMP_BINARY
    if (len(external) > 0
            and is_file_exists(external)):
        class_dump_bin = external
    else:
        class_dump_bin = os.path.join(
            tools_dir, clsdmp_bin)
    # Execute permission check
    if not os.access(class_dump_bin, os.X_OK):
        os.chmod(class_dump_bin, stat.S_IEXEC)
    return subprocess.check_output(
        [class_dump_bin, ipa_bin],
        stderr=subprocess.DEVNULL)


def classdump_linux(tools_dir, ipa_bin):
    """Run Classdump on Linux."""
    try:
        if (len(settings.JTOOL_BINARY) > 0
                and is_file_exists(settings.JTOOL_BINARY)):
            jtool_bin = settings.JTOOL_BINARY
        else:
            jtool_bin = os.path.join(tools_dir, 'jtool.ELF64')
        if not os.access(jtool_bin, os.X_OK):
            os.chmod(jtool_bin, stat.S_IEXEC)
        logger.info('Running jtool against the binary for dumping classes')
        args = [jtool_bin, '-arch', 'arm', '-d', 'objc', '-v', ipa_bin]
        # timeout to handle possible deadlock from jtool1
        return subprocess.check_output(
            args,
            stderr=subprocess.DEVNULL,
            timeout=60)
    except Exception:
        return b''


def get_class_dump(tools_dir, bin_path, app_dir, bin_type):
    """Running Classdump on binary."""
    try:
        bin_path = bin_path.as_posix()
        cdump = b''
        logger.info('Dumping classes')
        if platform.system() == 'Darwin':
            if bin_type == 'Swift':
                try:
                    cdump = classdump_mac(
                        'class-dump-swift',
                        tools_dir,
                        bin_path,
                    )
                except Exception:
                    cdump = classdump_mac(
                        'class-dump',
                        tools_dir,
                        bin_path,
                    )
            else:
                try:
                    cdump = classdump_mac(
                        'class-dump',
                        tools_dir,
                        bin_path,
                    )
                except Exception:
                    cdump = classdump_mac(
                        'class-dump-swift',
                        tools_dir,
                        bin_path,
                    )
            if b'Source: (null)' in cdump:
                # Run failsafe if classdump failed
                logger.info('Running fail safe class-dump-swift')
                cdump = classdump_mac(
                    'class-dump-swift',
                    tools_dir,
                    bin_path,
                )
        elif platform.system() == 'Linux':
            cdump = classdump_linux(tools_dir, bin_path)
        else:
            # Platform not supported
            logger.warning('class-dump is not supported in this platform')
        with open(os.path.join(app_dir, 'classdump.txt'), 'wb') as flip:
            flip.write(cdump)
        return cdump
    except Exception:
        logger.error('class-dump/class-dump-swift failed on this binary')
    return cdump
