# -*- coding: utf_8 -*-
"""Handle Classdump for iOS binaries."""

import logging
import os
import platform
import stat
import subprocess

import lief

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    is_file_exists,
)


logger = logging.getLogger(__name__)
OBJC_STRING_SECTIONS = (
    '__objc_classname',
    '__objc_methname',
    '__swift5_reflstr',
    '__swift5_typeref',
    '__cstring',
)


def classdump_lief(ipa_bin):
    """Extract Objective-C and Swift class/selector names via LIEF."""
    entries = []
    seen = set()
    try:
        fat = lief.MachO.parse(ipa_bin)
        if not fat:
            return b''
        for binary in fat:
            for section in binary.sections:
                if section.name not in OBJC_STRING_SECTIONS:
                    continue
                for token in bytes(section.content).split(b'\x00'):
                    if len(token) > 1 and token.isascii() and token not in seen:
                        seen.add(token)
                        entries.append(token)
    except Exception:
        logger.warning('Failed to extract Objective-C/Swift metadata via LIEF')
    return b'\n'.join(entries)


def classdump_mac(checksum, clsdmp_bin, tools_dir, ipa_bin):
    """Run Classdump for Objective-C/Swift."""
    if clsdmp_bin == 'class-dump-swift':
        external = settings.CLASSDUMP_SWIFT_BINARY
    else:
        external = settings.CLASSDUMP_BINARY
    msg = f'Running {clsdmp_bin} against binary'
    logger.info(msg)
    append_scan_status(checksum, msg)
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


def classdump_linux(checksum, tools_dir, ipa_bin):
    """Run Classdump on Linux."""
    try:
        if (len(settings.JTOOL_BINARY) > 0
                and is_file_exists(settings.JTOOL_BINARY)):
            jtool_bin = settings.JTOOL_BINARY
        else:
            jtool_bin = os.path.join(tools_dir, 'jtool.ELF64')
        if not os.access(jtool_bin, os.X_OK):
            os.chmod(jtool_bin, stat.S_IEXEC)
        msg = 'Running jtool against the binary for dumping classes'
        logger.info(msg)
        append_scan_status(checksum, msg)
        args = [jtool_bin, '-arch', 'arm', '-d', 'objc', '-v', ipa_bin]
        # timeout to handle possible deadlock from jtool1
        return subprocess.check_output(
            args,
            stderr=subprocess.DEVNULL,
            timeout=60)
    except Exception:
        return b''


def get_class_dump(checksum, tools_dir, bin_path, app_dir, bin_type):
    """Running Classdump on binary."""
    try:
        bin_path = bin_path.as_posix()
        cdump = b''
        msg = 'Dumping Classes from the binary'
        logger.info(msg)
        append_scan_status(checksum, msg)
        if platform.system() == 'Darwin':
            primary = (
                'class-dump-swift' if bin_type == 'Swift' else 'class-dump'
            )
            secondary = (
                'class-dump' if bin_type == 'Swift' else 'class-dump-swift'
            )
            try:
                cdump = classdump_mac(
                    checksum, primary, tools_dir, bin_path)
            except Exception:
                try:
                    cdump = classdump_mac(
                        checksum, secondary, tools_dir, bin_path)
                except Exception:
                    cdump = b''
            if b'Source: (null)' in cdump:
                # Run failsafe if classdump failed
                msg = 'Running fail safe class-dump-swift'
                logger.info(msg)
                append_scan_status(checksum, msg)
                try:
                    cdump = classdump_mac(
                        checksum,
                        'class-dump-swift',
                        tools_dir,
                        bin_path,
                    )
                except Exception:
                    pass
        elif platform.system() == 'Linux':
            cdump = classdump_linux(checksum, tools_dir, bin_path)
        else:
            # Platform not supported
            msg = 'class-dump is not supported in this platform'
            logger.warning(msg)
            append_scan_status(checksum, msg)
        lief_dump = classdump_lief(bin_path)
        if lief_dump:
            cdump = cdump + b'\n' + lief_dump if cdump else lief_dump
        with open(os.path.join(app_dir, 'classdump.txt'), 'wb') as flip:
            flip.write(cdump)
        return cdump
    except Exception as exp:
        msg = 'Failed to dump classes from the binary'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return cdump
