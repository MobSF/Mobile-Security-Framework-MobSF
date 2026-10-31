# -*- coding: utf_8 -*-
"""Module for iOS IPA Binary Analysis."""

import logging
from pathlib import Path

import lief

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.StaticAnalyzer.views.ios.classdump import (
    get_class_dump,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    MachOChecksec,
)
from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)
from mobsf.StaticAnalyzer.views.ios.binary_rule_matcher import (
    binary_rule_matcher,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def detect_bin_type(libs):
    """Detect IPA binary type."""
    if any('libswiftCore.dylib' in itm for itm in libs):
        return 'Swift'
    else:
        return 'Objective C'


MACHO_CPU_TYPES = {
    -1: 'ANY',
    1: 'VAX',
    6: 'MC680x0',
    7: 'i386',
    16777223: 'x86_64',
    8: 'MIPS',
    10: 'MC98000',
    11: 'HPPA',
    12: 'ARM',
    16777228: 'ARM64',
    13: 'MC88000',
    14: 'SPARC',
    15: 'i860',
    16: 'Alpha',
    18: 'PowerPC',
    16777234: 'PowerPC64',
}
MACHO_CPU_SUBTYPES = {
    7: {
        0: 'CPU_SUBTYPE_INTEL_MODEL_ALL',
        1: 'CPU_THREADTYPE_INTEL_HTT',
        3: 'CPU_SUBTYPE_I386_ALL',
        4: 'CPU_SUBTYPE_486',
        5: 'CPU_SUBTYPE_586',
        8: 'CPU_SUBTYPE_PENTIUM_3',
        9: 'CPU_SUBTYPE_PENTIUM_M',
        10: 'CPU_SUBTYPE_PENTIUM_4',
        11: 'CPU_SUBTYPE_ITANIUM',
        12: 'CPU_SUBTYPE_XEON',
        34: 'CPU_SUBTYPE_XEON_MP',
        38: 'CPU_SUBTYPE_PENTPRO',
        40: 'CPU_SUBTYPE_PENTIUM_3_M',
        42: 'CPU_SUBTYPE_PENTIUM_4_M',
        43: 'CPU_SUBTYPE_ITANIUM_2',
        52: 'CPU_SUBTYPE_PENTIUM_3_XEON',
        102: 'CPU_SUBTYPE_PENTII_M3',
        132: 'CPU_SUBTYPE_486SX',
        166: 'CPU_SUBTYPE_PENTII_M5',
        199: 'CPU_SUBTYPE_CELERON',
        231: 'CPU_SUBTYPE_CELERON_MOBILE',
    },
    16777223: {
        3: 'CPU_SUBTYPE_X86_64_ALL',
        4: 'CPU_SUBTYPE_X86_ARCH1',
        8: 'CPU_SUBTYPE_X86_64_H',
    },
    12: {
        0: 'CPU_SUBTYPE_ARM_ALL12',
        5: 'CPU_SUBTYPE_ARM_V4T',
        6: 'CPU_SUBTYPE_ARM_V6',
        7: 'CPU_SUBTYPE_ARM_V5TEJ',
        8: 'CPU_SUBTYPE_ARM_XSCALE',
        9: 'CPU_SUBTYPE_ARM_V7',
        10: 'CPU_SUBTYPE_ARM_V7F',
        11: 'CPU_SUBTYPE_ARM_V7S',
        12: 'CPU_SUBTYPE_ARM_V7K',
        13: 'CPU_SUBTYPE_ARM_V8',
        14: 'CPU_SUBTYPE_ARM_V6M',
        15: 'CPU_SUBTYPE_ARM_V7M',
        16: 'CPU_SUBTYPE_ARM_V7EM',
        17: 'CPU_SUBTYPE_ARM_V8M',
    },
    16777228: {
        0: 'CPU_SUBTYPE_ARM64_ALL',
        1: 'CPU_SUBTYPE_ARM64_V8',
        2: 'CPU_SUBTYPE_ARM64E',
    },
    18: {
        0: 'CPU_SUBTYPE_POWERPC_ALL',
        1: 'CPU_SUBTYPE_POWERPC_601',
        2: 'CPU_SUBTYPE_POWERPC_602',
        3: 'CPU_SUBTYPE_POWERPC_603',
        4: 'CPU_SUBTYPE_POWERPC_603e',
        5: 'CPU_SUBTYPE_POWERPC_603ev',
        6: 'CPU_SUBTYPE_POWERPC_604',
        7: 'CPU_SUBTYPE_POWERPC_604e',
        8: 'CPU_SUBTYPE_POWERPC_620',
        9: 'CPU_SUBTYPE_POWERPC_750',
        10: 'CPU_SUBTYPE_POWERPC_7400',
        11: 'CPU_SUBTYPE_POWERPC_7450',
        100: 'CPU_SUBTYPE_POWERPC_970',
    },
}
MACHO_CPU_SUBTYPES[16777234] = MACHO_CPU_SUBTYPES[18]


def get_bin_info(bin_file):
    """Get Binary Information."""
    logger.info('Getting Binary Information')
    fat = lief.MachO.parse(bin_file.as_posix())
    if not fat:
        return {}
    for binary in fat:
        magic = binary.header.magic
        if magic in (
                lief.MachO.MACHO_TYPES.MAGIC_64,
                lief.MachO.MACHO_TYPES.CIGAM_64):
            sz = '64-bit'
        else:
            sz = '32-bit'
        endian = '>' if magic in (
            lief.MachO.MACHO_TYPES.CIGAM,
            lief.MachO.MACHO_TYPES.CIGAM_64) else '<'
        cputype = int(binary.header.cpu_type)
        st = int(binary.header.cpu_subtype) & 0x0FFFFFFF
        arch = MACHO_CPU_TYPES.get(cputype, cputype)
        subarch = MACHO_CPU_SUBTYPES.get(cputype, {}).get(st, st)
        return {'endian': endian,
                'bit': sz,
                'arch': arch,
                'subarch': subarch}


def ipa_macho_analysis(binary):
    data = {
        'checksec': {},
        'symbols': [],
        'libraries': [],
    }
    try:
        logger.info('Running MachO Analysis on: %s', binary.name)
        cs = MachOChecksec(binary)
        chksec = cs.checksec()
        symbols = cs.get_symbols()
        libs = cs.get_libraries()
        data['checksec'] = chksec
        data['symbols'] = symbols
        data['libraries'] = libs
    except Exception:
        logger.exception('Running MachO Analysis')
    return data


def binary_analysis(
        checksum, src, tools_dir, app_dir, executable_name, app_root=None):
    """Binary Analysis of IPA."""
    bin_dict = {
        'checksec': {},
        'libraries': [],
        'bin_code_analysis': {},
        'strings': [],
        'bin_info': {},
        'bin_type': '',
        'bin_path': None,
    }
    try:
        binary_findings = {}
        msg = 'Starting Binary Analysis'
        logger.info(msg)
        append_scan_status(checksum, msg)

        scan_root = Path(app_dir)
        payload_root = Path(src)
        dot_app_path = Path(app_root) if app_root else next(
            payload_root.glob('**/*.app'), None)

        if not dot_app_path:
            logger.warning('Could not find .app directory.')
            return bin_dict

        try:
            app_relative = dot_app_path.relative_to(scan_root)
            payload_relative = dot_app_path.relative_to(payload_root)
        except ValueError:
            logger.warning('Application bundle escapes scan directory.')
            return bin_dict
        if (not is_safe_path(scan_root, dot_app_path, app_relative)
                or not is_safe_path(
                    payload_root, dot_app_path, payload_relative)
                or not dot_app_path.is_dir()
                or is_pipe_or_link(dot_app_path)):
            logger.warning('Unsafe application bundle path.')
            return bin_dict

        if not executable_name:
            bin_name = dot_app_path.stem
        else:
            if is_path_traversal(executable_name):
                logger.warning('Unsafe CFBundleExecutable value.')
                return bin_dict
            _bin = dot_app_path / executable_name
            if not is_safe_path(
                    dot_app_path, _bin, executable_name):
                logger.warning('Executable escapes application bundle.')
                return bin_dict
            if (_bin.exists()
                    and _bin.is_file()
                    and not is_pipe_or_link(_bin)):
                bin_name = executable_name
            else:
                bin_name = dot_app_path.stem

        bin_path = dot_app_path / bin_name

        if (is_path_traversal(bin_name)
                or not is_safe_path(dot_app_path, bin_path, bin_name)
                or not bin_path.exists()
                or not bin_path.is_file()
                or is_pipe_or_link(bin_path)):
            msg = (
                f'MobSF Cannot find binary in {bin_path.as_posix()}. '
                'Skipping Binary Analysis.')
            logger.warning(msg)
            append_scan_status(checksum, 'Skipping binary analysis', msg)
        else:
            macho = ipa_macho_analysis(bin_path)
            bin_info = get_bin_info(bin_path)
            bin_type = detect_bin_type(macho['libraries'])
            classdump = get_class_dump(
                checksum,
                tools_dir,
                bin_path,
                app_dir,
                bin_type)
            binary_rule_matcher(
                checksum,
                binary_findings,
                macho['symbols'], classdump)
            bin_dict['checksec'] = macho['checksec']
            bin_dict['libraries'] = macho['libraries']
            bin_dict['bin_code_analysis'] = binary_findings
            bin_dict['bin_info'] = bin_info
            bin_dict['bin_type'] = bin_type
            logger.info('Running strings against the Binary')
            bin_dict['strings'] = strings_on_binary(bin_path.as_posix())
            bin_dict['bin_path'] = bin_path
    except Exception as exp:
        msg = 'Failed to run IPA Binary Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return bin_dict
