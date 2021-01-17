# -*- coding: utf_8 -*-
"""Module for iOS IPA Binary Analysis."""

import logging
from pathlib import Path

from macholib.mach_o import (CPU_TYPE_NAMES, MH_CIGAM_64, MH_MAGIC_64,
                             get_cpu_subtype)
from macholib.MachO import MachO

from mobsf.StaticAnalyzer.views.ios.classdump import (
    get_class_dump,
)
from mobsf.StaticAnalyzer.views.ios.macho_analysis import (
    macho_analysis,
)
from mobsf.StaticAnalyzer.views.ios.binary_rule_matcher import (
    binary_rule_matcher,
)
from mobsf.StaticAnalyzer.tools.strings import (
    strings_util,
)

logger = logging.getLogger(__name__)


def detect_bin_type(libs):
    """Detect IPA binary type."""
    if any('libswiftCore.dylib' in itm for itm in libs):
        return 'Swift'
    else:
        return 'Objective C'


def strings_on_ipa(bin_path):
    """Extract Strings from IPA."""
    try:
        logger.info('Running strings against the Binary')
        unique_str = []
        unique_str = list(set(strings_util(bin_path.as_posix())))
        return unique_str
    except Exception:
        logger.exception('Running strings against the Binary')


def get_bin_info(bin_file):
    """Get Binary Information."""
    logger.info('Getting Binary Information')
    m = MachO(bin_file.as_posix())
    for header in m.headers:
        if header.MH_MAGIC == MH_MAGIC_64 or header.MH_MAGIC == MH_CIGAM_64:
            sz = '64-bit'
        else:
            sz = '32-bit'
        arch = CPU_TYPE_NAMES.get(
            header.header.cputype, header.header.cputype)
        subarch = get_cpu_subtype(
            header.header.cputype, header.header.cpusubtype)
        return {'endian': header.endian,
                'bit': sz,
                'arch': arch,
                'subarch': subarch}


def binary_analysis(src, tools_dir, app_dir, executable_name):
    """Binary Analysis of IPA."""
    bin_dict = {
        'checksec': {},
        'libraries': [],
        'bin_code_analysis': {},
        'strings': [],
        'bin_info': {},
        'bin_type': '',
    }
    try:
        binary_findings = {}
        logger.info('Starting Binary Analysis')
        dirs = Path(src).glob('*')
        dot_app_dir = ''
        bin_name = ''
        for dir_ in dirs:
            if dir_.suffix == '.app':
                dot_app_dir = dir_.as_posix()
                break
        # Bin Dir - Dir/Payload/x.app/
        bin_dir = Path(src) / dot_app_dir
        if not executable_name:
            bin_name = dot_app_dir.replace('.app', '')
        else:
            _bin = bin_dir / executable_name
            if _bin.exists():
                bin_name = executable_name
        # Bin Path - Dir/Payload/x.app/x
        bin_path = bin_dir / bin_name
        if not (bin_path.exists() or bin_path.is_file()):
            logger.warning(
                'MobSF Cannot find binary in %s', bin_path.as_posix())
            logger.warning('Skipping Binary analysis')
        else:
            macho = macho_analysis(bin_path)
            bin_info = get_bin_info(bin_path)
            bin_type = detect_bin_type(macho['libraries'])
            classdump = get_class_dump(
                tools_dir,
                bin_path,
                app_dir, bin_type)
            binary_rule_matcher(
                binary_findings,
                macho['symbols'], classdump)
            strings_in_ipa = strings_on_ipa(bin_path)
            bin_dict['checksec'] = macho['checksec']
            bin_dict['libraries'] = macho['libraries']
            bin_dict['bin_code_analysis'] = binary_findings
            bin_dict['strings'] = strings_in_ipa
            bin_dict['bin_info'] = bin_info
            bin_dict['bin_type'] = bin_type
    except Exception:
        logger.exception('IPA Binary Analysis')
    return bin_dict
