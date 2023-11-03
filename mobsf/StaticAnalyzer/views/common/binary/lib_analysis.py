import logging
from pathlib import Path

import lief

from mobsf.MobSF.utils import (
    settings_enabled,
)
from mobsf.StaticAnalyzer.views.common.binary.elf import (
    ELFChecksec,
)
from mobsf.StaticAnalyzer.views.common.binary.macho import (
    MachOChecksec,
)


logger = logging.getLogger(__name__)


def library_analysis(src, arch):
    """Perform library binary analysis."""
    res = {
        f'{arch}_analysis': [],
        f'{arch}_strings': [],
        f'{arch}_symbols': [],
    }
    try:
        if arch == 'macho':
            analysis = MachOChecksec
            ext = '*.dylib'
            if not settings_enabled('DYLIB_ANALYSIS_ENABLED'):
                return res
        elif arch == 'elf':
            analysis = ELFChecksec
            ext = '*.so'
            if not settings_enabled('SO_ANALYSIS_ENABLED'):
                return res
        elif arch == 'ar':
            ext = '*.o'
            res[f'{arch}_a'] = ''
        logger.info('Library Binary Analysis Started')
        # Supports Static Library, Shared objects, Dynamic Library,
        # from APK, SO, AAR, JAR, IPA, DYLIB, and A
        for libfile in Path(src).rglob(ext):
            rel_path = (
                f'{libfile.parents[1].name}/'
                f'{libfile.parents[0].name}/'
                f'{libfile.name}')
            logger.info('Analyzing %s', rel_path)
            if arch == 'ar':
                # Handle static library
                if lief.is_macho(libfile.as_posix()):
                    analysis = MachOChecksec
                    res[f'{arch}_a'] = 'MachO'
                elif lief.is_elf(libfile.as_posix()):
                    analysis = ELFChecksec
                    res[f'{arch}_a'] = 'ELF'
                else:
                    continue
            chk = analysis(libfile, rel_path)
            chksec = chk.checksec()
            strings = chk.strings()
            symbols = chk.get_symbols()

            if chksec:
                res[f'{arch}_analysis'].append(chksec)
            if strings:
                res[f'{arch}_strings'].append({
                    rel_path: strings})
            if symbols:
                res[f'{arch}_symbols'].append({
                    rel_path: symbols})
        if ext == '*.dylib':
            # Do Framework Analysis for iOS
            res['framework_analysis'] = []
            res['framework_strings'] = []
            res['framework_symbols'] = []
            frameworks_analysis(src, res)
            if res['framework_strings']:
                res[f'{arch}_strings'].extend(
                    res['framework_strings'])
    except Exception:
        logger.exception('Performing Library Binary Analysis')
    return res


def frameworks_analysis(src, res):
    """Binary Analysis on Frameworks."""
    try:
        logger.info('Framework Binary Analysis Started')
        # Supports iOS Frameworks
        for ffile in Path(src).rglob('*'):
            parent = ffile.parents[0].name
            if not parent.endswith('.framework'):
                continue
            rel_path = (
                f'{ffile.parents[1].name}/'
                f'{ffile.parents[0].name}/'
                f'{ffile.name}')
            if ffile.suffix != '' or ffile.name not in parent:
                continue
            # Frameworks/XXX.framework/XXX
            logger.info('Analyzing %s', rel_path)
            chk = MachOChecksec(ffile, rel_path)
            chksec = chk.checksec()
            strings = chk.strings()
            symbols = chk.get_symbols()
            if chksec:
                res['framework_analysis'].append(chksec)
            if strings:
                res['framework_strings'].append({
                    rel_path: strings})
            if symbols:
                res['framework_symbols'].append({
                    rel_path: symbols})
    except Exception:
        logger.exception('Performing Framework Binary Analysis')
