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
                res[f'{arch}_a'] = ''
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
    except Exception:
        logger.exception('Performing Library Binary Analysis')
    return res
