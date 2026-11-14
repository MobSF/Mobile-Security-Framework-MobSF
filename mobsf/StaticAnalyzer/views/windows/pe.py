# -*- coding: utf_8 -*-
"""Windows PE binary hardening checks using lief."""
import logging
import struct

import lief

from django.conf import settings

from mobsf.MobSF.utils import run_with_timeout

logger = logging.getLogger(__name__)

HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'
NA = 'Not Applicable'

DLL_FLAGS = lief.PE.OptionalHeader.DLL_CHARACTERISTICS
SECTION_FLAGS = lief.PE.Section.CHARACTERISTICS
MACHINES = lief.PE.Header.MACHINE_TYPES

COR_ILONLY = 0x1
COR_HEADER_SIZE = 24

# Microsoft SDL banned APIs (banned.h). A and W variants are matched
# by stripping the suffix.
BANNED_APIS = {
    'strcpy', 'wcscpy', '_tcscpy', '_mbscpy', 'strcpya', 'strcpyw',
    'lstrcpy', 'lstrcpya', 'lstrcpyw', 'strcpyn', 'strncpy', 'wcsncpy',
    '_tcsncpy', '_mbsncpy', 'lstrcpyn', 'strcat', 'wcscat', '_tcscat',
    '_mbscat', 'strcata', 'strcatw', 'lstrcat', 'lstrcata', 'lstrcatw',
    'strncat', 'wcsncat', '_tcsncat', '_mbsncat', 'lstrcatn', 'sprintf',
    'swprintf', 'wsprintf', 'wsprintfa', 'wsprintfw', '_stprintf',
    'vsprintf', 'vswprintf', 'wvsprintf', 'wvsprintfa', 'wvsprintfw',
    '_vstprintf', 'strtok', 'wcstok', '_tcstok', '_mbstok', 'gets',
    '_getws', '_getts', 'makepath', '_makepath', '_wmakepath',
    '_splitpath', '_wsplitpath', 'itoa', '_itoa', '_itow', '_ltoa',
    '_ltow', '_ultoa', '_ultow', 'alloca', '_alloca', 'scanf', 'wscanf',
    'sscanf', 'swscanf', 'chartooem', 'oemtochar',
}


def _check(value, severity, description):
    return {
        'value': value,
        'severity': severity,
        'description': description,
    }


def _clr_flags(binary):
    """Return COR20 header flags, or None for native images."""
    try:
        clr = binary.data_directory(
            lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER)
        if not clr or not clr.rva or clr.size < COR_HEADER_SIZE:
            return None
        raw = bytes(binary.get_content_from_virtual_address(
            clr.rva, COR_HEADER_SIZE))
        if len(raw) < COR_HEADER_SIZE:
            return None
        return struct.unpack_from('<I', raw, 16)[0]
    except Exception:
        return None


class PEChecksec:
    """Binary hardening checks for one PE image."""

    def __init__(self, pe_path, rel_path):
        self.rel_path = rel_path
        self.binary = run_with_timeout(
            lief.PE.parse,
            settings.BINARY_ANALYSIS_TIMEOUT,
            str(pe_path))
        self.clr_flags = None
        self.is_64 = False
        self.is_x86 = False
        if self.binary:
            self.clr_flags = _clr_flags(self.binary)
            self.is_64 = (self.binary.optional_header.magic
                          == lief.PE.PE_TYPE.PE32_PLUS)
            self.is_x86 = self.binary.header.machine == MACHINES.I386

    @property
    def is_managed(self):
        return self.clr_flags is not None

    @property
    def is_il_only(self):
        """IL-only .NET images have no native code to harden."""
        return self.is_managed and bool(self.clr_flags & COR_ILONLY)

    def _has_dll_flag(self, flag):
        return self.binary.optional_header.has(flag)

    def runtime(self):
        if self.is_il_only:
            return '.NET (IL only)'
        if self.is_managed:
            return '.NET (mixed mode)'
        return 'Native'

    def image_type(self):
        is_dll = self.binary.header.has_characteristic(
            lief.PE.Header.CHARACTERISTICS.DLL)
        return 'DLL' if is_dll else 'EXE'

    def aslr(self):
        if not self._has_dll_flag(DLL_FLAGS.DYNAMIC_BASE):
            return _check(
                False, HIGH,
                'The binary is not built with /DYNAMICBASE. Without '
                'Address Space Layout Randomization (ASLR) the image loads '
                'at a predictable address, making memory corruption '
                'exploits such as Return Oriented Programming (ROP) '
                'reliable. Link with /DYNAMICBASE.')
        if not self.binary.has_relocations and self.image_type() == 'EXE':
            return _check(
                False, WARNING,
                'The binary sets /DYNAMICBASE but has no relocation '
                'table, so Windows cannot relocate it and ASLR is not '
                'effective. Do not strip relocations (/FIXED).')
        return _check(
            True, SECURE,
            'The binary is built with /DYNAMICBASE and can be relocated, '
            'so ASLR randomizes its load address.')

    def high_entropy_va(self):
        if not self.is_64:
            return _check(
                NA, INFO,
                'High entropy ASLR only applies to 64-bit images.')
        if self._has_dll_flag(DLL_FLAGS.HIGH_ENTROPY_VA):
            return _check(
                True, SECURE,
                'The binary is built with /HIGHENTROPYVA and uses the '
                'full 64-bit address space for ASLR.')
        return _check(
            False, WARNING,
            'The 64-bit binary is not built with /HIGHENTROPYVA, which '
            'limits ASLR entropy. Link with /HIGHENTROPYVA.')

    def dep(self):
        if self._has_dll_flag(DLL_FLAGS.NX_COMPAT):
            return _check(
                True, SECURE,
                'The binary is built with /NXCOMPAT. Data Execution '
                'Prevention (DEP) marks data pages non-executable, so '
                'injected shellcode cannot run from the stack or heap.')
        return _check(
            False, HIGH,
            'The binary is not built with /NXCOMPAT. Without Data '
            'Execution Prevention (DEP) attacker-controlled data in memory '
            'can be executed. Link with /NXCOMPAT.')

    def cfg(self):
        if self.is_il_only:
            return _check(
                NA, INFO,
                'Control Flow Guard does not apply to IL-only .NET '
                'assemblies; the CLR compiles and protects managed code.')
        if self._has_dll_flag(DLL_FLAGS.GUARD_CF):
            return _check(
                True, SECURE,
                'The binary is built with Control Flow Guard (/guard:cf), '
                'which validates indirect call targets at runtime.')
        return _check(
            False, WARNING,
            'The binary is not built with Control Flow Guard. CFG '
            'blocks many control-flow hijacking techniques by validating '
            'indirect call targets. Compile and link with /guard:cf.')

    def safe_seh(self):
        if self.is_il_only:
            return _check(
                NA, INFO,
                'SafeSEH does not apply to IL-only .NET assemblies.')
        if not self.is_x86:
            return _check(
                NA, INFO,
                'SafeSEH only applies to 32-bit x86 images; other '
                'architectures use table-based exception handling.')
        if self._has_dll_flag(DLL_FLAGS.NO_SEH):
            return _check(
                True, SECURE,
                'The binary does not use structured exception handlers '
                '(IMAGE_DLLCHARACTERISTICS_NO_SEH), so SEH overwrites do '
                'not apply.')
        config = self._load_config()
        if config and config.se_handler_count:
            return _check(
                True, SECURE,
                'The binary is built with /SAFESEH and registers a table '
                'of valid exception handlers.')
        return _check(
            False, HIGH,
            'The 32-bit binary is not built with /SAFESEH. An attacker '
            'who overwrites an exception handler record on the stack can '
            'redirect execution. Link with /SAFESEH.')

    def stack_cookie(self):
        if self.is_il_only:
            return _check(
                NA, INFO,
                'Stack buffer security cookies (/GS) do not apply to '
                'IL-only .NET assemblies.')
        config = self._load_config()
        if config and config.security_cookie:
            return _check(
                True, SECURE,
                'The binary has a /GS security cookie. Stack buffer '
                'overflows that overwrite the return address are '
                'detected before the function returns.')
        return _check(
            False, WARNING,
            'No /GS security cookie was found in the load configuration. '
            'Stack buffer overflows may overwrite the return address '
            'undetected. Compile with /GS.')

    def rwx_sections(self):
        rwx = [
            sec.name for sec in self.binary.sections
            if sec.has_characteristic(SECTION_FLAGS.MEM_EXECUTE)
            and sec.has_characteristic(SECTION_FLAGS.MEM_WRITE)]
        if rwx:
            return _check(
                ', '.join(rwx), HIGH,
                'The binary has sections that are both writable and '
                'executable. Writable code lets an attacker modify '
                'instructions in place and defeats DEP.')
        return _check(
            False, SECURE,
            'No section is both writable and executable.')

    def code_signature(self):
        if not self.binary.has_signatures:
            return _check(
                False, INFO,
                'The binary has no Authenticode signature. Files inside '
                'an MSIX or APPX package are covered by the package '
                'signature instead.')
        try:
            result = self.binary.verify_signature()
        except Exception:
            result = None
        if result == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            return _check(
                True, SECURE,
                'The binary has an Authenticode signature whose digest '
                'matches the file. Certificate trust is not evaluated.')
        return _check(
            False, HIGH,
            'The binary has an Authenticode signature that does not '
            'match its contents. The file may have been modified after '
            'signing.')

    def banned_imports(self):
        if self.is_il_only:
            return _check(
                NA, INFO,
                'Native banned API checks do not apply to IL-only .NET '
                'assemblies.')
        found = set()
        for table in ('imports', 'delay_imports'):
            try:
                for lib in getattr(self.binary, table):
                    for entry in lib.entries:
                        if entry.is_ordinal or not entry.name:
                            continue
                        name = entry.name.lower()
                        if (name in BANNED_APIS
                                or name.rstrip('aw') in BANNED_APIS):
                            found.add(entry.name)
            except Exception:
                continue
        if found:
            return _check(
                ', '.join(sorted(found)), WARNING,
                'The binary imports functions banned by the Microsoft '
                'Security Development Lifecycle (banned.h). These APIs '
                'are prone to buffer overflows; use the bounded *_s or '
                'StringCch* replacements.')
        return _check(
            'None', SECURE,
            'The binary does not import any SDL banned functions.')

    def _load_config(self):
        try:
            if self.binary.has_configuration:
                return self.binary.load_configuration
        except Exception:
            pass
        return None

    def checksec(self):
        if not self.binary:
            return None
        return {
            'name': self.rel_path,
            'arch': self.binary.header.machine.name,
            'format': 'PE32+' if self.is_64 else 'PE32',
            'type': self.image_type(),
            'runtime': self.runtime(),
            'aslr': self.aslr(),
            'high_entropy_va': self.high_entropy_va(),
            'dep': self.dep(),
            'cfg': self.cfg(),
            'safe_seh': self.safe_seh(),
            'stack_cookie': self.stack_cookie(),
            'rwx_sections': self.rwx_sections(),
            'code_signature': self.code_signature(),
            'banned_imports': self.banned_imports(),
        }
