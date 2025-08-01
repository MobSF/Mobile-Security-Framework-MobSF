# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)
from mobsf.MobSF.utils import (
    run_with_timeout,
)

from django.conf import settings


NA = 'Not Applicable'
NO_RELRO = 'No RELRO'
PARTIAL_RELRO = 'Partial RELRO'
FULL_RELRO = 'Full RELRO'
INFO = 'info'
WARNING = 'warning'
HIGH = 'high'


def nm_is_debug_symbol_stripped(elf_file):
    """Check if debug symbols are stripped using OS utility."""
    # https://linux.die.net/man/1/nm
    out = subprocess.check_output(
        [shutil.which('nm'), '--debug-syms', elf_file],
        stderr=subprocess.STDOUT)
    return b'no debug symbols' in out


class ELFChecksec:
    def __init__(self, elf_file, so_rel):
        self.elf_path = elf_file.as_posix()
        self.elf_rel = so_rel
        self.elf = run_with_timeout(
            lief.parse,
            settings.BINARY_ANALYSIS_TIMEOUT,
            self.elf_path)

    def checksec(self):
        elf_dict = {}
        elf_dict['name'] = self.elf_rel
        if not self.is_elf(self.elf_path):
            return
        is_nx = self.is_nx()
        if is_nx:
            severity = INFO
            desc = (
                'The binary has NX bit set. This marks a '
                'memory page non-executable making attacker '
                'injected shellcode non-executable.')
        else:
            severity = HIGH
            desc = (
                'The binary does not have NX bit set. NX bit '
                'offer protection against exploitation of memory corruption '
                'vulnerabilities by marking memory page as non-executable. '
                'Use option --noexecstack or -z noexecstack to mark stack as '
                'non executable.')
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
            'description': desc,
        }
        severity = 'info'
        is_pie = self.is_pie()
        if is_pie == 'dso':
            is_pie = 'Dynamic Shared Object (DSO)'
            desc = (
                'The shared object is build with -fPIC flag which '
                'enables Position independent code. This makes Return '
                'Oriented Programming (ROP) attacks much more difficult '
                'to execute reliably.')
        elif is_pie == 'pie':
            is_pie = 'Position Independent Executable (PIE)'
            desc = (
                'The shared object is build with -fPIC flag which '
                'enables Position independent code. This makes Return '
                'Oriented Programming (ROP) attacks much more difficult '
                'to execute reliably.')
        elif is_pie == 'rel':
            is_pie = 'Relocatable Object File'
            desc = (
                'The shared object is build with -fPIC flag which '
                'enables Position independent code. This makes Return '
                'Oriented Programming (ROP) attacks much more difficult '
                'to execute reliably.')
        elif is_pie == 'no':
            is_pie = 'No PIE'
            severity = 'high'
            desc = (
                'The shared object is built without Position '
                'Independent Code flag. In order to prevent '
                'an attacker from reliably jumping to, for example, a '
                'particular exploited function in memory, Address '
                'space layout randomization (ASLR) randomly arranges '
                'the address space positions of key data areas of a '
                'process, including the base of the executable and the '
                'positions of the stack,heap and libraries. Use compiler '
                'option -fPIC to enable Position Independent Code.')
        elf_dict['pie'] = {
            'is_pie': is_pie,
            'severity': severity,
            'description': desc,
        }
        has_canary = self.has_canary()
        if has_canary:
            severity = INFO
            desc = (
                'This binary has a stack canary value '
                'added to the stack so that it will be overwritten by '
                'a stack buffer that overflows the return address. '
                'This allows detection of overflows by verifying the '
                'integrity of the canary before function return.')
        else:
            severity = HIGH
            desc = (
                'This binary does not have a stack '
                'canary value added to the stack. Stack canaries '
                'are used to detect and prevent exploits from '
                'overwriting return address. Use the option '
                '-fstack-protector-all to enable stack canaries. '
                'Not applicable for Dart/Flutter libraries unless '
                'Dart FFI is used.')
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        relro = self.relro()
        if relro == NA:
            severity = INFO
            desc = ('RELRO checks are not applicable for '
                    'Flutter/Dart binaries')
        elif relro == FULL_RELRO:
            severity = INFO
            desc = (
                'This shared object has full RELRO '
                'enabled. RELRO ensures that the GOT cannot be '
                'overwritten in vulnerable ELF binaries. '
                'In Full RELRO, the entire GOT (.got and '
                '.got.plt both) is marked as read-only.')
        elif relro == PARTIAL_RELRO:
            severity = WARNING
            desc = (
                'This shared object has partial RELRO '
                'enabled. RELRO ensures that the GOT cannot be '
                'overwritten in vulnerable ELF binaries. '
                'In partial RELRO, the non-PLT part of the GOT '
                'section is read only but .got.plt is still '
                'writeable. Use the option -z,relro,-z,now to '
                'enable full RELRO.')
        else:
            severity = HIGH
            desc = (
                'This shared object does not have RELRO '
                'enabled. The entire GOT (.got and '
                '.got.plt both) are writable. Without this compiler '
                'flag, buffer overflows on a global variable can '
                'overwrite GOT entries. Use the option '
                '-z,relro,-z,now to enable full RELRO and only '
                '-z,relro to enable partial RELRO.')
        elf_dict['relocation_readonly'] = {
            'relro': relro,
            'severity': severity,
            'description': desc,
        }
        rpath = self.rpath()
        if rpath:
            severity = HIGH
            desc = (
                'The binary has RPATH set. In certain cases, '
                'an attacker can abuse this feature to run arbitrary '
                'libraries for code execution and privilege '
                'escalation. The only time a library should '
                'set RPATH is when it is linked to private '
                'libraries in the same package. Remove the '
                'compiler option -rpath to remove RPATH.')
            rpt = rpath.rpath
        else:
            severity = INFO
            desc = (
                'The binary does not have run-time search path '
                'or RPATH set.')
            rpt = rpath
        elf_dict['rpath'] = {
            'rpath': rpt,
            'severity': severity,
            'description': desc,
        }
        runpath = self.runpath()
        if runpath:
            severity = HIGH
            desc = (
                'The binary has RUNPATH set. In certain cases, '
                'an attacker can abuse this feature and or modify '
                'environment variables to run arbitrary '
                'libraries for code execution and privilege '
                'escalation. The only time a library should '
                'set RUNPATH is when it is linked to private '
                'libraries in the same package. Remove the compiler '
                'option --enable-new-dtags,-rpath to remove RUNPATH.')
            rnp = runpath.runpath
        else:
            severity = INFO
            desc = (
                'The binary does not have RUNPATH set.')
            rnp = runpath
        elf_dict['runpath'] = {
            'runpath': rnp,
            'severity': severity,
            'description': desc,
        }
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = INFO
            desc = ('The binary has the '
                    f'following fortified functions: {fortified_functions}')
        else:
            if self.is_dart():
                severity = INFO
            else:
                severity = WARNING
            desc = ('The binary does not have any '
                    'fortified functions. Fortified functions '
                    'provides buffer overflow checks against '
                    'glibc\'s commons insecure functions like '
                    'strcpy, gets etc. Use the compiler option '
                    '-D_FORTIFY_SOURCE=2 to fortify functions. '
                    'This check is not applicable for '
                    'Dart/Flutter libraries.')
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
            'description': desc,
        }
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = INFO
            desc = 'Symbols are stripped.'
        else:
            severity = WARNING
            desc = 'Symbols are available.'
        elf_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return elf_dict

    def is_elf(self, elf_path):
        return lief.is_elf(elf_path)

    def is_nx(self):
        return self.elf.has_nx

    def is_pie(self):
        if self.elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN:
            if self.elf.has(lief.ELF.DynamicEntry.TAG.DEBUG_TAG):
                return 'pie'
            else:
                return 'dso'
        elif self.elf.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
            return 'rel'
        return 'no'

    def is_dart(self):
        dart = ('_kDartVmSnapshotInstructions',
                'Dart_Cleanup')
        if any(i in self.strings() for i in dart):
            return True
        for symbol in dart:
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def has_canary(self):
        if self.is_dart():
            return True
        for symbol in ('__stack_chk_fail',
                       '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def relro(self):
        try:
            gnu_relro = lief.ELF.Segment.TYPE.GNU_RELRO
            bind_now_flag = lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW
            flags_tag = lief.ELF.DynamicEntry.TAG.FLAGS
            flags1_tag = lief.ELF.DynamicEntry.TAG.FLAGS_1
            now_flag = lief.ELF.DynamicEntryFlags.FLAG.NOW

            if self.is_dart():
                return NA

            if not self.elf.get(gnu_relro):
                return NO_RELRO

            flags = self.elf.get(flags_tag)
            bind_now = flags and bind_now_flag in flags

            flags1 = self.elf.get(flags1_tag)
            now = flags1 and now_flag in flags1

            if bind_now or now:
                return FULL_RELRO
            else:
                return PARTIAL_RELRO
        except Exception:
            pass
        return NO_RELRO

    def rpath(self):
        rpath = lief.ELF.DynamicEntry.TAG.RPATH
        return self.elf.get(rpath)

    def runpath(self):
        runpath = lief.ELF.DynamicEntry.TAG.RUNPATH
        return self.elf.get(runpath)

    def is_symbols_stripped(self):
        try:
            for i in self.elf.symtab_symbols:
                if i:
                    return False
            return True
        except Exception:
            try:
                return nm_is_debug_symbol_stripped(
                    self.elf_path)
            except Exception:
                return True

    def fortify(self):
        fortified_funcs = []
        for function in self.elf.symbols:
            if isinstance(function.name, bytes):
                try:
                    function_name = function.name.decode('utf-8')
                except UnicodeDecodeError:
                    function_name = function.name.decode('utf-8', 'replace')
            else:
                function_name = function.name
            if function_name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        normalized = set()
        try:
            elf_strings = self.elf.strings
        except Exception:
            elf_strings = None
        if not elf_strings:
            elf_strings = strings_on_binary(self.elf_path)
        for i in elf_strings:
            if isinstance(i, bytes):
                continue
            normalized.add(i)
        return list(normalized)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.elf.symtab_symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
