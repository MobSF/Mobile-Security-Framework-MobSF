# !/usr/bin/python
# coding=utf-8
import logging
from pathlib import Path

import lief

logger = logging.getLogger(__name__)


class Checksec:
    def __init__(self, elf_file, so_rel):
        self.elf_path = elf_file.as_posix()
        self.elf_rel = so_rel
        self.elf = lief.parse(self.elf_path)

    def checksec(self):
        elf_dict = {}
        elf_dict['name'] = self.elf_rel
        if not self.is_elf(self.elf_path):
            return
        is_nx = self.is_nx()
        if is_nx:
            severity = 'info'
            desc = (
                'The shared object has NX bit set. This marks a '
                'memory page non-executable making attacker '
                'injected shellcode non-executable.')
        else:
            severity = 'high'
            desc = (
                'The shared object does not have NX bit set. NX bit '
                'offer protection against exploitation of memory corruption '
                'vulnerabilities by marking memory page as non-executable. '
                'Use option --noexecstack or -z noexecstack to mark stack as '
                'non executable.')
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
            'description': desc,
        }
        has_canary = self.has_canary()
        if has_canary:
            severity = 'info'
            desc = (
                'This shared object has a stack canary value '
                'added to the stack so that it will be overwritten by '
                'a stack buffer that overflows the return address. '
                'This allows detection of overflows by verifying the '
                'integrity of the canary before function return.')
        else:
            severity = 'high'
            desc = (
                'This shared object does not have a stack '
                'canary value added to the stack. Stack canaries '
                'are used to detect and prevent exploits from '
                'overwriting return address. Use the option '
                '-fstack-protector-all to enable stack canaries.')
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        relro = self.relro()
        if relro == 'Full RELRO':
            severity = 'info'
            desc = (
                'This shared object has full RELRO '
                'enabled. RELRO ensures that the GOT cannot be '
                'overwritten in vulnerable ELF binaries. '
                'In Full RELRO, the entire GOT (.got and '
                '.got.plt both) is marked as read-only.')
        elif relro == 'Partial RELRO':
            severity = 'warning'
            desc = (
                'This shared object has partial RELRO '
                'enabled. RELRO ensures that the GOT cannot be '
                'overwritten in vulnerable ELF binaries. '
                'In partial RELRO, the non-PLT part of the GOT '
                'section is read only but .got.plt is still '
                'writeable. Use the option -z,relro,-z,now to '
                'enable full RELRO.')
        else:
            severity = 'high'
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
            severity = 'high'
            desc = (
                'The shared object has RPATH set. In certain cases '
                'an attacker can abuse this feature to run arbitrary '
                'shared objects for code execution and privilege '
                'escalation. The only time a shared library in '
                'should set RPATH is if it is linked to private '
                'shared libraries in the same package. Remove the '
                'compiler option -rpath to remove RPATH.')
            rpt = rpath.rpath
        else:
            severity = 'info'
            desc = (
                'The shared object does not have run-time search path '
                'or RPATH set.')
            rpt = rpath
        elf_dict['rpath'] = {
            'rpath': rpt,
            'severity': severity,
            'description': desc,
        }
        runpath = self.runpath()
        if runpath:
            severity = 'high'
            desc = (
                'The shared object has RUNPATH set. In certain cases '
                'an attacker can abuse this feature and or modify '
                'environment variables to run arbitrary '
                'shared objects for code execution and privilege '
                'escalation. The only time a shared library in should '
                'set RUNPATH is if it is linked to private shared '
                'libraries in the same package. Remove the compiler '
                'option --enable-new-dtags,-rpath to remove RUNPATH.')
            rnp = runpath.runpath
        else:
            severity = 'info'
            desc = (
                'The shared object does not have RUNPATH set.')
            rnp = runpath
        elf_dict['runpath'] = {
            'runpath': rnp,
            'severity': severity,
            'description': desc,
        }
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = 'info'
            desc = ('The shared object has the '
                    f'following fortified functions: {fortified_functions}')
        else:
            severity = 'warning'
            desc = ('The shared object does not have any '
                    'fortified functions. Fortified functions '
                    'provides buffer overflow checks against '
                    'glibc\'s commons insecure functions like '
                    'strcpy, gets etc. Use the compiler option '
                    '-D_FORTIFY_SOURCE=2 to fortify functions.')
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
            'description': desc,
        }
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = 'info'
            desc = 'Symbols are stripped.'
        else:
            severity = 'warning'
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

    def has_canary(self):
        for symbol in ('__stack_chk_fail',
                       '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except lief.not_found:
                pass
        return False

    def relro(self):
        try:
            gnu_relro = lief.ELF.SEGMENT_TYPES.GNU_RELRO
            flags = lief.ELF.DYNAMIC_TAGS.FLAGS
            bind_now = lief.ELF.DYNAMIC_FLAGS.BIND_NOW
            if self.elf.get(gnu_relro):
                if bind_now in self.elf.get(flags):
                    return 'Full RELRO'
                else:
                    return 'Partial RELRO'
            return 'No RELRO'
        except lief.not_found:
            return 'No RELRO'

    def rpath(self):
        try:
            rpath = lief.ELF.DYNAMIC_TAGS.RPATH
            return self.elf.get(rpath)
        except lief.not_found:
            return False

    def runpath(self):
        try:
            runpath = lief.ELF.DYNAMIC_TAGS.RUNPATH
            return self.elf.get(runpath)
        except lief.not_found:
            return False

    def is_symbols_stripped(self):
        for i in self.elf.static_symbols:
            if i:
                return False
        return True

    def fortify(self):
        fortified_funcs = []
        for function in self.elf.symbols:
            if function.name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        return self.elf.strings


def elf_analysis(app_dir: str) -> dict:
    """Perform elf analysis on shared object."""
    try:
        strings = []
        elf_list = []
        logger.info('Binary Analysis Started')
        libs = Path(app_dir) / 'lib'
        elf = {'elf_analysis': elf_list, 'elf_strings': strings}
        if not libs.is_dir():
            return elf
        for sofile in libs.rglob('*.so'):
            so_rel = (
                f'{sofile.parents[1].name}/'
                f'{sofile.parents[0].name}/'
                f'{sofile.name}')
            logger.info('Analyzing %s', so_rel)
            chk = Checksec(sofile, so_rel)
            elf_find = chk.checksec()
            if elf_find:
                elf_list.append(elf_find)
                strings.append({so_rel: chk.strings()})
        return {'elf_analysis': elf_list, 'elf_strings': strings}
    except Exception:
        logger.exception('Performing Binary Analysis')
        return elf
