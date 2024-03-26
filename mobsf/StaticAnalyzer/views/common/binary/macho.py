# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess
from pathlib import Path

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)


def objdump_is_debug_symbol_stripped(macho_file):
    """Check if debug symbols are stripped using OS utility."""
    # https://www.unix.com/man-page/osx/1/objdump/
    # Works only on MacOS
    out = subprocess.check_output(
        [shutil.which('objdump'), '--syms', macho_file],
        stderr=subprocess.STDOUT)
    return b' d  ' not in out


class MachOChecksec:
    def __init__(self, macho, rel_path=None):
        self.macho_path = macho.as_posix()
        if rel_path:
            self.macho_name = rel_path
        else:
            self.macho_name = macho.name
        self.macho = lief.parse(self.macho_path)

    def checksec(self):
        macho_dict = {}
        macho_dict['name'] = self.macho_name

        if not self.is_macho(self.macho_path):
            return {}

        has_nx = self.has_nx()
        has_pie = self.has_pie()
        has_canary = self.has_canary()
        has_rpath = self.has_rpath()
        has_code_signature = self.has_code_signature()
        has_arc = self.has_arc()
        is_encrypted = self.is_encrypted()
        is_stripped = self.is_symbols_stripped()

        if has_nx:
            severity = 'info'
            desc = (
                'The binary has NX bit set. This marks a '
                'memory page non-executable making attacker '
                'injected shellcode non-executable.')
        else:
            severity = 'info'
            desc = (
                'The binary does not have NX bit set. NX bit '
                'offer protection against exploitation of memory corruption '
                'vulnerabilities by marking memory page as non-executable. '
                'However iOS never allows an app to execute from writeable '
                'memory. You do not need to specifically enable the '
                '‘NX bit’ because it’s always enabled for all '
                'third-party code.')
        macho_dict['nx'] = {
            'has_nx': has_nx,
            'severity': severity,
            'description': desc,
        }
        if has_pie:
            severity = 'info'
            desc = (
                'The binary is build with -fPIC flag which '
                'enables Position independent code. This makes Return '
                'Oriented Programming (ROP) attacks much more difficult '
                'to execute reliably.')
        else:
            severity = 'high'
            ext = Path(self.macho_name).suffix
            # PIE check not applicable for static and dynamic libraries
            # https://github.com/MobSF/Mobile-Security-Framework-MobSF/
            # issues/2290#issuecomment-1837272113
            if (ext == '.dylib'
                    or (not ext and '.framework' in self.macho_name)):
                severity = 'info'
            desc = (
                'The binary is built without Position '
                'Independent Code flag. In order to prevent '
                'an attacker from reliably jumping to, for example, a '
                'particular exploited function in memory, Address '
                'space layout randomization (ASLR) randomly arranges '
                'the address space positions of key data areas of a '
                'process, including the base of the executable and the '
                'positions of the stack,heap and libraries. Use compiler '
                'option -fPIC to enable Position Independent Code. '
                'Not applicable for dylibs and static libraries.')
        macho_dict['pie'] = {
            'has_pie': has_pie,
            'severity': severity,
            'description': desc,
        }
        if has_canary:
            severity = 'info'
            desc = (
                'This binary has a stack canary value '
                'added to the stack so that it will be overwritten by '
                'a stack buffer that overflows the return address. '
                'This allows detection of overflows by verifying the '
                'integrity of the canary before function return.')
        elif is_stripped:
            severity = 'warning'
            desc = (
                'This binary has debug symbols stripped. We cannot identify '
                'whether stack canary is enabled or not.')
        else:
            severity = 'high'
            sw_msg = ''
            if 'libswift' in self.macho_name:
                severity = 'warning'
                sw_msg = ' This might be okey for pure Swift dylibs.'
            desc = (
                'This binary does not have a stack '
                'canary value added to the stack. Stack canaries '
                'are used to detect and prevent exploits from '
                'overwriting return address. Use the option '
                f'-fstack-protector-all to enable stack canaries.{sw_msg}')
        macho_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        if has_arc:
            severity = 'info'
            desc = (
                'The binary is compiled with Automatic Reference '
                'Counting (ARC) flag. ARC is a compiler '
                'feature that provides automatic memory '
                'management of Objective-C objects and is an '
                'exploit mitigation mechanism against memory '
                'corruption vulnerabilities.'
            )
        elif is_stripped:
            severity = 'warning'
            desc = (
                'This binary has debug symbols stripped. We cannot identify '
                'whether ARC is enabled or not.')
        else:
            severity = 'high'
            desc = (
                'The binary is not compiled with Automatic '
                'Reference Counting (ARC) flag. ARC is a compiler '
                'feature that provides automatic memory '
                'management of Objective-C objects and '
                'protects from memory corruption '
                'vulnerabilities. Use compiler option '
                '-fobjc-arc to enable ARC or set '
                'Objective-C Automatic Reference Counting '
                'to YES in project configuration.')
        macho_dict['arc'] = {
            'has_arc': has_arc,
            'severity': severity,
            'description': desc,
        }
        if has_rpath:
            severity = 'warning'
            desc = (
                'The binary has Runpath Search Path (@rpath) set. '
                'In certain cases an attacker can abuse this '
                'feature to run arbitrary executable for code '
                'execution and privilege escalation. Remove the '
                'compiler option -rpath to remove @rpath.')
        else:
            severity = 'info'
            desc = (
                'The binary does not have Runpath Search '
                'Path (@rpath) set.')
        macho_dict['rpath'] = {
            'has_rpath': has_rpath,
            'severity': severity,
            'description': desc,
        }
        if has_code_signature:
            severity = 'info'
            desc = 'This binary has a code signature.'
        else:
            severity = 'warning'
            desc = 'This binary does not have a code signature.'
        macho_dict['code_signature'] = {
            'has_code_signature': has_code_signature,
            'severity': severity,
            'description': desc,
        }
        if is_encrypted:
            severity = 'info'
            desc = 'This binary is encrypted.'
        else:
            severity = 'warning'
            desc = 'This binary is not encrypted.'
        macho_dict['encrypted'] = {
            'is_encrypted': is_encrypted,
            'severity': severity,
            'description': desc,
        }
        if is_stripped:
            severity = 'info'
            desc = 'Debug Symbols are stripped'
        else:
            severity = 'warning'
            desc = (
                'Debug Symbols are available. To strip '
                'debugging symbols, set Strip Debug '
                'Symbols During Copy to YES, '
                'Deployment Postprocessing to YES, '
                'and Strip Linked Product to YES in '
                'project\'s build settings.')
        macho_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return macho_dict

    def is_macho(self, macho_path):
        return lief.is_macho(macho_path)

    def has_nx(self):
        return self.macho.has_nx

    def has_pie(self):
        return self.macho.is_pie

    def has_canary(self):
        stk_check = '___stack_chk_fail'
        stk_guard = '___stack_chk_guard'
        imp_func_gen = self.macho.imported_functions
        has_stk_check = any(
            str(func).strip() == stk_check for func in imp_func_gen)
        has_stk_guard = any(
            str(func).strip() == stk_guard for func in imp_func_gen)

        return has_stk_check and has_stk_guard

    def has_arc(self):
        for func in self.macho.imported_functions:
            if str(func).strip() in ('_objc_release', '_swift_release'):
                return True
        return False

    def has_rpath(self):
        return self.macho.has_rpath

    def has_code_signature(self):
        try:
            return self.macho.code_signature.data_size > 0
        except Exception:
            return False

    def is_encrypted(self):
        try:
            return bool(self.macho.encryption_info.crypt_id)
        except Exception:
            return False

    def is_symbols_stripped(self):
        try:
            return objdump_is_debug_symbol_stripped(self.macho_path)
        except Exception:
            # Based on issues/1917#issuecomment-1238078359
            # and issues/2233#issue-1846914047
            stripped_sym = 'radr://5614542'
            # radr://5614542 symbol is added back for
            # debug symbols stripped binaries
            for i in self.macho.symbols:
                if i.name.lower().strip() in (
                        '__mh_execute_header', stripped_sym):
                    # __mh_execute_header is present in both
                    # stripped and unstripped binaries
                    # also ignore radr://5614542
                    continue
                if (i.type & 0xe0) > 0 or i.type in (0x0e, 0x1e):
                    # N_STAB set or 14, 30

                    # N_STAB	0xe0  /* if any of these bits set,
                    # a symbolic debugging entry */ -> 224
                    # https://opensource.apple.com/source/xnu/xnu-201/
                    # EXTERNAL_HEADERS/mach-o/nlist.h
                    # Only symbolic debugging entries have
                    # some of the N_STAB bits set and if any
                    # of these bits are set then it is a
                    # symbolic debugging entry (a stab).

                    # Identified a debugging symbol
                    return False
            if stripped_sym in self.get_symbols():
                return True
            return False

    def get_libraries(self):
        libs = []
        if not self.macho:
            return libs
        for i in self.macho.libraries:
            curr = '.'.join(str(x) for x in i.current_version)
            comp = '.'.join(str(x) for x in i.compatibility_version)
            lib = (f'{i.name} (compatibility version: {comp}'
                   f', current version: {curr})')
            libs.append(lib)
        return libs

    def strings(self):
        return strings_on_binary(self.macho_path)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.macho.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
