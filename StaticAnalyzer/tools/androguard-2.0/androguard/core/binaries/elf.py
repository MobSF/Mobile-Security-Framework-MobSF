# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from elfesteem import *
from miasm.tools.pe_helper import *
from miasm.core import asmbloc
from miasm.arch import arm_arch
from miasm.core import bin_stream


from androguard.core import bytecode
from androguard.core.androconf import CONF, debug

def disasm_at_addr(in_str, ad_to_dis, symbol_pool):
    kargs = {}
    all_bloc = asmbloc.dis_bloc_all(arm_arch.arm_mn, in_str, ad_to_dis, set(),
                                        symbol_pool=symbol_pool,
                                        dontdis_retcall = False,
                                        follow_call = False,
                                        **kargs)
    for i in all_bloc:
        bytecode._PrintDefault("%s\n" % i.label)
        for j in i.lines:
            bytecode._PrintDefault("\t %s\n" % j)
        bytecode._PrintDefault("\n")

class Function(object):
    def __init__(self, cm, name, info):
        self.cm = cm
        self.name = name
        self.info = info

    def show(self):
        bytecode._PrintSubBanner("Function")
        bytecode._PrintDefault("name=%s addr=0x%x\n" % (self.name, self.info.value))

        self.cm.disasm_at_addr( self.info.value )

class ClassManager(object):
    def __init__(self, in_str, symbol_pool):
        self.in_str = in_str
        self.symbol_pool = symbol_pool

    def disasm_at_addr(self, ad_to_dis):
        disasm_at_addr( self.in_str, ad_to_dis, self.symbol_pool )

class ELF(object):
    def __init__(self, buff):
        self.E = elf_init.ELF( buff )

        self.in_str = bin_stream.bin_stream(self.E.virt)
        self.symbol_pool = None
        self.functions = []

        self.create_symbol_pool()

        self.CM = ClassManager( self.in_str, self.symbol_pool )

        self.create_functions()

    def create_symbol_pool(self):
        dll_dyn_funcs = get_import_address_elf(self.E)
        self.symbol_pool = asmbloc.asm_symbol_pool()
        for (n,f), ads in dll_dyn_funcs.items():
            for ad in ads:
                l  = self.symbol_pool.getby_name_create("%s_%s"%(n, f))
                l.offset = ad
                self.symbol_pool.s_offset[l.offset] = l

    def show(self):
        for i in self.get_functions():
            i.show()

    def get_functions(self):
        return self.functions

    def create_functions(self):
        try:
            for k, v in self.E.sh.symtab.symbols.items():
                if v.size != 0:
                    self.functions.append( Function(self.CM, k, v) )
        except AttributeError:
            pass

        for k, v in self.E.sh.dynsym.symbols.items():
            if v.size != 0:
                self.functions.append( Function(self.CM, k, v) )
