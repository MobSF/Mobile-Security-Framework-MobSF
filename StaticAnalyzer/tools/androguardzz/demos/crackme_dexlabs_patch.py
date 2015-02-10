#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis
from androguard.core import androconf

class Nop(dvm.Instruction10x) :
    def __init__(self) :
        self.OP = 0x00

def patch_dex( m ) :
    for i in m.get_methods() :
        if i.get_class_name() == "Lorg/dexlabs/poc/dexdropper/DropActivity;" :
            print i.get_class_name(), i.get_name()
            
            patch_method_3( i )
            # or
            # patch_method_X( i )


def  patch_method_1( method ) :
    buff = method.get_code().get_bc().insn
    buff = "\x00" * 0x12 + buff[0x12:]
    method.get_code().get_bc().insn = buff

def  patch_method_2( method ) :
    method.set_code_idx( 0x12 )
    instructions = [ j for j in method.get_instructions() ]
    for j in range(0, 9) :
        instructions.insert(0, Nop() )
    method.set_instructions( instructions )            

def  patch_method_3( method ) :
    method.set_code_idx( 0x12 )
    instructions = [ j for j in method.get_instructions() ]
    for j in range(0, 9) :
        instructions.insert(0, dvm.Instruction10x(None, "\x00\x00") )
    method.set_instructions( instructions )            


FILENAME_INPUT = "apks/crash/crackme-obfuscator.apk"

FILENAME_OUTPUT = "./toto.dex"

androconf.set_debug()

a = apk.APK( FILENAME_INPUT )
vm = dvm.DalvikVMFormat( a.get_dex() )
vmx = analysis.VMAnalysis( vm )

patch_dex( vm )

new_dex = vm.save()

fd = open(FILENAME_OUTPUT, "w")
fd.write( new_dex )
fd.close()