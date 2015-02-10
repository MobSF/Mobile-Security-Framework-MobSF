#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.decompiler import decompiler

TEST = "examples/android/TestsAndroguard/bin/classes.dex"

j = dvm.DalvikVMFormat( open(TEST).read() )
jx = analysis.VMAnalysis( j )

#d = decompiler.DecompilerDex2Jad( j )
#d = decompiler.DecompilerDed( j )
d = decompiler.DecompilerDAD( j, jx ) 

j.set_decompiler( d )

# SHOW METHODS
for i in j.get_methods() :
    if i.get_name() == "onCreate" :
        print i.get_class_name(), i.get_name()
        i.source()

#    if i.get_name() == "testWhileTrue" :
#        i.source()
