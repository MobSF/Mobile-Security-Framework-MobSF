#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.util import read

TEST = "examples/android/TestsAndroguard/bin/classes.dex"

j = dvm.DalvikVMFormat( read(TEST, binary=False) )
x = analysis.VMAnalysis( j )
j.set_vmanalysis( x )

# SHOW CLASSES (verbose and pretty)
j.pretty_show()

# SHOW METHODS
for i in j.get_methods():
    i.pretty_show( )
