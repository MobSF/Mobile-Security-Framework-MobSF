#!/usr/bin/env python

import sys, random, string

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.util import read

TEST = "./examples/dalvik/test/bin/classes.dex"
TEST_OUTPUT = "./examples/dalvik/test/bin/classes_output.dex"

j = dvm.DalvikVMFormat( read(TEST, binary=False) )

# Modify the name of each field
#for field in j.get_fields():
#   field.set_name( random.choice( string.letters ) + ''.join([ random.choice(string.letters + string.digits) for i in range(10 - 1) ] ) )

# Modify the name of each method (minus the constructor (<init>) and a extern called method (go))
#for method in j.get_methods():
#   if method.get_name() != "go" and method.get_name() != "<init>":
#      method.set_name( random.choice( string.letters ) + ''.join([ random.choice(string.letters + string.digits) for i in range(10 - 1) ] ) )

# SAVE CLASS
with open( TEST_OUTPUT, "w" ) as fd:
	fd.write( j.save() )
