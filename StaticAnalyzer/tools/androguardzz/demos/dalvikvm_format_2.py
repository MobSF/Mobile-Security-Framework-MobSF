#!/usr/bin/env python

import sys, random, string

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm

TEST = "./examples/dalvik/test/bin/classes.dex"
TEST_OUTPUT = "./examples/dalvik/test/bin/classes_output.dex"

j = dvm.DalvikVMFormat( open(TEST).read() )

# Modify the name of each field
#for field in j.get_fields() :
#   field.set_name( random.choice( string.letters ) + ''.join([ random.choice(string.letters + string.digits) for i in range(10 - 1) ] ) )

# Modify the name of each method (minus the constructor (<init>) and a extern called method (go))
#for method in j.get_methods() :
#   if method.get_name() != "go" and method.get_name() != "<init>" :
#      method.set_name( random.choice( string.letters ) + ''.join([ random.choice(string.letters + string.digits) for i in range(10 - 1) ] ) )

# SAVE CLASS
fd = open( TEST_OUTPUT, "w" )
fd.write( j.save() )
fd.close()
