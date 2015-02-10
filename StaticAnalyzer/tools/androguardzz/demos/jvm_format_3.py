#!/usr/bin/env python

import sys, random, string

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "/core")
sys.path.append(PATH_INSTALL + "/core/bytecodes")

import jvm

TEST = "./examples/java/test/orig/Test1.class"
TEST_REF = "./examples/java/Hello.class"
TEST_OUTPUT = "./examples/java/test/new/Test1.class"

j = jvm.JVMFormat( open(TEST).read() )
j2 = jvm.JVMFormat( open(TEST_REF).read() )

# Insert a craft method :)
j.insert_craft_method( "toto", [ "ACC_PUBLIC", "[B", "[B" ], [ [ "aconst_null" ], [ "areturn" ] ] )

# Insert a method with no dependances methods
j.insert_direct_method( "toto2", j2.get_method("test3")[0] )

# SAVE CLASS
fd = open( TEST_OUTPUT, "w" )
fd.write( j.save() )
fd.close()
