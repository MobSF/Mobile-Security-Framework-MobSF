#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

TEST = 'examples/android/TestsAndroguard/bin/classes.dex'

d = dvm.DalvikVMFormat(open(TEST, "r").read())
x = analysis.VMAnalysis(d)

# CFG
for method in d.get_methods():
    g = x.get_method(method)

    if method.get_code() == None:
      continue

    print method.get_class_name(), method.get_name(), method.get_descriptor()

    idx = 0
    for i in g.get_basic_blocks().get():
        print "\t %s %x %x" % (i.name, i.start, i.end), '[ NEXT = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.get_next() ), ']', '[ PREV = ', ', '.join( j[2].get_name() for j in i.get_prev() ), ']'

        for ins in i.get_instructions():
            print "\t\t %x" % idx, ins.get_name(), ins.get_output()
            idx += ins.get_length()

        print ""
