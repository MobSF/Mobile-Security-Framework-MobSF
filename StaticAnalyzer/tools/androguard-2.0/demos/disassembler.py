#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

TEST = 'examples/android/TestsAndroguard/bin/classes.dex'

a = AndroguardS(TEST)
x = analysis.VMAnalysis(a.get_vm())

for method in a.get_methods():
    print method.get_class_name(), method.get_name(), method.get_descriptor()
    code = method.get_code()

    if code != None:
      bc = code.get_bc()
      idx = 0
      for i in bc.get_instructions():
          print "\t", "%x" % idx, i.get_name(), i.get_output()
          idx += i.get_length()


for method in a.get_methods():
    print method.get_class_name(), method.get_name(), method.get_descriptor()
    idx = 0
    for i in method.get_instructions():
        print "\t", "%x" % idx, i.get_name(), i.get_output()
        idx += i.get_length()
