#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk


TEST = "examples/android/TestsAndroguard/bin/TestsAndroguard.apk"


a = apk.APK( TEST )
j = dvm.DalvikVMFormat( a.get_dex() )

for m in j.get_methods() :
  print m.get_class_name(), m.get_name(), m.get_descriptor()
  code_debug = m.get_debug()
  if code_debug != None :
    print code_debug.get_line_start(), code_debug.get_parameters_size(), code_debug.get_parameter_names(), code_debug.get_translated_parameter_names()
    for i in code_debug.get_bytecodes() :
      print i.get_op_value(), i.get_format(), i.get_value()
