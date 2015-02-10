#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.androconf import CONF
from androguard.core.analysis import analysis, ganalysis


#CONF["LAZY_ANALYSIS"] = True

TEST = "examples/android/TestsAndroguard/bin/TestsAndroguard.apk"

a = apk.APK( TEST )
j = dvm.DalvikVMFormat( a.get_dex() )
dx = analysis.uVMAnalysis( j )
gx = ganalysis.GVMAnalysis( dx, None )

j.set_vmanalysis( dx )
j.set_gvmanalysis( gx )

j.create_xref()
j.create_dref()

for m in dx.get_methods() :

  idx = 0
  for i in m.basic_blocks.get() :
    print "\t %s %x %x" % (i.name, i.start, i.end), i.get_instructions()[-1].get_name()

  print m.method.XREFfrom, m.method.XREFto
