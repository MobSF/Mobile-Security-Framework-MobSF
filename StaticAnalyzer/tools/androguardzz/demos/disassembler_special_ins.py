#!/usr/bin/env python

import sys, hashlib

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

TEST = 'examples/android/TestsAndroguard/bin/classes.dex'

a = AndroguardS( TEST )
x = analysis.VMAnalysis( a.get_vm() )

for method in a.get_methods() :
    g = x.get_method( method )

    if method.get_code() == None :
      continue

    idx = 0
    for i in g.basic_blocks.get() :
        for ins in i.get_instructions() :   
            op_value = ins.get_op_value()
            
            # packed/sparse
            if op_value == 0x2b or op_value == 0x2c :
                special_ins = i.get_special_ins(idx)
                if special_ins != None :
                    print "\t %x" % idx, ins, special_ins, ins.get_name(), ins.get_output(), special_ins.get_values()
            # fill
            if op_value == 0x26 :
                special_ins = i.get_special_ins(idx)
                if special_ins != None :
                    print "\t %x" % idx, ins, special_ins, ins.get_name(), ins.get_output(), repr( special_ins.get_data() )

            idx += ins.get_length()