#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2011, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

import sys, itertools, time, os, random
from ctypes import cdll, c_float, c_int, c_uint, c_void_p, Structure, addressof, create_string_buffer, cast, POINTER, pointer
from struct import pack, unpack, calcsize                                                                                                                                                        

PATH_INSTALL = "../../../"
sys.path.append(PATH_INSTALL + "./")
sys.path.append(PATH_INSTALL + "./core")
sys.path.append(PATH_INSTALL + "./core/bytecodes")
sys.path.append(PATH_INSTALL + "./core/analysis")

import apk, dvm, analysis, msign

if __name__ == "__main__" :
#    a = apk.APK( PATH_INSTALL + "examples/android/TestsAndroguard/bin/TestsAndroguard.apk" )
#    a = apk.APK( PATH_INSTALL + "apks/drweb-600-android-beta.apk" )
#    a = apk.APK( PATH_INSTALL + "debug/062d5e38dc4618a8b1c6bf3587dc2016a3a3db146aea0d82cc227a18ca21ad13")
    a = apk.APK( PATH_INSTALL + "apks/malwares/kungfu/sample2.apk" )

    t1 = time.time()


    if len(sys.argv) > 1 :
        d = dvm.DalvikVMFormat( a.get_dex(), engine=["python"] ) 
    else :
        d = dvm.DalvikVMFormat( a.get_dex() )

    t2 = time.time()
    x = analysis.VMAnalysis( d ) 

    t3 = time.time()
    print '-> %0.8f %0.8f %0.8f' % ((t2-t1, t3-t2, t3-t1))

    sys.exit(0)

    for method in d.get_methods() :
        print method.get_class_name(), method.get_name(), method.get_descriptor()

        code = method.get_code()
        if code == None :
            continue

        bc = code.get_bc()
    
        idx = 0
        for i in bc.get() :
            print "\t", "%x" % idx, i.get_op_value(), i.get_name(), i.get_operands()#, i.get_formatted_operands()
            idx += i.get_length()

    sys.exit(0)
