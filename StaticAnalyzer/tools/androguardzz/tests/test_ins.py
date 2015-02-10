#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
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

import sys, re

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis


TESTS_CASES  = [ #'examples/android/TC/bin/classes.dex',
                 'examples/android/TestsAndroguard/bin/classes.dex',
               ]

VALUES = {
            'examples/android/TestsAndroguard/bin/classes.dex' : {
                  "Ltests/androguard/TestInvoke; <init> ()V" : {
                     0x0 : ("invoke-direct" , [['v',1] , ['meth@', 4, 'Ljava/lang/Object;', '()', 'V', '<init>']]),
                     0xa : ("invoke-virtual", [['v',1], ['v',0] , ['meth@', 49, 'Ltests/androguard/TestInvoke;', '(I)', 'I', 'TestInvoke1']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke1 (I)I" : {
                     0x4 : ("invoke-virtual", [['v',1] , ['v',2] , ['v',0] , ['meth@', 50,'Ltests/androguard/TestInvoke;' ,'(I I)', 'I', 'TestInvoke2']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke2 (I I)I" : {
                     0x4 : ("invoke-virtual", [['v',1] , ['v',2] , ['v',3] , ['v',0] , ['meth@', 51, 'Ltests/androguard/TestInvoke;', '(I I I)', 'I', 'TestInvoke3']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke3 (I I I)I" : {
                     0x4 : ("invoke-virtual", [['v', 1], ['v', 2], ['v', 3], ['v', 4], ['v', 0], ['meth@', 52, 'Ltests/androguard/TestInvoke;', '(I I I I)', 'I', 'TestInvoke4']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke4 (I I I I)I" : {
                     0xe : ("invoke-virtual/range", [['v', 0], ['v', 1], ['v', 2], ['v', 3], ['v', 4], ['v', 5], ['meth@', 53, 'Ltests/androguard/TestInvoke;', '(I I I I I)', 'I', 'TestInvoke5']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke5 (I I I I I)I" : {
                     0x10 : ("invoke-virtual/range", [['v', 0], ['v', 1], ['v', 2], ['v', 3], ['v', 4], ['v', 5], ['v', 6], ['meth@', 54, 'Ltests/androguard/TestInvoke;', '(I I I I I I)', 'I', 'TestInvoke6']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke6 (I I I I I I)I" : {
                     0x12 : ("invoke-virtual/range", [['v', 0], ['v', 1], ['v', 2], ['v', 3], ['v', 4], ['v', 5], ['v', 6], ['v', 7], ['meth@', 55, 'Ltests/androguard/TestInvoke;', '(I I I I I I I)', 'I', 'TestInvoke7']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke7 (I I I I I I I)I" : {
                     0x16 : ("invoke-virtual/range", [['v', 0], ['v', 1], ['v', 2], ['v', 3], ['v', 4], ['v', 5], ['v', 6], ['v', 7], ['v', 8], ['meth@', 56, 'Ltests/androguard/TestInvoke;', '(I I I I I I I I)', 'I', 'TestInvoke8']]),
                  },

                  "Ltests/androguard/TestInvoke; TestInvoke8 (I I I I I I I I)I" : {
                     0x0 : ("mul-int", [['v', 0], ['v', 2], ['v', 3]]),
                     0x4 : ("mul-int/2addr", [['v', 0], ['v', 4]]),
                     0x10 :  ("return", [['v', 0]]),
                  }
               },
}

def test(got, expected):
    if got == expected:
        prefix = ' OK '
    else:
        prefix = '  X '

    print '\t%s got: %s expected: %s' % (prefix, repr(got), repr(expected))

def getVal(i) :
    op = i.get_operands()

    if isinstance(op, int) :
        return [ op ]
    elif i.get_name() == "lookupswitch" :
        x = []

        x.append( i.get_operands().default )
        for idx in range(0, i.get_operands().npairs) :
            off = getattr(i.get_operands(), "offset%d" % idx)
            x.append( off )
        return x

    return [-1]

def check(a, values) :
    for method in a.get_methods() :
        key = method.get_class_name() + " " + method.get_name() + " " + method.get_descriptor()

        if key not in values :
            continue

        print "CHECKING ...", method.get_class_name(), method.get_name(), method.get_descriptor()
        code = method.get_code()
        bc = code.get_bc()

        idx = 0
        for i in bc.get() :
#            print "\t", "%x(%d)" % (idx, idx), i.get_name(), i.get_operands()
            if idx in values[key] :
                elem = values[key][idx]

                val1 = i.get_name() + "%s" % i.get_operands()
                val2 = elem[0] + "%s" % elem[1]

                test(val1, val2)

                del values[key][idx]

            idx += i.get_length()


for i in TESTS_CASES :
    a = AndroguardS( i )
    check( a, VALUES[i] )

    x = analysis.VMAnalysis( a.get_vm() )
    print x
