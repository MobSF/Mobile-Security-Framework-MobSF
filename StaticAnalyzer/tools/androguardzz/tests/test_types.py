#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2010, Anthony Desnos <desnos at t0t0.fr>
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

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

#TEST_CASE  = 'examples/android/TC/bin/classes.dex'
TEST_CASE = 'examples/android/TestsAndroguard/bin/classes.dex'

VALUES_ = { "Lorg/t0t0/androguard/TC/TestType1; <init> ()V" : [
                  42,
                  -42,
                  0,

                  42,
                  -42,
                  0,

                  42.0,
                  -42.0,
                  0.0,

                  42.0,
                  -42.0,
                  0.0,
            ],
}

VALUES = { 'Ltests/androguard/TestActivity; testDouble ()V' : [
        -5.0,
        -4,
        -3,
        -2,
        -1,
        0,
        1,
        2,
        3,
        4,
        5,

        -5,
        -4,
        -3,
        -2,
        -1,
        0,
        1,
        2,
        3,
        4,
        5,

        -5,
        -4,
        -3,
        -2,
        -1,
        0,
        1,
        2,
        3,
        4,
        5,

        65534,
        65535,
        65536,
        65537,

        32769,
        32768,
        32767,
        32766,

        65534,
        65535,
        65536,
        65537,

        32769,
        32768,
        32767,
        32766,

        65534,
        65535,
        65536,
        65537,

        32769,
        32768,
        32767,
        32766,

        5346952,
        5346952,
        5346952,

        65534.5,
        65535.5,
        65536.5,
        65537.5,

        32769.5,
        32768.5,
        32767.5,
        32766.5,

        65534.5,
        65535.5,
        65536.5,
        65537.5,

        32769.5,
        32768.5,
        32767.5,
        32766.5,

        -5,
        -65535,
        -65536,
        -123456789123456789.555555555,
        -123456789123456789.555555555,
        -606384730,
        -123456790519087104,
        3.5
        ],
}

def test(got, expected):
    if got == expected:
        prefix = ' OK '
    else:
        prefix = '  X '
    print '%s got: %s expected: %s' % (prefix, repr(got), repr(expected))


a = AndroguardS( TEST_CASE )

for method in a.get_methods() :
    key = method.get_class_name() + " " + method.get_name() + " " + method.get_descriptor()

    if key not in VALUES :
        continue

    print method.get_class_name(), method.get_name(), method.get_descriptor()
    code = method.get_code()
    bc = code.get_bc()

    idx = 0
    for i in bc.get() :
        #print "\t", "%x" % idx, i.get_name(), i.get_operands()
        if "const" in i.get_name() :
            formatted_operands = i.get_formatted_operands()
            for f in formatted_operands :
#                print i.get_name(), i.get_operands(), i.get_formatted_operands()
                test( f[1], VALUES[ key ].pop(0) )

        idx += i.get_length()
