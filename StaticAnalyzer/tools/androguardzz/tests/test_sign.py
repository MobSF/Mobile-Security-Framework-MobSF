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

import sys

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.androgen import AndroguardS

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

TEST_CASE  = "examples/android/TestsAndroguard/bin/classes.dex"

def test(got, expected):
    if got == expected:
        prefix = ' OK '
    else:
        prefix = '  X '
    print '%s got: %s expected: %s' % (prefix, repr(got), repr(expected))


a = AndroguardS( TEST_CASE )
x = analysis.uVMAnalysis( a.get_vm() )

for method in a.get_methods() :
    print method.get_class_name(), method.get_name(), method.get_descriptor()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_L0_0).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_L0_1).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_L0_2).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_L0_3).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_L0_4).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_HEX).get_string()
    print "-> : \t", x.get_method_signature(method, predef_sign = analysis.SIGNATURE_SEQUENCE_BB).get_list()

    print
