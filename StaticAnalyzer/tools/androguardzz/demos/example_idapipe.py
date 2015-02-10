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


import sys, os
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)

from androguard.core.binaries import idapipe

PATH_IDA = os.path.expanduser("~") + "/ida-6.2/idal"
PATH_WRAPPER = "./androguard/core/binaries/idawrapper.py"

ip = idapipe.IDAPipe( PATH_IDA, PATH_WRAPPER, "./elsim/examples/x86/elf/polarssl/libpolarssl.so" )
#ip = idapipe.IDAPipe( "/media/truecrypt1/ida/6.2/ida-6.2/idal", "examples/x86/pe/win32k-5.1.2600.6119.sys" )

try :
    f = ip.get_quick_functions()

   # print len(f)

    idapipe.display_function( f[ 15344 ] )
    #ip.get_raw()
    #ip.get_functions()
    #ip.get_function_name( "aes_gen_tables" )

    ip.quit()
except :
    import traceback
    traceback.print_exc()
    ip.quit()
