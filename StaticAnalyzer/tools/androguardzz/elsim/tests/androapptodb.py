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
sys.path.append("./")

PATH_INSTALL = "../androguard"

sys.path.append(PATH_INSTALL)

from optparse import OptionParser

from elsim.similarity.similarity import *

from androguard.core import androconf
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_2 = { 'name' : ('-n', '--name'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_3 = { 'name' : ('-s', '--subname'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_4 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
option_5 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

############################################################
def main(options, arguments) :
    if options.input != None  and options.output != None and options.name != None and options.subname != None :
        edi = ElsimDBIn( options.output )

        ret_type = androconf.is_android( options.input )
        if ret_type == "APK" :
            a = apk.APK( options.input )
            d1 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d1 = dvm.DalvikVMFormat( open(options.input, "rb").read() )

        dx1 = analysis.VMAnalysis( d1 )

        regexp_pattern = None
        regexp_exclude_pattern = None

        edi.add( d1, dx1, options.name, options.sname, regexp_pattern, regexp_exclude_pattern)
        edi.save()

    elif options.version != None :
        print "Androapptodb version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
