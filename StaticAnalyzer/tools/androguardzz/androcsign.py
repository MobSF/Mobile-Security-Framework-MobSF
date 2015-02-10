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

from androguard.core import androconf

sys.path.append("./elsim/")
from elsim.elsign import dalvik_elsign

from optparse import OptionParser

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-r', '--remove'), 'help' : 'remote the signature', 'nargs' : 1 }
option_2 = { 'name' : ('-o', '--output'), 'help' : 'output database', 'nargs' : 1 }
option_3 = { 'name' : ('-l', '--list'), 'help' : 'list signatures in database', 'nargs' : 1 }
option_4 = { 'name' : ('-c', '--check'), 'help' : 'check signatures in database', 'nargs' : 1 }
option_5 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4, option_5]

def main(options, arguments) :
    s = dalvik_elsign.CSignature(pcs=dalvik_elsign.PublicCSignature)
    if options.input != None :
        ret = s.add_file( open( options.input, "rb" ).read() )
        if ret != None and options.output != None :
            s.add_indb( ret, options.output )

    elif options.list != None :
        s.list_indb( options.list )

    elif options.remove != None :
        s.remove_indb( options.remove, options.output )

    elif options.check != None :
        s.check_db( options.check )

    elif options.version != None :
        print "Androcsign version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
