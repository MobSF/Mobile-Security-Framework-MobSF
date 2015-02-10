#!/usr/bin/env python

# This file is part of Elsim.
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
sys.path.append("./")

PATH_INSTALL = "../androguard"

sys.path.append(PATH_INSTALL)

from optparse import OptionParser

from elsim.elsim_db import *
from elsim.elsim_dalvik import LIST_EXTERNAL_LIBS
from elsim.similarity.similarity import *

from androguard.core import androconf
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis

DEFAULT_SIGNATURE = analysis.SIGNATURE_SEQUENCE_BB
option_0 = { 'name' : ('-i', '--input'), 'help' : 'use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-b', '--database'), 'help' : 'path of the database', 'nargs' : 1 }
option_2 = { 'name' : ('-l', '--listdatabase'), 'help' : 'display information in the database', 'action' : 'count' }
option_3 = { 'name' : ('-d', '--directory'), 'help' : 'use this directory', 'nargs' : 1  }
option_4 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]


def check_one_file(d1, dx1) :
  print "Similarities ...."
  e = ElsimDB( options.database )
  print e.percentages(d1, dx1)

def check_one_directory(directory) :
    for root, dirs, files in os.walk( directory, followlinks=True ) :
        if files != [] :
            for f in files :
                real_filename = root
                if real_filename[-1] != "/" :
                    real_filename += "/"
                real_filename += f

                print "filename: %s ..." % real_filename
                ret_type = androconf.is_android( real_filename )
                if ret_type == "APK" :
                    a = apk.APK( real_filename )
                    d1 = dvm.DalvikVMFormat( a.get_dex() )
                elif ret_type == "DEX" :
                    d1 = dvm.DalvikVMFormat( open(real_filename, "rb").read() )

                dx1 = analysis.VMAnalysis( d1 )
                check_one_file( d1, dx1 )

def main(options, arguments) :
    if options.input != None and options.database != None :
        ret_type = androconf.is_android( options.input )
        if ret_type == "APK" :
            a = apk.APK( options.input )
            d1 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d1 = dvm.DalvikVMFormat( open(options.input, "rb").read() )

        dx1 = analysis.VMAnalysis( d1 )

        check_one_file(d1, dx1)

    elif options.directory != None and options.database != None :
      check_one_directory( options.directory )

    elif options.database != None and options.listdatabase != None :
        db = DBFormat( options.database )
        db.show()

    elif options.version != None :
        print "Androappindb version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
