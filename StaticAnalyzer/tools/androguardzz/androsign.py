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

from optparse import OptionParser

from androguard.core import androconf
from androguard.core.bytecodes import apk

sys.path.append("./elsim/")
from elsim.elsign import dalvik_elsign


option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-d', '--directory'), 'help' : 'directory : use this directory', 'nargs' : 1 }
option_2 = { 'name' : ('-b', '--database'), 'help' : 'database : use this database', 'nargs' : 1 }
option_3 = { 'name' : ('-c', '--config'), 'help' : 'use this configuration', 'nargs' : 1 }
option_4 = { 'name' : ('-v', '--verbose'), 'help' : 'display debug information', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

def display(ret, debug) :
    print "---->", ret[0]
    sys.stdout.flush()

def main(options, arguments) :
    if options.database == None or options.config == None :
        return

    s = dalvik_elsign.MSignature( options.database, options.config, options.verbose != None, ps = dalvik_elsign.PublicSignature)

    if options.input != None :
        ret_type = androconf.is_android( options.input ) 
        
        print os.path.basename(options.input), ":",
        sys.stdout.flush()
        if ret_type == "APK" :
            try :
                a = apk.APK( options.input )
                if a.is_valid_APK() :
                    display( s.check_apk( a ), options.verbose )
                else :
                    print "INVALID"
            except Exception, e :
                print "ERROR", e

        elif ret_type == "DEX" :
            display( s.check_dex( open(options.input, "rb").read() ), options.verbose )
    elif options.directory != None :
        for root, dirs, files in os.walk( options.directory, followlinks=True ) :
            if files != [] :
                for f in files :
                    real_filename = root
                    if real_filename[-1] != "/" :
                        real_filename += "/"
                    real_filename += f

                    ret_type = androconf.is_android( real_filename )
                    if ret_type == "APK"  :
                        print os.path.basename( real_filename ), ":",
                        sys.stdout.flush()
                        try :
                            a = apk.APK( real_filename )
                            if a.is_valid_APK() :
                                display( s.check_apk( a ), options.verbose )
                            else :
                                print "INVALID APK"
                        except Exception, e :
                            print "ERROR", e
                    elif ret_type == "DEX" :
                        try :
                            print os.path.basename( real_filename ), ":",
                            sys.stdout.flush()
                            display( s.check_dex( open(real_filename, "rb").read() ), options.verbose )
                        except Exception, e : 
                            print "ERROR", e

    elif options.version != None :
        print "Androsign version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
