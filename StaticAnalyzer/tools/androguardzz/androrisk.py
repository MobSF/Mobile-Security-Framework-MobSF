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
from androguard.core.analysis import risk

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 1 }
option_1 = { 'name' : ('-m', '--method'), 'help' : 'perform analysis of each method', 'action' : 'count' }
option_2 = { 'name' : ('-d', '--directory'), 'help' : 'directory : use this directory', 'nargs' : 1 }
option_3 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3]

def display_result(res) :
  for i in res :
    print "\t", i
    for j in res[i] :
      print "\t\t", j, res[i][j]

def analyze_app(filename, ri, a) :
    print filename
    display_result( ri.with_apk( a ) )

def analyze_dex(filename, ri, d) :
    print filename
    display_result( ri.with_dex( d ) )

def main(options, arguments) :
    ri = risk.RiskIndicator()
    ri.add_risk_analysis( risk.RedFlags() )
    ri.add_risk_analysis( risk.FuzzyRisk() )

    if options.input != None :
        ret_type = androconf.is_android( options.input ) 
        if ret_type == "APK" :
            a = apk.APK( options.input )
            analyze_app( options.input, ri, a )
        elif ret_type == "DEX" :
            analyze_dex( options.input, ri, open(options.input, "r").read() )


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
                        try :
                            a = apk.APK( real_filename )
                            analyze_app( real_filename, ri, a )
                        except Exception, e :
                            print e

                    elif ret_type == "DEX" :
                        analyze_dex( real_filename, ri, open(real_filename, "r").read() )

    elif options.version != None :
        print "Androrisk version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
