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

from optparse import OptionParser

from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.core import androconf

sys.path.append("./elsim")
from elsim import elsim
from elsim.elsim_dalvik import ProxyDalvik, FILTERS_DALVIK_SIM, ProxyDalvikMethod, FILTERS_DALVIK_BB
from elsim.elsim_dalvik import ProxyDalvikBasicBlock, FILTERS_DALVIK_DIFF_BB
from elsim.elsim_dalvik import DiffDalvikMethod


option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 2 }
option_1 = { 'name' : ('-t', '--threshold'), 'help' : 'define the threshold', 'nargs' : 1 }
option_2 = { 'name' : ('-c', '--compressor'), 'help' : 'define the compressor', 'nargs' : 1 }
option_3 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
#option_4 = { 'name' : ('-e', '--exclude'), 'help' : 'exclude specific blocks (0 : orig, 1 : diff, 2 : new)', 'nargs' : 1 }
option_5 = { 'name' : ('-e', '--exclude'), 'help' : 'exclude specific class name (python regexp)', 'nargs' : 1 }
option_6 = { 'name' : ('-s', '--size'), 'help' : 'exclude specific method below the specific size', 'nargs' : 1 }
option_7 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_5, option_6, option_7]

def main(options, arguments) :
    details = False
    if options.display != None :
        details = True
    
    if options.input != None :
        ret_type = androconf.is_android( options.input[0] )
        if ret_type == "APK" :
            a = apk.APK( options.input[0] )
            d1 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d1 = dvm.DalvikVMFormat( open(options.input[0], "rb").read() )
        
        dx1 = analysis.VMAnalysis( d1 )
       
        ret_type = androconf.is_android( options.input[1] )
        if ret_type == "APK" :
            a = apk.APK( options.input[1] )
            d2 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d2 = dvm.DalvikVMFormat( open(options.input[1], "rb").read() )
        
        dx2 = analysis.VMAnalysis( d2 )

        print d1, dx1, d2, dx2
        sys.stdout.flush()
        
        threshold = None
        if options.threshold != None :
            threshold = float(options.threshold)

        FS = FILTERS_DALVIK_SIM
        FS[elsim.FILTER_SKIPPED_METH].set_regexp( options.exclude )
        FS[elsim.FILTER_SKIPPED_METH].set_size( options.size )
        el = elsim.Elsim( ProxyDalvik(d1, dx1), ProxyDalvik(d2, dx2), FS, threshold, options.compressor )
        el.show()

        e1 = elsim.split_elements( el, el.get_similar_elements() )
        for i in e1 :
            j = e1[ i ]
            elb = elsim.Elsim( ProxyDalvikMethod(i), ProxyDalvikMethod(j), FILTERS_DALVIK_BB, threshold, options.compressor )
            #elb.show()

            eld = elsim.Eldiff( ProxyDalvikBasicBlock(elb), FILTERS_DALVIK_DIFF_BB )
            #eld.show()

            ddm = DiffDalvikMethod( i, j, elb, eld )
            ddm.show()

        print "NEW METHODS"
        enew = el.get_new_elements()
        for i in enew :
            el.show_element( i, False )

        print "DELETED METHODS"
        edel = el.get_deleted_elements()
        for i in edel :
            el.show_element( i )

    elif options.version != None :
        print "Androdiff version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
