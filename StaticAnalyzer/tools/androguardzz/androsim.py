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
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis

sys.path.append("./elsim")
from elsim import elsim
from elsim.elsim_dalvik import ProxyDalvik, FILTERS_DALVIK_SIM
from elsim.elsim_dalvik import ProxyDalvikStringMultiple, ProxyDalvikStringOne, FILTERS_DALVIK_SIM_STRING

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 2 }
option_1 = { 'name' : ('-t', '--threshold'), 'help' : 'specify the threshold (0.0 to 1.0) to know if a method is similar. This option will impact on the filtering method. Because if you specify a higher value of the threshold, you will have more associations', 'nargs' : 1 }
option_2 = { 'name' : ('-c', '--compressor'), 'help' : 'specify the compressor (BZ2, ZLIB, SNAPPY, LZMA, XZ). The final result depends directly of the type of compressor. But if you use LZMA for example, the final result will be better, but it take more time', 'nargs' : 1 }
option_4 = { 'name' : ('-d', '--display'), 'help' : 'display all information about methods', 'action' : 'count' }
option_5 = { 'name' : ('-n', '--new'), 'help' : 'calculate the final score only by using the ratio of included methods', 'action' : 'count' }
option_6 = { 'name' : ('-e', '--exclude'), 'help' : 'exclude specific class name (python regexp)', 'nargs' : 1 }
option_7 = { 'name' : ('-s', '--size'), 'help' : 'exclude specific method below the specific size (specify the minimum size of a method to be used (it is the length (bytes) of the dalvik method)', 'nargs' : 1 }
option_8 = { 'name' : ('-x', '--xstrings'), 'help' : 'display similarities of strings', 'action' : 'count'  }
option_9 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
option_10 = { 'name' : ('-l', '--library'), 'help' : 'use python library (python) or specify the path of the shared library)', 'nargs' : 1 }

options = [option_0, option_1, option_2, option_4, option_5, option_6, option_7, option_8, option_9, option_10]

def check_one_file(a, d1, dx1, FS, threshold, file_input, view_strings=False, new=True, library=True) :
    d2 = None
    ret_type = androconf.is_android( file_input )
    if ret_type == "APK" :
        a = apk.APK( file_input )
        d2 = dvm.DalvikVMFormat( a.get_dex() )
    elif ret_type == "DEX" :
        d2 = dvm.DalvikVMFormat( open(file_input, "rb").read() )

    if d2 == None :
      return
    dx2 = analysis.VMAnalysis( d2 )

    el = elsim.Elsim( ProxyDalvik(d1, dx1), ProxyDalvik(d2, dx2), FS, threshold, options.compressor, libnative=library )
    el.show()
    print "\t--> methods: %f%% of similarities" % el.get_similarity_value(new)
    

    if options.display :
        print "SIMILAR methods:"
        diff_methods = el.get_similar_elements()
        for i in diff_methods :
            el.show_element( i )
            
        print "IDENTICAL methods:"
        new_methods = el.get_identical_elements()
        for i in new_methods :
            el.show_element( i )

        print "NEW methods:"
        new_methods = el.get_new_elements()
        for i in new_methods :
            el.show_element( i, False )

        print "DELETED methods:"
        del_methods = el.get_deleted_elements()
        for i in del_methods :
            el.show_element( i )
            
        print "SKIPPED methods:"
        skipped_methods = el.get_skipped_elements()
        for i in skipped_methods :
            el.show_element( i )
    
    if view_strings :
        els = elsim.Elsim( ProxyDalvikStringMultiple(d1, dx1),
                           ProxyDalvikStringMultiple(d2, dx2), 
                           FILTERS_DALVIK_SIM_STRING, 
                           threshold, 
                           options.compressor, 
                           libnative=library )
        #els = elsim.Elsim( ProxyDalvikStringOne(d1, dx1),
        #    ProxyDalvikStringOne(d2, dx2), FILTERS_DALVIK_SIM_STRING, threshold, options.compressor, libnative=library )
        els.show()
        print "\t--> strings: %f%% of similarities" % els.get_similarity_value(new)
    
        if options.display :
          print "SIMILAR strings:"
          diff_strings = els.get_similar_elements()
          for i in diff_strings :
            els.show_element( i )
            
          print "IDENTICAL strings:"
          new_strings = els.get_identical_elements()
          for i in new_strings :
            els.show_element( i )

          print "NEW strings:"
          new_strings = els.get_new_elements()
          for i in new_strings :
            els.show_element( i, False )

          print "DELETED strings:"
          del_strings = els.get_deleted_elements()
          for i in del_strings :
            els.show_element( i )
            
          print "SKIPPED strings:"
          skipped_strings = els.get_skipped_elements()
          for i in skipped_strings :
            els.show_element( i )
        

def check_one_directory(a, d1, dx1, FS, threshold, directory, view_strings=False, new=True, library=True) :
    for root, dirs, files in os.walk( directory, followlinks=True ) :
        if files != [] :
            for f in files :
                real_filename = root
                if real_filename[-1] != "/" :
                    real_filename += "/"
                real_filename += f

                print "filename: %s ..." % real_filename
                check_one_file(a, d1, dx1, FS, threshold, real_filename, view_strings, new, library)

############################################################
def main(options, arguments) :
    if options.input != None :
        a = None
        ret_type = androconf.is_android( options.input[0] )
        if ret_type == "APK" :
            a = apk.APK( options.input[0] )
            d1 = dvm.DalvikVMFormat( a.get_dex() )
        elif ret_type == "DEX" :
            d1 = dvm.DalvikVMFormat( open(options.input[0], "rb").read() )
        
        dx1 = analysis.VMAnalysis( d1 )
        
        threshold = None
        if options.threshold != None :
            threshold = float(options.threshold)

        FS = FILTERS_DALVIK_SIM
        FS[elsim.FILTER_SKIPPED_METH].set_regexp( options.exclude )
        FS[elsim.FILTER_SKIPPED_METH].set_size( options.size )
    
        new = True
        if options.new != None :
          new = False
        
        library = True
        if options.library != None :
            library = options.library
            if options.library == "python" :
                library = False

        if os.path.isdir( options.input[1] ) == False :
            check_one_file( a, d1, dx1, FS, threshold, options.input[1], options.xstrings, new, library )
        else :
            check_one_directory(a, d1, dx1, FS, threshold, options.input[1], options.xstrings, new, library )

    elif options.version != None :
        print "Androsim version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
