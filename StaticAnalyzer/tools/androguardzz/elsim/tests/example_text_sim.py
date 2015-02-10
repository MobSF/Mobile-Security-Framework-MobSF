#!/usr/bin/env python

# This file is part of Elsim.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Elsim is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Elsim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Elsim.  If not, see <http://www.gnu.org/licenses/>.


from optparse import OptionParser

import sys
sys.path.append("./")

from elsim.elsim import Elsim, ELSIM_VERSION
from elsim.elsim_text import ProxyText, FILTERS_TEXT

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use these filenames', 'nargs' : 2 }
option_1 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
option_2 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2]

############################################################
def main(options, arguments) :
    if options.input != None :

        el = Elsim( ProxyText( open(options.input[0], "rb").read() ),
                ProxyText( open(options.input[1], "rb").read() ), FILTERS_TEXT,
                libpath="elsim/similarity/libsimilarity/libsimilarity.so")
        el.show()
        print "\t--> sentences: %f%% of similarities" % el.get_similarity_value()
        
        if options.display :
            print "SIMILAR sentences:"
            diff_methods = el.get_similar_elements()
            for i in diff_methods :
                el.show_element( i )
            
            print "IDENTICAL sentences:"
            new_methods = el.get_identical_elements()
            for i in new_methods :
                el.show_element( i )

            print "NEW sentences:"
            new_methods = el.get_new_elements()
            for i in new_methods :
                el.show_element( i, False )

            print "DELETED sentences:"
            del_methods = el.get_deleted_elements()
            for i in del_methods :
                el.show_element( i )
            
            print "SKIPPED sentences:"
            skip_methods = el.get_skipped_elements()
            for i in skip_methods :
                el.show_element( i )

    elif options.version != None :
        print "example text sim  %s" % ELSIM_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
