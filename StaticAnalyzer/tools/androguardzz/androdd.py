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

from androguard.core.androgen import Androguard
from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.bytecode import method2dot, method2format

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'base directory to output all files', 'nargs' : 1 }

option_2 = { 'name' : ('-d', '--dot'), 'help' : 'write the method in dot format', 'action' : 'count' }
option_3 = { 'name' : ('-f', '--format'), 'help' : 'write the method in specific format (png, ...)', 'nargs' : 1 }

option_4 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4]

def valid_class_name( class_name ):
    if class_name[-1] == ";" :
        return class_name[1:-1]
    return class_name

def create_directory( class_name, output ) :
    output_name = output
    if output_name[-1] != "/" :
        output_name = output_name + "/"

    try :
        os.makedirs( output_name + class_name )
    except OSError :
        pass

def create_directories( a, output ) :
    for vm in a.get_vms() :
        for class_name in vm.get_classes_names() :
            create_directory( valid_class_name( class_name ), output )

def export_apps_to_format( a, output, dot=None, _format=None ) :
    output_name = output
    if output_name[-1] != "/" :
        output_name = output_name + "/"

    for vm in a.get_vms() :
        x = analysis.VMAnalysis( vm )
        for method in vm.get_methods() :
            filename = output_name + valid_class_name( method.get_class_name() )
            if filename[-1] != "/" :
                filename = filename + "/"

            descriptor = method.get_descriptor()
            descriptor = descriptor.replace(";", "")
            descriptor = descriptor.replace(" ", "")
            descriptor = descriptor.replace("(", "-")
            descriptor = descriptor.replace(")", "-")
            descriptor = descriptor.replace("/", "_")

            filename = filename + method.get_name() + descriptor


            buff = method2dot( x.get_method( method ) )

            if dot :
                fd = open( filename + ".dot", "w")
                fd.write( buff )
                fd.close()

            if _format :
                method2format( filename + "." + _format, _format, raw = buff )

def main(options, arguments) :
    if options.input != None and options.output != None :
        a = Androguard( [ options.input ] )

        if options.dot != None or options.format != None :
            create_directories( a, options.output )
            export_apps_to_format( a, options.output, options.dot, options.format )
        else :
          print "Please, specify a format or dot option"

    elif options.version != None :
        print "Androdd version %s" % androconf.ANDROGUARD_VERSION
    
    else :
      print "Please, specify an input file and an output directory"

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
