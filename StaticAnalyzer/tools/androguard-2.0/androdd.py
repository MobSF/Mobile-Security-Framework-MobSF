#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2012/2013, Anthony Desnos <desnos at t0t0.fr>
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

import shutil
import sys
import os
import re

from optparse import OptionParser

from androguard.core.androgen import Androguard
from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm
from androguard.core.bytecode import method2dot, method2format
from androguard.decompiler import decompiler

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'base directory to output all files', 'nargs' : 1 }
option_2 = { 'name' : ('-d', '--decompiler'), 'help' : 'choose a decompiler', 'nargs' : 1 }
option_3 = { 'name' : ('-j', '--jar'), 'help' : 'output jar file', 'action' : 'count' }

option_4 = { 'name' : ('-f', '--format'), 'help' : 'write the method in specific format (png, ...)', 'nargs' : 1 }

option_5 = { 'name' : ('-l', '--limit'), 'help' : 'limit analysis to specific methods/classes by using a regexp', 'nargs' : 1}
option_6 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6]


def valid_class_name(class_name):
    if class_name[-1] == ";":
        return class_name[1:-1]
    return class_name


def create_directory(class_name, output):
    output_name = output
    if output_name[-1] != "/":
        output_name = output_name + "/"

    pathdir = output_name + class_name
    try:
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)
    except OSError:
        # FIXME
        pass


def export_apps_to_format(filename, a, output, methods_filter=None, jar=None, decompiler_type=None, format=None):
    print "Dump information %s in %s" % (filename, output)

    if not os.path.exists(output):
        print "Create directory %s" % output
        os.makedirs(output)
    else:
        print "Clean directory %s" % output
        androconf.rrmdir(output)
        os.makedirs(output)

    methods_filter_expr = None
    if methods_filter:
        methods_filter_expr = re.compile(methods_filter)

    output_name = output
    if output_name[-1] != "/":
        output_name = output_name + "/"

    dump_classes = []
    for vm in a.get_vms():
        print "Analysis ...",
        sys.stdout.flush()
        vmx = analysis.VMAnalysis(vm)
        print "End"

        print "Decompilation ...",
        sys.stdout.flush()

        if not decompiler_type:
            vm.set_decompiler(decompiler.DecompilerDAD(vm, vmx))
        elif decompiler_type == "dex2jad":
            vm.set_decompiler(decompiler.DecompilerDex2Jad(vm,
                                                           androconf.CONF["PATH_DEX2JAR"],
                                                           androconf.CONF["BIN_DEX2JAR"],
                                                           androconf.CONF["PATH_JAD"],
                                                           androconf.CONF["BIN_JAD"],
                                                           androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "dex2winejad":
            vm.set_decompiler(decompiler.DecompilerDex2WineJad(vm,
                                                               androconf.CONF["PATH_DEX2JAR"],
                                                               androconf.CONF["BIN_DEX2JAR"],
                                                               androconf.CONF["PATH_JAD"],
                                                               androconf.CONF["BIN_WINEJAD"],
                                                               androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "ded":
            vm.set_decompiler(decompiler.DecompilerDed(vm,
                                                       androconf.CONF["PATH_DED"],
                                                       androconf.CONF["BIN_DED"],
                                                       androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "dex2fernflower":
            vm.set_decompiler(decompiler.DecompilerDex2Fernflower(vm,
                                                                  androconf.CONF["PATH_DEX2JAR"],
                                                                  androconf.CONF["BIN_DEX2JAR"],
                                                                  androconf.CONF["PATH_FERNFLOWER"],
                                                                  androconf.CONF["BIN_FERNFLOWER"],
                                                                  androconf.CONF["OPTIONS_FERNFLOWER"],
                                                                  androconf.CONF["TMP_DIRECTORY"]))
        else:
            raise("invalid decompiler !")
        print "End"

        if options.jar:
            print "jar ...",
            filenamejar = decompiler.Dex2Jar(vm,
                                             androconf.CONF["PATH_DEX2JAR"],
                                             androconf.CONF["BIN_DEX2JAR"],
                                             androconf.CONF["TMP_DIRECTORY"]).get_jar()
            shutil.move(filenamejar, output + "classes.jar")
            print "End"

        for method in vm.get_methods():
            if methods_filter_expr:
                msig = "%s%s%s" % (method.get_class_name(),
                                   method.get_name(),
                                   method.get_descriptor())
                if not methods_filter_expr.search(msig):
                    continue

            filename_class = valid_class_name(method.get_class_name())
            create_directory(filename_class, output)

            print "Dump %s %s %s ..." % (method.get_class_name(),
                                         method.get_name(),
                                         method.get_descriptor()),

            filename_class = output_name + filename_class
            if filename_class[-1] != "/":
                filename_class = filename_class + "/"

            descriptor = method.get_descriptor()
            descriptor = descriptor.replace(";", "")
            descriptor = descriptor.replace(" ", "")
            descriptor = descriptor.replace("(", "-")
            descriptor = descriptor.replace(")", "-")
            descriptor = descriptor.replace("/", "_")

            filename = filename_class + method.get_name() + descriptor
            if len(method.get_name() + descriptor) > 250:
                all_identical_name_methods = vm.get_methods_descriptor(method.get_class_name(), method.get_name())
                pos = 0
                for i in all_identical_name_methods:
                    if i.get_descriptor() == method.get_descriptor():
                        break
                    pos += 1

                filename = filename_class + method.get_name() + "_%d" % pos

            buff = method2dot(vmx.get_method(method))

            if format:
                print "%s ..." % format,
                method2format(filename + "." + format, format, None, buff)

            if method.get_class_name() not in dump_classes:
                print "source codes ...",
                current_class = vm.get_class(method.get_class_name())
                current_filename_class = valid_class_name(current_class.get_name())
                create_directory(filename_class, output)

                current_filename_class = output_name + current_filename_class + ".java"
                with open(current_filename_class, "w") as fd:
                    fd.write(current_class.get_source())
                dump_classes.append(method.get_class_name())

            print "bytecodes ...",
            bytecode_buff = dvm.get_bytecodes_method(vm, vmx, method)
            with open(filename + ".ag", "w") as fd:
                fd.write(bytecode_buff)
            print


def main(options, arguments):
    if options.input != None and options.output != None:
        a = Androguard([options.input])
        export_apps_to_format(options.input, a, options.output, options.limit, options.jar, options.decompiler, options.format)
    elif options.version != None:
        print "Androdd version %s" % androconf.ANDROGUARD_VERSION
    else:
      print "Please, specify an input file and an output directory"

if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
