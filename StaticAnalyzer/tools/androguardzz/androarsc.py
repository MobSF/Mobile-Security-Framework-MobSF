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
from xml.dom import minidom
import codecs

from androguard.core import androconf
from androguard.core.bytecodes import apk


option_0 = { 'name' : ('-i', '--input'), 'help' : 'filename input (APK or android resources(arsc))', 'nargs' : 1 }
option_1 = { 'name' : ('-p', '--package'), 'help' : 'select the package (optional)', 'nargs' : 1 }
option_2 = { 'name' : ('-l', '--locale'), 'help' : 'select the locale (optional)', 'nargs' : 1 }
option_3 = { 'name' : ('-t', '--type'), 'help' : 'select the type (string, interger, public, ...)', 'nargs' : 1 }
option_4 = { 'name' : ('-o', '--output'), 'help' : 'filename output', 'nargs' : 1 }
option_5 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
options = [option_0, option_1, option_2, option_3, option_4, option_5]


def main(options, arguments):
    if options.input != None:
        buff = ""

        arscobj = None
        ret_type = androconf.is_android(options.input)
        if ret_type == "APK":
            a = apk.APK(options.input)
            arscobj = a.get_android_resources()
        elif ret_type == "ARSC":
            arscobj = apk.ARSCParser(open(options.input, "rb").read())
        else:
            print "Unknown file type"
            return

        if not options.package and not options.type and not options.locale:
            buff = ""
            for package in arscobj.get_packages_names():
                buff += package + "\n"
                for locale in arscobj.get_locales(package):
                    buff += "\t" + repr(locale) + "\n"
                    for ttype in arscobj.get_types(package, locale):
                        buff += "\t\t" + ttype + "\n"

        else:
            package = options.package or arscobj.get_packages_names()[0]
            ttype = options.type or "public"
            locale = options.locale or '\x00\x00'

            buff = minidom.parseString(getattr(arscobj, "get_" + ttype + "_resources")(package, locale)).toprettyxml()

        if options.output != None:
            fd = codecs.open(options.output, "w", "utf-8")
            fd.write(buff)
            fd.close()
        else:
            print buff

    elif options.version != None:
        print "Androarsc version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
