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


option_0 = { 'name' : ('-i', '--input'), 'help' : 'filename input (APK or android\'s binary xml)', 'nargs' : 1 }
option_1 = { 'name' : ('-o', '--output'), 'help' : 'filename output of the xml', 'nargs' : 1 }
option_2 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
options = [option_0, option_1, option_2]


def main(options, arguments) :
    if options.input != None :
        buff = ""

        ret_type = androconf.is_android(options.input)
        if ret_type == "APK":
            a = apk.APK(options.input)
            print a.get_android_manifest_xml()
            buff = a.get_android_manifest_xml().toprettyxml(encoding="utf-8")
            a.get_activities()
        elif ".xml" in options.input:
            ap = apk.AXMLPrinter(open(options.input, "rb").read())
            buff = minidom.parseString(ap.get_buff()).toprettyxml(encoding="utf-8")
        else:
            print "Unknown file type"
            return

        if options.output != None :
            fd = codecs.open(options.output, "w", "utf-8")
            fd.write( buff )
            fd.close()
        else :
            print buff

    elif options.version != None :
        print "Androaxml version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
