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

import sys, re, os

from optparse import OptionParser

from androguard.core.bytecodes import apk

sys.path.append("./elsim/")
from elsim.elsign import dalvik_elsign

sys.path.append("./mercury/client")
from merc.lib.common import Session

option_0 = { 'name' : ('-l', '--list'), 'help' : 'list all packages', 'nargs' : 1 }
option_1 = { 'name' : ('-i', '--input'), 'help' : 'get specific packages (a filter)', 'nargs' : 1 }
option_2 = { 'name' : ('-r', '--remotehost'), 'help' : 'specify ip of emulator/device', 'nargs' : 1 }
option_3 = { 'name' : ('-p', '--port'), 'help' : 'specify the port', 'nargs' : 1 }
option_4 = { 'name' : ('-o', '--output'), 'help' : 'output directory to write packages', 'nargs' : 1 }
option_5 = { 'name' : ('-b', '--database'), 'help' : 'database : use this database', 'nargs' : 1 }
option_6 = { 'name' : ('-c', '--config'), 'help' : 'use this configuration', 'nargs' : 1 }
option_7 = { 'name' : ('-v', '--verbose'), 'help' : 'display debug information', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6, option_7]

def display(ret, debug) :
    print "---->", ret[0],

def main(options, arguments) :
    sessionip = "127.0.0.1"
    sessionport = 31415
    
    if options.remotehost :
        sessionip = options.remotehost

    if options.port :
        sessionport = int(options.port)

    newsession = Session(sessionip, sessionport, "bind")

    # Check if connection can be established
    if newsession.executeCommand("core", "ping", None).data == "pong":
      
        if options.list :
            request = {'filter': options.list, 'permissions': None }
            apks_info = newsession.executeCommand("packages", "info", {}).getPaddedErrorOrData()
            print apks_info

        elif options.input and options.output :
            s = None
            if options.database != None or options.config != None :
                s = dalvik_elsign.MSignature( options.database, options.config, options.verbose != None, ps = dalvik_elsign.PublicSignature)
            
            request = {'filter': options.input, 'permissions': None }
            apks_info = newsession.executeCommand("packages", "info", request).getPaddedErrorOrData()
            print apks_info

            for i in apks_info.split("\n") :
                if re.match("APK path:", i) != None :
                    name_app = i.split(":")[1][1:]
                    print name_app,
                    response = newsession.downloadFile(name_app, options.output)
                    print response.data, response.error,
                    
                    if s != None :
                        a = apk.APK( options.output + "/" + os.path.basename(name_app) )
                        if a.is_valid_APK() :
                            display( s.check_apk( a ), options.verbose )
                    print
    else:
        print "\n**Network Error** Could not connect to " + sessionip + ":" + str(sessionport) + "\n"

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
