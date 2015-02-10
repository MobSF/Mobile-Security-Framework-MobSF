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

import sys, os, cmd, threading, re, atexit

from optparse import OptionParser

import androguard, androconf, jvm

# External Libraries

# python-ptrace : http://bitbucket.org/haypo/python-ptrace/
from ptrace import PtraceError
from ptrace.tools import locateProgram
from ptrace.debugger import ProcessExit, DebuggerError, PtraceDebugger, ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution
from ptrace.debugger.memory_mapping import readProcessMappings
####################

option_0 = { 'name' : ('-i', '--input'), 'help' : 'pid', 'nargs' : 1 }

option_1 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }

options = [option_0, option_1]

MAGIC_PATTERN = "\xca\xfe\xba\xbe"

class AndroPreDump :
    def __init__(self, input) :
        self.data = []

        self.pid = int(input)
        self.debugger = PtraceDebugger()
        self.process = self.debugger.addProcess(self.pid, is_attached=False)
        atexit.register(self.debugger.quit)

        Header = False
        Code = False

        self.procmaps = readProcessMappings(self.process)
        for pm in self.procmaps:
            if pm.permissions.find("w") != -1 and pm.pathname == None :

#            if Code == False and Header == True :
#               data = self.process.readBytes(pm.start, pm.end-pm.start)
#               idx = data.find("SourceFile")
#               if idx != -1 :
#                  print "CODE", pm
#                  self.data.append( (pm, data, idx) )
#                  Code = True

                if Header == False :
                    data = self.process.readBytes(pm.start, pm.end-pm.start)
                    idx = data.find(MAGIC_PATTERN)
                    if idx != -1 :
                        print "HEADER", pm
                        self.data.append( (pm, data) )
                        Header = True

        self.dumpMemory( "java_dump_memory" )
#      self.dumpFiles( "java_files" )

    def write(self, idx, buff) :
        self.process.writeBytes( idx, buff )

    def getFilesBuffer(self) :
        for i in self.data :
            d = i[1]
            x = d.find(MAGIC_PATTERN)
            idx = x
            while x != -1 :
                yield i[0].start + idx, d[x:]
                d = d[x+len(MAGIC_PATTERN):]

                idx += len(MAGIC_PATTERN)
                x = d.find(MAGIC_PATTERN)
                idx += x

    def dumpMemory(self, base_filename) :
        for i in self.data :
            fd = open(base_filename + "-" + "0x%x-0x%x" % (i[0].start, i[0].end), "w")
            fd.write( i[1] )
            fd.close()

    def dumpFiles(self, base_filename) :
        for i in self.data :
            fd = open(base_filename + "-" + "0x%x-0x%x" % (i[0].start + i[2], i[0].end), "w")
            fd.write( i[1][i[2]:] )
            fd.close()

class AndroDump :
    def __init__(self, adp) :
        self.__adp = adp

        for i in self.__adp.getFilesBuffer() :
            try :
                print "0x%x :" % (i[0])
                j = jvm.JVMFormat( i[1] )

                for method in j.get_methods() :
                    print "\t -->", method.get_class_name(), method.get_name(), method.get_descriptor()

#               if (method.get_class_name() == "Test2" and method.get_name() == "main") :
#                  print "patch"

#                  code = method.get_code()
                        #code.remplace_at( 51, [ "bipush", 20 ] )
#                  code.show()

#            print "\t\t-> %x" % (len(j.save()))

#            self.__adp.write( i[0], j.save() )
            except Exception, e :
                print e

def main(options, arguments) :
    if options.input != None :
        apd = AndroPreDump( options.input )
        AndroDump( apd )

    elif options.version != None :
        print "Androdump version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
