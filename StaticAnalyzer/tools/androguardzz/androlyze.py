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

import sys, os, cmd, threading, code, re


from optparse import OptionParser

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.jvm import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *

from androguard.decompiler.decompiler import *

from androguard.core import androconf

from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config

from cPickle import dumps, loads

option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
option_2 = { 'name' : ('-m', '--method'), 'help' : 'display method(s) respect with a regexp', 'nargs' : 1 }
option_3 = { 'name' : ('-f', '--field'), 'help' : 'display field(s) respect with a regexp', 'nargs' : 1 }
option_4 = { 'name' : ('-s', '--shell'), 'help' : 'open an interactive shell to play more easily with objects', 'action' : 'count' }
option_5 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
option_6 = { 'name' : ('-p', '--pretty'), 'help' : 'pretty print !', 'action' : 'count' }
option_8 = { 'name' : ('-x', '--xpermissions'), 'help' : 'show paths of permissions', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6, option_8]

def init_print_colors() :
    from IPython.utils import coloransi, io
    default_colors(coloransi.TermColors)
    CONF["PRINT_FCT"] = io.stdout.write

def interact() :
    cfg = Config()
    ipshell = InteractiveShellEmbed(config=cfg, banner1="Androlyze version %s" % androconf.ANDROGUARD_VERSION)
    init_print_colors()
    ipshell()

def save_session(l, filename) :
    """
        save your session !

        :param l: a list of objects
        :type: a list of object
        :param filename: output filename to save the session
        :type filename: string

        :Example:
            save_session([a, vm, vmx], "msession.json")
    """
    fd = open(filename, "w")
    fd.write( dumps(l, -1) )
    fd.close()

def load_session(filename) :
    """
        load your session !

        :param filename: the filename where the session has been saved
        :type filename: string
        
        :rtype: the elements of your session :)

        :Example: 
            a, vm, vmx = load_session("mysession.json")
    """
    return loads( open(filename, "r").read() )

def AnalyzeAPK(filename, raw=False, decompiler=None) :
    """
        Analyze an android application and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android application or a buffer which represents the application
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean
        :param decompiler: ded, dex2jad, dad (optional)
        :type decompiler: string
        
        :rtype: return the :class:`APK`, :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("APK ...")
    a = APK(filename, raw)

    d, dx = AnalyzeDex( a.get_dex(), raw=True, decompiler=decompiler )

    return a, d, dx


def AnalyzeDex(filename, raw=False, decompiler=None) :
    """
        Analyze an android dex file and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android dex file or a buffer which represents the dex file
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean

        :rtype: return the :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("DalvikVMFormat ...")
    d = None
    if raw == False :
        d = DalvikVMFormat( open(filename, "rb").read() )
    else :
        d = DalvikVMFormat( filename )

    androconf.debug("Export VM to python namespace")
    d.create_python_export()

    androconf.debug("VMAnalysis ...")
    dx = uVMAnalysis( d )

    androconf.debug("GVMAnalysis ...")
    gx = GVMAnalysis( dx, None )

    d.set_vmanalysis( dx )
    d.set_gvmanalysis( gx )

    RunDecompiler( d, dx, decompiler )

    androconf.debug("XREF ...")
    d.create_xref()
    androconf.debug("DREF ...")
    d.create_dref()

    return d, dx

def RunDecompiler(d, dx, decompiler) :
    """
        Run the decompiler on a specific analysis

        :param d: the DalvikVMFormat object
        :type d: :class:`DalvikVMFormat` object
        :param dx: the analysis of the format
        :type dx: :class:`VMAnalysis` object 
        :param decompiler: the type of decompiler to use ("dad", "dex2jad", "ded")
        :type decompiler: string
    """
    if decompiler != None :
      androconf.debug("Decompiler ...")
      decompiler = decompiler.lower()
      if decompiler == "dex2jad" :
        d.set_decompiler( DecompilerDex2Jad( d, androconf.CONF["PATH_DEX2JAR"], androconf.CONF["BIN_DEX2JAR"], androconf.CONF["PATH_JAD"], androconf.CONF["BIN_JAD"], androconf.CONF["TMP_DIRECTORY"] ) )
      elif decompiler == "ded" :
        d.set_decompiler( DecompilerDed( d, androconf.CONF["PATH_DED"], androconf.CONF["BIN_DED"], androconf.CONF["TMP_DIRECTORY"]) )
      elif decompiler == "dad" :
        d.set_decompiler( DecompilerDAD( d, dx ) )
      else :
        print "Unknown decompiler, use DAD decompiler by default"
        d.set_decompiler( DecompilerDAD( d, dx ) )

def AnalyzeElf(filename, raw=False) :
    # avoid to install smiasm for everybody
    from androguard.core.binaries.elf import ELF 

    e = None
    if raw == False:
        e = ELF( open(filename, "rb").read() )
    else:
        e = ELF( filename )

    ExportElfToPython( e )

    return e

def ExportElfToPython(e) :
    for function in e.get_functions():
        name = "FUNCTION_" + function.name
        setattr( e, name, function )
        
def AnalyzeJAR(filename, raw=False) :
    androconf.debug("JAR ...")
    a = JAR(filename, raw)

    d = AnalyzeClasses( a.get_classes() )

    return a, d

def AnalyzeClasses( classes ) :
  d = {}
  for i in classes :
    d[i[0]] = JVMFormat( i[1] )

  return d

def main(options, arguments) :
    if options.shell != None :
        interact()

    elif options.input != None :
        _a = AndroguardS( options.input )

        if options.pretty != None :
          init_print_colors()

        if options.display != None :
            if options.pretty != None :
                _a.ianalyze()
                _a.pretty_show()
            else :
                _a.show()

        elif options.method != None :
            for method in _a.get("method", options.method) :
                if options.pretty != None :
                    _a.ianalyze()
                    method.pretty_show() 
                else :
                    method.show()

        elif options.field != None :
            for field in _a.get("field", options.field) :
                field.show()

        elif options.xpermissions != None :
            _a.ianalyze()
            perms_access = _a.get_analysis().get_permissions( [] )
            for perm in perms_access :
                print "PERM : ", perm
                for path in perms_access[ perm ] :
                    show_Path( _a.get_vm(), path )

    elif options.version != None :
        print "Androlyze version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
