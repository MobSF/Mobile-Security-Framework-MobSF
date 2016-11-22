#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2012/2013/2014, Anthony Desnos <desnos at t0t0.fr>
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

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *

from androguard.util import *
from androguard.misc import *

from IPython.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config


option_0 = { 'name' : ('-i', '--input'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_1 = { 'name' : ('-d', '--display'), 'help' : 'display the file in human readable format', 'action' : 'count' }
option_2 = { 'name' : ('-m', '--method'), 'help' : 'display method(s) respect with a regexp', 'nargs' : 1 }
option_3 = { 'name' : ('-f', '--field'), 'help' : 'display field(s) respect with a regexp', 'nargs' : 1 }
option_4 = { 'name' : ('-s', '--shell'), 'help' : 'open an interactive shell to play more easily with objects', 'action' : 'count' }
option_5 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
option_6 = { 'name' : ('-p', '--pretty'), 'help' : 'pretty print !', 'action' : 'count' }
option_8 = { 'name' : ('-x', '--xpermissions'), 'help' : 'show paths of permissions', 'action' : 'count' }

options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6, option_8]


def init_print_colors():
    from IPython.utils import coloransi, io
    default_colors(coloransi.TermColors)
    CONF["PRINT_FCT"] = io.stdout.write


def interact():
    cfg = Config()
    ipshell = InteractiveShellEmbed(config=cfg, banner1="Androlyze version %s" % ANDROGUARD_VERSION)
    init_print_colors()
    ipshell()


def main(options, arguments):
    if options.shell != None:
        interact()

    elif options.input != None:
        _a = AndroguardS( options.input )

        if options.pretty != None:
          init_print_colors()

        if options.display != None:
            if options.pretty != None:
                _a.ianalyze()
                _a.pretty_show()
            else:
                _a.show()

        elif options.method != None:
            for method in _a.get("method", options.method):
                if options.pretty != None:
                    _a.ianalyze()
                    method.pretty_show()
                else:
                    method.show()

        elif options.field != None:
            for field in _a.get("field", options.field):
                field.show()

        elif options.xpermissions != None:
            _a.ianalyze()
            perms_access = _a.get_analysis().get_permissions( [] )
            for perm in perms_access:
                print "PERM : ", perm
                for path in perms_access[ perm ]:
                    show_Path( _a.get_vm(), path )

    elif options.version != None:
        print "Androlyze version %s" % androconf.ANDROGUARD_VERSION

if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)