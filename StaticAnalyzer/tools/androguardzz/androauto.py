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
from androguard.core.analysis import auto
from androguard.core.androconf import set_debug

option_0 = {'name': ('-d', '--directory'), 'help': 'directory input', 'nargs': 1}
option_1 = {'name': ('-v', '--verbose'), 'help': 'add debug', 'action': 'count'}
options = [option_0, option_1]


class AndroLog:
  def __init__(self, id_file, filename):
    self.id_file = id_file


def main(options, arguments):
  if options.verbose:
    set_debug()

  if options.directory:
    settings = {
      "my": auto.DirectoryAndroAnalysis(options.directory),
      "log": AndroLog,
      "max_fetcher": 3,
    }

    aa = auto.AndroAuto(settings)
    aa.go()

if __name__ == "__main__":
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
