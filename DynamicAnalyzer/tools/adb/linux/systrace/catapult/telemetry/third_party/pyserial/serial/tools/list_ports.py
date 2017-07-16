#!/usr/bin/env python

# portable serial port access with python
# this is a wrapper module for different platform implementations of the
# port enumeration feature
#
# (C) 2011-2013 Chris Liechti <cliechti@gmx.net>
# this is distributed under a free software license, see license.txt

"""\
This module will provide a function called comports that returns an
iterable (generator or list) that will enumerate available com ports. Note that
on some systems non-existent ports may be listed.

Additionally a grep function is supplied that can be used to search for ports
based on their descriptions or hardware ID.
"""

import sys, os, re

# chose an implementation, depending on os
#~ if sys.platform == 'cli':
#~ else:
import os
# chose an implementation, depending on os
if os.name == 'nt': #sys.platform == 'win32':
    from serial.tools.list_ports_windows import *
elif os.name == 'posix':
    from serial.tools.list_ports_posix import *
#~ elif os.name == 'java':
else:
    raise ImportError("Sorry: no implementation for your platform ('%s') available" % (os.name,))

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def grep(regexp):
    """\
    Search for ports using a regular expression. Port name, description and
    hardware ID are searched. The function returns an iterable that returns the
    same tuples as comport() would do.
    """
    r = re.compile(regexp, re.I)
    for port, desc, hwid in comports():
        if r.search(port) or r.search(desc) or r.search(hwid):
            yield port, desc, hwid


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def main():
    import optparse

    parser = optparse.OptionParser(
        usage = "%prog [options] [<regexp>]",
        description = "Miniterm - A simple terminal program for the serial port."
    )

    parser.add_option("--debug",
            help="print debug messages and tracebacks (development mode)",
            dest="debug",
            default=False,
            action='store_true')

    parser.add_option("-v", "--verbose",
            help="show more messages (can be given multiple times)",
            dest="verbose",
            default=1,
            action='count')

    parser.add_option("-q", "--quiet",
            help="suppress all messages",
            dest="verbose",
            action='store_const',
            const=0)

    (options, args) = parser.parse_args()


    hits = 0
    # get iteraror w/ or w/o filter
    if args:
        if len(args) > 1:
            parser.error('more than one regexp not supported')
        print "Filtered list with regexp: %r" % (args[0],)
        iterator = sorted(grep(args[0]))
    else:
        iterator = sorted(comports())
    # list them
    for port, desc, hwid in iterator:
        print("%-20s" % (port,))
        if options.verbose > 1:
            print("    desc: %s" % (desc,))
            print("    hwid: %s" % (hwid,))
        hits += 1
    if options.verbose:
        if hits:
            print("%d ports found" % (hits,))
        else:
            print("no ports found")

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# test
if __name__ == '__main__':
    main()
