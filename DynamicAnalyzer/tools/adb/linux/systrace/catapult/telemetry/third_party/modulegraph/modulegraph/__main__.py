from __future__ import print_function
import sys
import os
import optparse
import textwrap
from .modulegraph import ModuleGraph

def main():
    # Parse command line
    usage = textwrap.dedent('''\
        Usage:
            modulegraph [options] scriptfile ...

        Valid options:
        * -d: Increase debug level
        * -q: Clear debug level

        * -m: arguments are module names, not script files
        * -x name: Add 'name' to the excludes list
        * -p name: Add 'name' to the module search path

        * -g: Output a .dot graph
        * -h: Output a html file
    ''')
    parser = optparse.OptionParser(usage=usage, add_help_option=False)
    parser.add_option('-d', action='count', dest='debug', default=1)
    parser.add_option('-q', action='store_const', dest='debug', const=0)

    parser.add_option('-m', action='store_true', dest='domods', default=False)
    parser.add_option('-x', action='append', dest='excludes', default=[])
    parser.add_option('-p', action='append', dest='addpath', default=[])

    parser.add_option('-g', action='store_const', dest='output', const='dot')
    parser.add_option('-h', action='store_const', dest='output', const='html')
    opts, args = parser.parse_args()

    if not args:
        print("No script specified", file=sys.stderr)
        print(usage, file=sys.stderr)
        sys.exit(1)

    script = args[0]

    # Set the path based on sys.path and the script directory
    path = sys.path[:]
    path[0] = os.path.dirname(script)
    path = opts.addpath + path
    if opts.debug > 1:
        print("path:", file=sys.stderr)
        for item in path:
            print("   ", repr(item), file=sys.stderr)

    # Create the module finder and turn its crank
    mf = ModuleGraph(path, excludes=opts.excludes, debug=opts.debug)
    for arg in args:
        if opts.domods:
            if arg[-2:] == '.*':
                mf.import_hook(arg[:-2], None, ["*"])
            else:
                mf.import_hook(arg)
        else:
            mf.run_script(arg)
    if opts.output == 'dot':
        mf.graphreport()
    elif opts.output == 'html':
        mf.create_xref()
    else:
        mf.report()
    sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrupt]")
