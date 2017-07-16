Commandline tools
=================

The package can be used as a script using "python -mmodulegraph".

This script calculates the module graph for the scripts passed
on the commandline and by default prints a list of modules
in the objectgraph, and their type and location.

The script has a number of options to change the output:

* ``-d``: Increase the debug level

* ``-q``: Clear the debug level (emit minimal output)

* ``-m``: The arguments are module names instead of script files

* ``-x name``: Add ``name`` to the list of excludes

* ``-p path``: Add ``path`` to the module search path

* ``-g``: Emit a ``.dot`` file instead of a list of modules

* ``-h``: Emit a ``.html`` file instead of a list of modules

Deprecation warning
-------------------

The package also installs a command-line tool named "modulegraph",
this command-line tool is deprecated and will be removed in a
future version.
