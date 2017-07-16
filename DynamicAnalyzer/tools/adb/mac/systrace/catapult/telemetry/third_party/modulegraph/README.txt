modulegraph determines a dependency graph between Python modules primarily
by bytecode analysis for import statements.

modulegraph uses similar methods to modulefinder from the standard library,
but uses a more flexible internal representation, has more extensive 
knowledge of special cases, and is extensible.
