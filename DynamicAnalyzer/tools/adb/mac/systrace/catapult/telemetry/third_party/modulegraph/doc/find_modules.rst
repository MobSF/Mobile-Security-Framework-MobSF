:mod:`modulegraph.find_modules` --- High-level module dependency finding interface
==================================================================================

.. module:: modulegraph.find_modules
   :synopsis: High-level module dependency finding interface

This module provides a high-level interface to the functionality of 
the modulegraph package.


.. function:: find_modules([scripts[, includes[, packages[, excludes[, path[, debug]]]]]])

   High-level interface, takes iterables for: scripts, includes, packages, excludes

   And returns a :class:`modulegraph.modulegraph.ModuleGraph` instance, 
   python_files, and extensions

   python_files is a list of pure python dependencies as modulegraph.Module objects,

   extensions is a list of platform-specific C extension dependencies as modulegraph.Module objects


.. function:: parse_mf_results(mf)

   Return two lists: the first one contains the python files in the graph,
   the second the C extensions.
        
   :param mf: a :class:`modulegraph.modulegraph.ModuleGraph` instance


Lower-level functionality
-------------------------

The functionality in this section is much lower level and should probably
not be used. It's mostly documented as a convenience for maintainers.


.. function:: get_implies()

   Return a mapping of implied dependencies. The key is a, possibly dotted,
   module name and the value a list of dependencies.

   This contains hardcoded list of hard dependencies, for example for C
   extensions in the standard libary that perform imports in C code, which
   the generic dependency finder cannot locate.

.. function:: plat_prepare(includes, packages, excludes)

   Updates the lists of includes, packages and excludes for the current
   platform. This will add items to these lists based on hardcoded platform
   information.

.. function:: find_needed_modules([mf[, scripts[, includes[, packages[, warn]]]]])

   Feeds the given :class:`ModuleGraph <modulegraph.ModuleGraph>`  with
   the *scripts*, *includes* and *packages* and returns the resulting
   graph. This function will create a new graph when *mf* is not specified
   or ``None``.
