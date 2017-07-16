:mod:`modulegraph.modulegraph` --- Find modules used by a script
================================================================

.. module:: modulegraph.modulegraph
   :synopsis: Find modules used by a script

This module defines :class:`ModuleGraph`, which is used to find
the dependencies of scripts using bytecode analysis.

A number of APIs in this module refer to filesystem path. Those paths can refer to
files inside zipfiles (for example when there are zipped egg files on :data:`sys.path`).
Filenames referring to entries in a zipfile are not marked any way, if ``"somepath.zip"``
refers to a zipfile, that is ``"somepath.zip/embedded/file"`` will be used to refer to
``embedded/file`` inside the zipfile.

The actual graph
----------------

.. class:: ModuleGraph([path[, excludes[, replace_paths[, implies[, graph[, debug]]]]]])

   Create a new ModuleGraph object. Use the :meth:`run_script` method to add scripts,
   and their dependencies to the graph.

   :param path: Python search path to use, defaults to :data:`sys.path`
   :param excludes: Iterable with module names that should not be included as a dependency
   :param replace_paths: List of pathname rewrites ``(old, new)``. When this argument is
     supplied the ``co_filename`` attributes of code objects get rewritten before scanning
     them for dependencies.
   :param implies: Implied module dependencies, a mapping from a module name to the list
     of modules it depends on. Use this to tell modulegraph about dependencies that cannot
     be found by code inspection (such as imports from C code or using the :func:`__import__`
     function).
   :param graph: A precreated :class:`Graph <altgraph.Graph.Graph>` object to use, the
     default is to create a new one.
   :param debug: The :class:`ObjectGraph <altgraph.ObjectGraph.ObjectGraph>` debug level.


.. method:: run_script(pathname[, caller])

   Create, and return,  a node by path (not module name). The *pathname* should
   refer to a Python source file and will be scanned for dependencies.

   The optional argument *caller* is the the node that calls this script,
   and is used to add a reference in the graph.

.. method:: import_hook(name[[, caller[, fromlist[, level, [, attr]]]])

   Import a module and analyse its dependencies

   :arg name:     The module name
   :arg caller:   The node that caused the import to happen
   :arg fromlist: The list of names to import, this is an empty list for
      ``import name`` and a list of names for ``from name import a, b, c``.
   :arg level:    The import level. The value should be ``-1`` for classical Python 2
     imports, ``0`` for absolute imports and a positive number for relative imports (
     where the value is the number of leading dots in the imported name).
   :arg attr:     Attributes for the graph edge.


.. method:: implyNodeReference(node, other, edgeData=None)

   Explictly mark that *node* depends on *other*. Other is either
   a :class:`node <Node>` or the name of a module that will be
   searched for as if it were an absolute import.


.. method:: createReference(fromnode, tonode[, edge_data])

   Create a reference from *fromnode* to *tonode*, with optional edge data.

   The default for *edge_data* is ``"direct"``.

.. method:: getReferences(fromnode)

   Yield all nodes that *fromnode* refers to. That is, all modules imported
   by *fromnode*.

   Node :data:`None` is the root of the graph, and refers to all notes that were
   explicitly imported by :meth:`run_script` or :meth:`import_hook`, unless you use
   an explicit parent with those methods.

   .. versionadded:: 0.11

.. method:: getReferers(tonode, collapse_missing_modules=True)

   Yield all nodes that refer to *tonode*. That is, all modules that import
   *tonode*.

   If *collapse_missing_modules* is false this includes refererences from
   :class:`MissingModule` nodes, otherwise :class:`MissingModule` nodes
   are replaced by the "real" nodes that reference this missing node.

   .. versionadded:: 0.12

.. method:: foldReferences(pkgnode)

   Hide all submodule nodes for package *pkgnode* and add ingoing and outgoing
   edges to *pkgnode* based on the edges from the submodule nodes.

   This can be used to simplify a module graph: after folding 'email' all
   references to modules in the 'email' package are references to the package.

   .. versionadded: 0.11

.. method:: findNode(name)

   Find a node by identifier.  If a node by that identifier exists, it will be returned.

   If a lazy node exists by that identifier with no dependencies (excluded), it will be
   instantiated and returned.

   If a lazy node exists by that identifier with dependencies, it and its
   dependencies will be instantiated and scanned for additional depende



.. method:: create_xref([out])

   Write an HTML file to the *out* stream (defaulting to :data:`sys.stdout`).

   The HTML file contains a textual description of the dependency graph.



.. method:: graphreport([fileobj[, flatpackages]])

   .. todo:: To be documented



.. method:: report()

   Print a report to stdout, listing the found modules with their
   paths, as well as modules that are missing, or seem to be missing.


Mostly internal methods
.......................

The methods in this section should be considered as methods for subclassing at best,
please let us know if you need these methods in your code as they are on track to be
made private methods before the 1.0 release.

.. warning:: The methods in this section will be refactored in a future release,
   the current architecture makes it unnecessarily hard to write proper tests.

.. method:: determine_parent(caller)

   Returns the node of the package root voor *caller*. If *caller* is a package
   this is the node itself, if the node is a module in a package this is the
   node of for the package and otherwise the *caller* is not a package and
   the result is :data:`None`.

.. method:: find_head_package(parent, name[, level])

   .. todo:: To be documented


.. method:: load_tail(mod, tail)

   This method is called to load the rest of a dotted name after loading the root
   of a package. This will import all intermediate modules as well (using
   :meth:`import_module`), and returns the module :class:`node <Node>` for the
   requested node.

   .. note:: When *tail* is empty this will just return *mod*.

   :arg mod:   A start module (instance of :class:`Node`)
   :arg tail:  The rest of a dotted name, can be empty
   :raise ImportError: When the requested (or one of its parents) module cannot be found
   :returns: the requested module



.. method:: ensure_fromlist(m, fromlist)

   Yield all submodules that would be imported when importing *fromlist*
   from *m* (using ``from m import fromlist...``).

   *m* must be a package and not a regular module.

.. method:: find_all_submodules(m)

   Yield the filenames for submodules of in the same package as *m*.



.. method:: import_module(partname, fqname, parent)

   Perform import of the module with basename *partname* (``path``) and
   full name *fqname* (``os.path``). Import is performed by *parent*.

   This will create a reference from the parent node to the
   module node and will load the module node when it is not already
   loaded.



.. method:: load_module(fqname, fp, pathname, (suffix, mode, type))

   Load the module named *fqname* from the given *pathame*. The
   argument *fp* is either :data:`None`, or a stream where the
   code for the Python module can be loaded (either byte-code or
   the source code). The *(suffix, mode, type)* tuple are the
   suffix of the source file, the open mode for the file and the
   type of module.

   Creates a node of the right class and processes the dependencies
   of the :class:`node <Node>` by scanning the byte-code for the node.

   Returns the resulting :class:`node <Node>`.



.. method:: scan_code(code, m)

   Scan the *code* object for module *m* and update the dependencies of
   *m* using the import statemets found in the code.

   This will automaticly scan the code for nested functions, generator
   expressions and list comprehensions as well.



.. method:: load_package(fqname, pathname)

   Load a package directory.



.. method:: find_module(name, path[, parent])

   Locates a module named *name* that is not yet part of the
   graph. This method will raise :exc:`ImportError` when
   the module cannot be found or when it is already part
   of the graph. The *name* can not be a dotted name.

   The *path* is the search path used, or :data:`None` to
   use the default path.

   When the *parent* is specified *name* refers to a
   subpackage of *parent*, and *path* should be the
   search path of the parent.

   Returns the result of the global function
   :func:`find_module <modulegraph.modulegraph.find_module>`.


.. method:: itergraphreport([name[, flatpackages]])

   .. todo:: To be documented



.. method:: replace_paths_in_code(co)

   Replace the filenames in code object *co* using the *replace_paths* value that
   was passed to the contructor. Returns the rewritten code object.



.. method:: calc_setuptools_nspackages()

   Returns a mapping from package name to a list of paths where that package
   can be found in ``--single-version-externally-managed`` form.

   This method is used to be able to find those packages: these use
   a magic ``.pth`` file to ensure that the package is added to :data:`sys.path`,
   as they do not contain an ``___init__.py`` file.

   Packages in this form are used by system packages and the "pip"
   installer.


Graph nodes
-----------

The :class:`ModuleGraph` contains nodes that represent the various types of modules.

.. class:: Alias(value)

   This is a subclass of string that is used to mark module aliases.



.. class:: Node(identifier)

   Base class for nodes, which provides the common functionality.

   Nodes can by used as mappings for storing arbitrary data in the node.

   Nodes are compared by comparing their *identifier*.

.. data:: debug

   Debug level (integer)

.. data:: graphident

   The node identifier, this is the value of the *identifier* argument
   to the constructor.

.. data:: identifier

   The node identifier, this is the value of the *identifier* argument
   to the constructor.

.. data:: filename

   The filename associated with this node.

.. data:: packagepath

   The value of ``__path__`` for this node.

.. data:: code

   The :class:`code object <types.CodeObject>` associated with this node

.. data:: globalnames

   The set of global names that are assigned to in this module. This
   includes those names imported through startimports of Python modules.

.. data:: startimports

   The set of startimports this module did that could not be resolved,
   ie. a startimport from a non-Python module.


.. method:: __contains__(name)

   Return if there is a value associated with *name*.

   This method is usually accessed as ``name in aNode``.

.. method:: __setitem__(name, value)

   Set the value of *name* to *value*.

   This method is usually accessed as ``aNode[name] = value``.

.. method:: __getitem__(name)

   Returns the value of *name*, raises :exc:`KeyError` when
   it cannot be found.

   This method is usually accessed as ``value = aNode[name]``.

.. method:: get(name[, default])

   Returns the value of *name*, or the default value when it
   cannot be found. The *default* is :data:`None` when not specified.

.. method:: infoTuple()

   Returns a tuple with information used in the :func:`repr`
   output for the node. Subclasses can add additional informations
   to the result.


.. class:: AliasNode (name, node)

   A node that represents an alias from a name to another node.

   The value of attribute *graphident* for this node will be the
   value of *name*, the other :class:`Node` attributed are
   references to those attributed in *node*.

.. class:: BadModule(identifier)

   Base class for nodes that should be ignored for some reason

.. class:: ExcludedModule(identifier)

   A module that is explicitly excluded.

.. class:: MissingModule(identifier)

   A module that is imported but cannot be located.



.. class:: Script(filename)

   A python script.

   .. data:: filename

      The filename for the script

.. class:: BaseModule(name[, filename[, path]])

    The base class for actual modules. The *name* is
    the possibly dotted module name, *filename* is the
    filesystem path to the module and *path* is the
    value of ``__path__`` for the module.

.. data:: graphident

   The name of the module

.. data:: filename

   The filesystem path to the module.

.. data:: path

   The value of ``__path__`` for this module.

.. class:: BuiltinModule(name)

   A built-in module (on in :data:`sys.builtin_module_names`).

.. class:: SourceModule(name)

   A module for which the python source code is available.

.. class:: InvalidSourceModule(name)

   A module for which the python source code is available, but where
   that source code cannot be compiled (due to syntax errors).

   This is a subclass of :class:`SourceModule`.

   .. versionadded:: 0.12

.. class:: CompiledModule(name)

   A module for which only byte-code is available.

.. class:: Package(name)

   Represents a python package

.. class:: NamespacePackage(name)

   Represents a python namespace package.

   This is a subclass of :class:`Package`.

.. class:: Extension(name)

   A native extension


.. warning:: A number of other node types are defined in the module. Those modules aren't
   used by modulegraph and will be removed in a future version.


Edge data
---------

The edges in a module graph by default contain information about the edge, represented
by an instance of :class:`DependencyInfo`.

.. class:: DependencyInfo(conditional, function, tryexcept, fromlist)

   This class is a :func:`namedtuple <collections.namedtuple>` for representing
   the information on a dependency between two modules.

   All attributes can be used to deduce if a dependency is essential or not, and
   are particularly useful when reporting on missing modules (dependencies on
   :class:`MissingModule`).

   .. data:: fromlist

      A boolean that is true iff the target of the edge is named in the "import"
      list of a "from" import ("from package import module").

      When the target module is imported multiple times this attribute is false
      unless all imports are in "import" list of a "from" import.

   .. data:: function

      A boolean that is true iff the import is done inside a function definition,
      and is false for imports in module scope (or class scope for classes that
      aren't definined in a function).

   .. data:: tryexcept

      A boolean that is true iff the import that is done in the "try" or "except"
      block of a try statement (but not in the "else" block).

   .. data:: conditional

      A boolean that is true iff the import is done in either block of an "if"
      statement.

   When the target of the edge is imported multiple times the :data:`function`,
   :data:`tryexcept` and :data:`conditional` attributes of all imports are
   merged: when there is an import where all these attributes are false the
   attributes are false, otherwise each attribute is set to true if it is
   true for at least one of the imports.

   For example, when a module is imported both in a try-except statement and
   furthermore is imported in a function (in two separate statements),
   both :data:`tryexcept` and :data:`function` will be true.  But if there
   is a third unconditional toplevel import for that module as well all
   three attributes are false.

   .. warning::

      All attributes but :data:`fromlist` will be false when the source of
      a dependency is scanned from a byte-compiled module instead of a python
      source file. The :data:`fromlist` attribute will stil be set correctly.

Utility functions
-----------------

.. function:: find_module(name[, path])

   A version of :func:`imp.find_module` that works with zipped packages (and other
   :pep:`302` importers).

.. function:: moduleInfoForPath(path)

   Return the module name, readmode and type for the file at *path*, or
   None if it doesn't seem to be a valid module (based on its name).

.. function:: addPackagePath(packagename, path)

   Add *path* to the value of ``__path__`` for the package named *packagename*.

.. function:: replacePackage(oldname, newname)

   Rename *oldname* to *newname* when it is found by the module finder. This
   is used as a workaround for the hack that the ``_xmlplus`` package uses
   to inject itself in the ``xml`` namespace.


