Release history
===============

0.12
----

- Added ``ObjectGraph.edgeData`` to retrieve the edge data
  from a specific edge.

- Added ``AltGraph.update_edge_data`` and ``ObjectGraph.updateEdgeData``
  to update the data associated with a graph edge.

0.11
----

- Stabilize the order of elements in dot file exports,
  patch from bitbucket user 'pombredanne'.

- Tweak setup.py file to remove dependency on distribute (but
  keep the dependency on setuptools)


0.10.2
------

- There where no classifiers in the package metadata due to a bug
  in setup.py

0.10.1
------

This is a bugfix release

Bug fixes:

- Issue #3: The source archive contains a README.txt
  while the setup file refers to ReadMe.txt.

  This is caused by a misfeature in distutils, as a
  workaround I've renamed ReadMe.txt to README.txt
  in the source tree and setup file.


0.10
-----

This is a minor feature release

Features:

- Do not use "2to3" to support Python 3.

  As a side effect of this altgraph now supports
  Python 2.6 and later, and no longer supports
  earlier releases of Python.

- The order of attributes in the Dot output
  is now always alphabetical.

  With this change the output will be consistent
  between runs and Python versions.

0.9
---

This is a minor bugfix release

Features:

- Added ``altgraph.ObjectGraph.ObjectGraph.nodes``, a method
  yielding all nodes in an object graph.

Bugfixes:

- The 0.8 release didn't work with py2app when using
  python 3.x.


0.8
-----

This is a minor feature release. The major new feature
is a extensive set of unittests, which explains almost
all other changes in this release.

Bugfixes:

- Installing failed with Python 2.5 due to using a distutils
  class that isn't available in that version of Python
  (issue #1 on the issue tracker)

- ``altgraph.GraphStat.degree_dist`` now actually works

- ``altgraph.Graph.add_edge(a, b, create_nodes=False)`` will
  no longer create the edge when one of the nodes doesn't
  exist.

- ``altgraph.Graph.forw_topo_sort`` failed for some sparse graphs.

- ``altgraph.Graph.back_topo_sort`` was completely broken in
  previous releases.

- ``altgraph.Graph.forw_bfs_subgraph`` now actually works.

- ``altgraph.Graph.back_bfs_subgraph`` now actually works.

- ``altgraph.Graph.iterdfs`` now returns the correct result
  when the ``forward`` argument is ``False``.

- ``altgraph.Graph.iterdata`` now returns the correct result
  when the ``forward`` argument is ``False``.


Features:

- The ``altgraph.Graph`` constructor now accepts an argument
  that contains 2- and 3-tuples instead of requireing that
  all items have the same size. The (optional) argument can now
  also be any iterator.

- ``altgraph.Graph.Graph.add_node`` has no effect when you
  add a hidden node.

- The private method ``altgraph.Graph._bfs`` is no longer
  present.

- The private method ``altgraph.Graph._dfs`` is no longer
  present.

- ``altgraph.ObjectGraph`` now has a ``__contains__`` methods,
  which means you can use the ``in`` operator to check if a
  node is part of a graph.

- ``altgraph.GraphUtil.generate_random_graph`` will raise
  ``GraphError`` instead of looping forever when it is
  impossible to create the requested graph.

- ``altgraph.Dot.edge_style`` raises ``GraphError`` when
  one of the nodes is not present in the graph. The method
  silently added the tail in the past, but without ensuring
  a consistent graph state.

- ``altgraph.Dot.save_img`` now works when the mode is
  ``"neato"``.

0.7.2
-----

This is a minor bugfix release

Bugfixes:

- distutils didn't include the documentation subtree

0.7.1
-----

This is a minor feature release

Features:

- Documentation is now generated using `sphinx <http://pypi.python.org/pypi/sphinx>`_
  and can be viewed at <http://packages.python.org/altgraph>.

- The repository has moved to bitbucket

- ``altgraph.GraphStat.avg_hops`` is no longer present, the function had no
  implementation and no specified behaviour.

- the module ``altgraph.compat`` is gone, which means altgraph will no
  longer work with Python 2.3.


0.7.0
-----

This is a minor feature release.

Features:

- Support for Python 3

- It is now possible to run tests using 'python setup.py test'

  (The actual testsuite is still very minimal though)
