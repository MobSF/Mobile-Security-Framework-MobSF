:mod:`altgraph` --- A Python Graph Library
==================================================

.. module:: altgraph
   :synopsis: A directional graph for python

altgraph is a fork of `graphlib <http://pygraphlib.sourceforge.net>`_ tailored
to use newer Python 2.3+ features, including additional support used by the
py2app suite (modulegraph and macholib, specifically).

altgraph is a python based graph (network) representation and manipulation package.
It has started out as an extension to the `graph_lib module <http://www.ece.arizona.edu/~denny/python_nest/graph_lib_1.0.1.html>`_
written by Nathan Denny it has been significantly optimized and expanded.

The :class:`altgraph.Graph.Graph` class is loosely modeled after the `LEDA <http://www.algorithmic-solutions.com/enleda.htm>`_ 
(Library of Efficient Datatypes)  representation. The library
includes methods for constructing graphs, BFS and DFS traversals,
topological sort, finding connected components, shortest paths as well as a number
graph statistics functions. The library can also visualize graphs
via `graphviz <http://www.research.att.com/sw/tools/graphviz/>`_.


.. exception:: GraphError

   Exception raised when methods are called with bad values of
   an inconsistent state.
