:mod:`altgraph.GraphAlgo` --- Graph algorithms
==================================================

.. module:: altgraph.GraphAlgo
   :synopsis: Basic graphs algoritms

.. function:: dijkstra(graph, start[, end])

   Dijkstra's algorithm for shortest paths.

   Find shortest paths from the  start node to all nodes nearer 
   than or equal to the *end* node. The edge data is assumed to be the edge length.

   .. note::

       Dijkstra's algorithm is only guaranteed to work correctly when all edge lengths are positive.
       This code does not verify this property for all edges (only the edges examined until the end
       vertex is reached), but will correctly compute shortest paths even for some graphs with negative
       edges, and will raise an exception if it discovers that a negative edge has caused it to make a mistake.


.. function:: shortest_path(graph, start, end)

   Find a single shortest path from the given start node to the given end node.
   The input has the same conventions as :func:`dijkstra`. The output is a list 
   of the nodes in order along the shortest path.
