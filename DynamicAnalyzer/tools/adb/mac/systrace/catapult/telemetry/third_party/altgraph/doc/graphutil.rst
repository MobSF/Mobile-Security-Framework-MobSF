:mod:`altgraph.GraphUtil` --- Utility functions
================================================

.. module:: altgraph.GraphUtil
   :synopsis: Utility functions

The module :mod:`altgraph.GraphUtil` performs a number of more
or less useful utility functions.

.. function:: generate_random_graph(node_num, edge_num[, self_loops[, multi_edges])

   Generates and returns a :class:`Graph <altgraph.Graph.Graph>` instance
   with *node_num* nodes randomly connected by *edge_num* edges.

   When *self_loops* is present and True there can be edges that point from
   a node to itself.

   When *multi_edge* is present and True there can be duplicate edges.

   This method raises :class:`GraphError <altgraph.GraphError` when
   a graph with the requested configuration cannot be created.

.. function:: generate_scale_free_graph(steps, growth_num[, self_loops[, multi_edges]])

    Generates and returns a :py:class:`~altgraph.Graph.Graph` instance that 
    will have *steps*growth_n um* nodes and a scale free (powerlaw) 
    connectivity. 
    
    Starting with a fully connected graph with *growth_num* nodes
    at every step *growth_num* nodes are added to the graph and are connected 
    to existing nodes with a probability proportional to the degree of these 
    existing nodes.

    .. warning:: The current implementation is basically untested, although
       code inspection seems to indicate an implementation that is consistent
       with the description at 
       `Wolfram MathWorld <http://mathworld.wolfram.com/Scale-FreeNetwork.html>`_

.. function:: filter_stack(graph, head, filters)

   Perform a depth-first oder walk of the graph starting at *head* and
   apply all filter functions in *filters* on the node data of the nodes
   found.

   Returns (*visited*, *removes*, *orphans*), where

   * *visited*: the set of visited nodes

   * *removes*: the list of nodes where the node data doesn't match
     all *filters*.

   * *orphans*: list of tuples (*last_good*, *node*), where 
     node is not in *removes* and one of the nodes that is connected
     by an incoming edge is in *removes*. *Last_good* is the
     closest upstream node that is not in *removes*.
