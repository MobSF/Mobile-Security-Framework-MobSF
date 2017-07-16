:mod:`altgraph.Graph` --- Basic directional graphs
==================================================

.. module:: altgraph.Graph
   :synopsis: Basic directional graphs.

The module :mod:`altgraph.Graph` provides a class :class:`Graph` that
represents a directed graph with *N* nodes and *E* edges.

.. class:: Graph([edges])

  Constructs a new empty :class:`Graph` object. If the optional
  *edges* parameter is supplied, updates the graph by adding the
  specified edges.

  All of the elements in *edges* should be tuples with two or three
  elements. The first two elements of the tuple are the source and
  destination node of the edge, the optional third element is the
  edge data.  The source and destination nodes are added to the graph
  when the aren't already present.


Node related methods
--------------------

.. method:: Graph.add_node(node[, node_data])

   Adds a new node to the graph if it is not already present. The new
   node must be a hashable object.

   Arbitrary data can be attached to the node via the optional *node_data*
   argument.

   .. note:: the node also won't be added to the graph when it is
      present but currently hidden.


.. method:: Graph.hide_node(node)

   Hides a *node* from the graph. The incoming and outgoing edges of
   the node will also be hidden.

   Raises :class:`altgraph.GraphError` when the node is not (visible)
   node of the graph.


.. method:: Graph.restore_node(node)

   Restores a previously hidden *node*. The incoming and outgoing
   edges of the node are also restored.

   Raises :class:`altgraph.GraphError` when the node is not a hidden
   node of the graph.

.. method:: Graph.restore_all_nodes()

   Restores all hidden nodes.

.. method:: Graph.number_of_nodes()

   Return the number of visible nodes in the graph.

.. method:: Graph.number_of_hidden_nodes()

   Return the number of hidden nodes in the graph.

.. method:: Graph.node_list()

   Return a list with all visible nodes in the graph.

.. method:: Graph.hidden_node_list()

   Return a list with all hidden nodes in the graph.

.. method:: node_data(node)

   Return the data associated with the *node* when it was
   added.

.. method:: Graph.describe_node(node)

   Returns *node*, the node's data and the lists of outgoing
   and incoming edges for the node.

   .. note::

      the edge lists should not be modified, doing so
      can result in unpredicatable behavior.

.. method:: Graph.__contains__(node)

   Returns True iff *node* is a node in the graph. This
   method is accessed through the *in* operator.

.. method:: Graph.__iter__()

   Yield all nodes in the graph.

.. method:: Graph.out_edges(node)

   Return the list of outgoing edges for *node*

.. method:: Graph.inc_edges(node)

   Return the list of incoming edges for *node*

.. method:: Graph.all_edges(node)

   Return the list of incoming and outgoing edges for *node*

.. method:: Graph.out_degree(node)

   Return the number of outgoing edges for *node*.

.. method:: Graph.inc_degree(node)

   Return the number of incoming edges for *node*.

.. method:: Graph.all_degree(node)

   Return the number of edges (incoming or outgoing) for *node*.

Edge related methods
--------------------

.. method:: Graph.add_edge(head_id, tail_id [, edge data [, create_nodes]])

   Adds a directed edge from *head_id* to *tail_id*. Arbitrary data can
   be added via *edge_data*.  When *create_nodes* is *True* (the default),
   *head_id* and *tail_id* will be added to the graph when the aren't
   already present.

.. method:: Graph.hide_edge(edge)

   Hides an edge from the graph. The edge may be unhidden at some later
   time.

.. method:: Graph.restore_edge(edge)

   Restores a previously hidden *edge*.

.. method:: Graph.restore_all_edges()

   Restore all edges that were hidden before, except for edges
   referring to hidden nodes.

.. method:: Graph.edge_by_node(head, tail)

   Return the edge ID for an edge from *head* to *tail*,
   or :data:`None` when no such edge exists.

.. method:: Graph.edge_by_id(edge)

   Return the head and tail of the *edge*

.. method:: Graph.edge_data(edge)

   Return the data associated with the *edge*.

.. method:: Graph.update_edge_data(edge, data)

   Replace the edge data for *edge* by *data*. Raises
   :exc:`KeyError` when the edge does not exist.

   .. versionadded:: 0.12

.. method:: Graph.head(edge)

   Return the head of an *edge*

.. method:: Graph.tail(edge)

   Return the tail of an *edge*

.. method:: Graph.describe_edge(edge)

   Return the *edge*, the associated data, its head and tail.

.. method:: Graph.number_of_edges()

   Return the number of visible edges.

.. method:: Graph.number_of_hidden_edges()

   Return the number of hidden edges.

.. method:: Graph.edge_list()

   Returns a list with all visible edges in the graph.

.. method:: Graph.hidden_edge_list()

   Returns a list with all hidden edges in the graph.

Graph traversal
---------------

.. method:: Graph.out_nbrs(node)

   Return a list of all nodes connected by outgoing edges.

.. method:: Graph.inc_nbrs(node)

   Return a list of all nodes connected by incoming edges.

.. method:: Graph.all_nbrs(node)

   Returns a list of nodes connected by an incoming or outgoing edge.

.. method:: Graph.forw_topo_sort()

   Return a list of nodes where the successors (based on outgoing
   edges) of any given node apear in the sequence after that node.

.. method:: Graph.back_topo_sort()

   Return a list of nodes where the successors (based on incoming
   edges) of any given node apear in the sequence after that node.

.. method:: Graph.forw_bfs_subgraph(start_id)

   Return a subgraph consisting of the breadth first
   reachable nodes from *start_id* based on their outgoing edges.


.. method:: Graph.back_bfs_subgraph(start_id)

   Return a subgraph consisting of the breadth first
   reachable nodes from *start_id* based on their incoming edges.

.. method:: Graph.iterdfs(start[, end[, forward]])

   Yield nodes in a depth first traversal starting at the *start*
   node.

   If *end* is specified traversal stops when reaching that node.

   If forward is True (the default) edges are traversed in forward
   direction, otherwise they are traversed in reverse direction.

.. method:: Graph.iterdata(start[, end[, forward[, condition]]])

   Yield the associated data for nodes in a depth first traversal
   starting at the *start* node. This method will not yield values for nodes
   without associated data.

   If *end* is specified traversal stops when reaching that node.

   If *condition* is specified and the condition callable returns
   False for the associated data this method will not yield the
   associated data and will not follow the edges for the node.

   If forward is True (the default) edges are traversed in forward
   direction, otherwise they are traversed in reverse direction.

.. method:: Graph.forw_bfs(start[, end])

   Returns a list of nodes starting at *start* in some bread first
   search order (following outgoing edges).

   When *end* is specified iteration stops at that node.

.. method:: Graph.back_bfs(start[, end])

   Returns a list of nodes starting at *start* in some bread first
   search order (following incoming edges).

   When *end* is specified iteration stops at that node.

.. method:: Graph.get_hops(start[, end[, forward]])

   Computes the hop distance to all nodes centered around a specified node.

   First order neighbours are at hop 1, their neigbours are at hop 2 etc.
   Uses :py:meth:`forw_bfs` or :py:meth:`back_bfs` depending on the value of
   the forward parameter.

   If the distance between all neighbouring nodes is 1 the hop number
   corresponds to the shortest distance between the nodes.

   Typical usage::

        >>> print graph.get_hops(1, 8)
        >>> [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)]
        # node 1 is at 0 hops
        # node 2 is at 1 hop
        # ...
        # node 8 is at 5 hops


Graph statistics
----------------

.. method:: Graph.connected()

   Returns True iff every node in the graph can be reached from
   every other node.

.. method:: Graph.clust_coef(node)

   Returns the local clustering coefficient of node.

   The local cluster coefficient is the proportion of the actual number
   of edges between neighbours of node and the maximum number of
   edges between those nodes.
