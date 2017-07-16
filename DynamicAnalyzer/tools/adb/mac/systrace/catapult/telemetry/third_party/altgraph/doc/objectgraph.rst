:mod:`altgraph.ObjectGraph` --- Graphs of objecs with an identifier
===================================================================

.. module:: altgraph.ObjectGraph
   :synopsis: A graph of objects that have a "graphident" attribute.

.. class:: ObjectGraph([graph[, debug]])

   A graph of objects that have a "graphident" attribute. The
   value of this attribute is the key for the object in the
   graph.

   The optional *graph* is a previously constructed
   :class:`Graph <altgraph.Graph.Graph>`.

   The optional *debug* level controls the amount of debug output
   (see :meth:`msg`, :meth:`msgin` and :meth:`msgout`).

   .. note:: the altgraph library does not generate output, the
      debug attribute and message methods are present for use
      by subclasses.

.. data:: ObjectGraph.graph

   An :class:`Graph <altgraph.Graph.Graph>` object that contains
   the graph data.


.. method:: ObjectGraph.addNode(node)

   Adds a *node* to the graph.

   .. note:: re-adding a node that was previously removed
      using :meth:`removeNode` will reinstate the previously
      removed node.

.. method:: ObjectGraph.createNode(self, cls, name, \*args, \**kwds)

   Creates a new node using ``cls(*args, **kwds)`` and adds that
   node using :meth:`addNode`.

   Returns the newly created node.

.. method:: ObjectGraph.removeNode(node)

   Removes a *node* from the graph when it exists. The *node* argument
   is either a node object, or the graphident of a node.

.. method:: ObjectGraph.createReferences(fromnode, tonode[, edge_data])

   Creates a reference from *fromnode* to *tonode*. The optional
   *edge_data* is associated with the edge.

   *Fromnode* and *tonode* can either be node objects or the graphident
   values for nodes.

.. method:: removeReference(fromnode, tonode)

   Removes the reference from *fromnode* to *tonode* if it exists.

.. method:: ObjectGraph.getRawIdent(node)

   Returns the *graphident* attribute of *node*, or the graph itself
   when *node* is :data:`None`.

.. method:: getIdent(node)

   Same as :meth:`getRawIdent`, but only if the node is part
   of the graph.

   *Node* can either be an actual node object or the graphident of
   a node.

.. method:: ObjectGraph.findNode(node)

   Returns a given node in the graph, or :data:`Node` when it cannot
   be found.

   *Node* is either an object with a *graphident* attribute or
   the *graphident* attribute itself.

.. method:: ObjectGraph.__contains__(node)

   Returns True if *node* is a member of the graph. *Node* is either an
   object with a *graphident* attribute or the *graphident* attribute itself.

.. method:: ObjectGraph.flatten([condition[, start]])

   Yield all nodes that are entirely reachable by *condition*
   starting fromt he given *start* node or the graph root.

   .. note:: objects are only reachable from the graph root
      when there is a reference from the root to the node
      (either directly or through another node)

.. method:: ObjectGraph.nodes()

   Yield all nodes in the graph.

.. method:: ObjectGraph.get_edges(node)

   Returns two iterators that yield the nodes reaching by
   outgoing and incoming edges.

.. method:: ObjectGraph.filterStack(filters)

   Filter the ObjectGraph in-place by removing all edges to nodes that
   do not match every filter in the given filter list

   Returns a tuple containing the number of:
   (*nodes_visited*, *nodes_removed*, *nodes_orphaned*)

.. method:: ObjectGraph.edgeData(fromNode, toNode):
   Return the edge data associated with the edge from *fromNode*
   to *toNode*.  Raises :exc:`KeyError` when no such edge exists.

   .. versionadded: 0.12

.. method:: ObjectGraph.updateEdgeData(fromNode, toNode, edgeData)

   Replace the data associated with the edge from *fromNode* to
   *toNode* by *edgeData*.

   Raises :exc:`KeyError` when the edge does not exist.

Debug output
------------

.. data:: ObjectGraph.debug

   The current debug level.

.. method:: ObjectGraph.msg(level, text, \*args)

   Print a debug message at the current indentation level when the current
   debug level is *level* or less.

.. method:: ObjectGraph.msgin(level, text, \*args)

   Print a debug message when the current debug level is *level* or less,
   and increase the indentation level.

.. method:: ObjectGraph.msgout(level, text, \*args)

   Decrease the indentation level and print a debug message when the
   current debug level is *level* or less.
