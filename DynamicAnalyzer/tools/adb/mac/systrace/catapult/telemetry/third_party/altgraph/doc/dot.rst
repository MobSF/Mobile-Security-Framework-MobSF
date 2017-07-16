:mod:`altgraph.Dot` --- Interface to the dot language
=====================================================

.. module:: altgraph.Dot
   :synopsis: Interface to the dot language as used by Graphviz..

The :py:mod:`~altgraph.Dot` module provides a simple interface to the
file format used in the `graphviz`_ program. The module is intended to 
offload the most tedious part of the process (the **dot** file generation) 
while transparently exposing most of its features.

.. _`graphviz`: <http://www.research.att.com/sw/tools/graphviz/>`_

To display the graphs or to generate image files the `graphviz`_
package needs to be installed on the system, moreover the :command:`dot` and :command:`dotty` programs must
be accesible in the program path so that they can be ran from processes spawned
within the module. 

Example usage
-------------

Here is a typical usage::

    from altgraph import Graph, Dot

    # create a graph
    edges = [ (1,2), (1,3), (3,4), (3,5), (4,5), (5,4) ]
    graph = Graph.Graph(edges)
    
    # create a dot representation of the graph
    dot = Dot.Dot(graph)

    # display the graph
    dot.display()

    # save the dot representation into the mydot.dot file
    dot.save_dot(file_name='mydot.dot')

    # save dot file as gif image into the graph.gif file
    dot.save_img(file_name='graph', file_type='gif')


Directed graph and non-directed graph
-------------------------------------

Dot class can use for both directed graph and non-directed graph
by passing *graphtype* parameter.

Example::

    # create directed graph(default)
    dot = Dot.Dot(graph, graphtype="digraph")

    # create non-directed graph
    dot = Dot.Dot(graph, graphtype="graph")


Customizing the output
----------------------

The graph drawing process may be customized by passing
valid :command:`dot` parameters for the nodes and edges. For a list of all
parameters see the `graphviz`_ documentation.

Example::

    # customizing the way the overall graph is drawn
    dot.style(size='10,10', rankdir='RL', page='5, 5' , ranksep=0.75)

    # customizing node drawing
    dot.node_style(1, label='BASE_NODE',shape='box', color='blue' )
    dot.node_style(2, style='filled', fillcolor='red')

    # customizing edge drawing
    dot.edge_style(1, 2, style='dotted')
    dot.edge_style(3, 5, arrowhead='dot', label='binds', labelangle='90')
    dot.edge_style(4, 5, arrowsize=2, style='bold')


    .. note:: 
       
       dotty (invoked via :py:func:`~altgraph.Dot.display`) may not be able to
       display all graphics styles. To verify the output save it to an image 
       file and look at it that way.

Valid attributes
----------------

- dot styles, passed via the :py:meth:`Dot.style` method::

    rankdir = 'LR'   (draws the graph horizontally, left to right)
    ranksep = number (rank separation in inches)

- node attributes, passed via the :py:meth:`Dot.node_style` method::

     style = 'filled' | 'invisible' | 'diagonals' | 'rounded'
     shape = 'box' | 'ellipse' | 'circle' | 'point' | 'triangle'

- edge attributes, passed via the :py:meth:`Dot.edge_style` method::

     style     = 'dashed' | 'dotted' | 'solid' | 'invis' | 'bold'
     arrowhead = 'box' | 'crow' | 'diamond' | 'dot' | 'inv' | 'none' | 'tee' | 'vee'
     weight    = number (the larger the number the closer the nodes will be)

- valid `graphviz colors <http://www.research.att.com/~erg/graphviz/info/colors.html>`_

- for more details on how to control the graph drawing process see the 
  `graphviz reference <http://www.research.att.com/sw/tools/graphviz/refs.html>`_.


Class interface
---------------

.. class:: Dot(graph[, nodes[, edgefn[, nodevisitor[, edgevisitor[, name[, dot[, dotty[, neato[, graphtype]]]]]]]]])

  Creates a new Dot generator based on the specified 
  :class:`Graph <altgraph.Graph.Graph>`.  The Dot generator won't reference
  the *graph* once it is constructed.

  If the *nodes* argument is present it is the list of nodes to include
  in the graph, otherwise all nodes in *graph* are included.
  
  If the *edgefn* argument is present it is a function that yields the
  nodes connected to another node, this defaults to 
  :meth:`graph.out_nbr <altgraph.Graph.Graph.out_nbr>`. The constructor won't
  add edges to the dot file unless both the head and tail of the edge
  are in *nodes*.

  If the *name* is present it specifies the name of the graph in the resulting
  dot file. The default is ``"G"``.

  The functions *nodevisitor* and *edgevisitor* return the default style
  for a given edge or node (both default to functions that return an empty
  style).

  The arguments *dot*, *dotty* and *neato* are used to pass the path to 
  the corresponding `graphviz`_ command.


Updating graph attributes
.........................

.. method:: Dot.style(\**attr)

   Sets the overall style (graph attributes) to the given attributes.

   See `Valid Attributes`_ for more information about the attributes.

.. method:: Dot.node_style(node, \**attr)

   Sets the style for *node* to the given attributes.

   This method will add *node* to the graph when it isn't already 
   present.

   See `Valid Attributes`_ for more information about the attributes.

.. method:: Dot.all_node_style(\**attr)

   Replaces the current style for all nodes


.. method:: edge_style(head, tail, \**attr)

   Sets the style of an edge to the given attributes. The edge will
   be added to the graph when it isn't already present, but *head*
   and *tail* must both be valid nodes.

   See `Valid Attributes`_ for more information about the attributes.



Emitting output
...............

.. method:: Dot.display([mode])

   Displays the current graph via dotty.

   If the *mode* is ``"neato"`` the dot file is processed with
   the neato command before displaying.

   This method won't return until the dotty command exits.

.. method:: save_dot(filename)

   Saves the current graph representation into the given file.

   .. note::

       For backward compatibility reasons this method can also
       be called without an argument, it will then write the graph
       into a fixed filename (present in the attribute :data:`Graph.temp_dot`).

       This feature is deprecated and should not be used.


.. method:: save_image(file_name[, file_type[, mode]])

   Saves the current graph representation as an image file. The output
   is written into a file whose basename is *file_name* and whose suffix
   is *file_type*.

   The *file_type* specifies the type of file to write, the default
   is ``"gif"``.

   If the *mode* is ``"neato"`` the dot file is processed with
   the neato command before displaying.

   .. note::

       For backward compatibility reasons this method can also
       be called without an argument, it will then write the graph
       with a fixed basename (``"out"``).

       This feature is deprecated and should not be used.

.. method:: iterdot()

   Yields all lines of a `graphviz`_ input file (including line endings).

.. method:: __iter__()

   Alias for the :meth:`iterdot` method.
