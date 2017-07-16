:mod:`altgraph.GraphStat` --- Functions providing various graph statistics
==========================================================================

.. module:: altgraph.GraphStat
   :synopsis: Functions providing various graph statistics

The module :mod:`altgraph.GraphStat` provides function that calculate
graph statistics. Currently there is only one such function, more may
be added later.

.. function:: degree_dist(graph[, limits[, bin_num[, mode]]])

   Groups the number of edges per node into *bin_num* bins
   and returns the list of those bins. Every item in the result
   is a tuple with the center of the bin and the number of items
   in that bin.

   When the *limits* argument is present it must be a tuple with
   the mininum and maximum number of edges that get binned (that
   is, when *limits* is ``(4, 10)`` only nodes with between 4
   and 10 edges get counted.

   The *mode* argument is used to count incoming (``'inc'``) or
   outgoing (``'out'``) edges. The default is to count the outgoing
   edges.
