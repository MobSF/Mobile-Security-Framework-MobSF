# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

from xml.sax.saxutils import escape

from androguard.core import bytecode
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS
from androguard.core.analysis.risk import PERMISSIONS_RISK, INTERNET_RISK, PRIVACY_RISK, PHONE_RISK, SMS_RISK, MONEY_RISK
from androguard.core.analysis.analysis import PathVar, TAINTED_PACKAGE_CREATE


"""Base class for undirected graphs.

The Graph class allows any hashable object as a node
and can associate key/value attribute pairs with each undirected edge.

Self-loops are allowed but multiple edges are not (see MultiGraph).

For directed graphs see DiGraph and MultiDiGraph.
"""
#    Copyright (C) 2004-2011 by
#    Aric Hagberg <hagberg@lanl.gov>
#    Dan Schult <dschult@colgate.edu>
#    Pieter Swart <swart@lanl.gov>
#    All rights reserved.
#    BSD license.
from copy import deepcopy

__author__ = """\n""".join(['Aric Hagberg (hagberg@lanl.gov)',
                            'Pieter Swart (swart@lanl.gov)',
                            'Dan Schult(dschult@colgate.edu)'])

class Graph(object):
    """
    Base class for undirected graphs.

    A Graph stores nodes and edges with optional data, or attributes.

    Graphs hold undirected edges.  Self loops are allowed but multiple
    (parallel) edges are not.

    Nodes can be arbitrary (hashable) Python objects with optional
    key/value attributes.

    Edges are represented as links between nodes with optional
    key/value attributes.

    Parameters
    ----------
    data : input graph
        Data to initialize graph.  If data=None (default) an empty
        graph is created.  The data can be an edge list, or any
        NetworkX graph object.  If the corresponding optional Python
        packages are installed the data can also be a NumPy matrix
        or 2d ndarray, a SciPy sparse matrix, or a PyGraphviz graph.
    attr : keyword arguments, optional (default= no attributes)
        Attributes to add to graph as key=value pairs.

    See Also
    --------
    DiGraph
    MultiGraph
    MultiDiGraph

    Examples
    --------
    Create an empty graph structure (a "null graph") with no nodes and
    no edges.

    >>> G = nx.Graph()

    G can be grown in several ways.

    **Nodes:**

    Add one node at a time:

    >>> G.add_node(1)

    Add the nodes from any container (a list, dict, set or
    even the lines from a file or the nodes from another graph).

    >>> G.add_nodes_from([2,3])
    >>> G.add_nodes_from(range(100,110))
    >>> H=nx.Graph()
    >>> H.add_path([0,1,2,3,4,5,6,7,8,9])
    >>> G.add_nodes_from(H)

    In addition to strings and integers any hashable Python object
    (except None) can represent a node, e.g. a customized node object,
    or even another Graph.

    >>> G.add_node(H)

    **Edges:**

    G can also be grown by adding edges.

    Add one edge,

    >>> G.add_edge(1, 2)

    a list of edges,

    >>> G.add_edges_from([(1,2),(1,3)])

    or a collection of edges,

    >>> G.add_edges_from(H.edges())

    If some edges connect nodes not yet in the graph, the nodes
    are added automatically.  There are no errors when adding
    nodes or edges that already exist.

    **Attributes:**

    Each graph, node, and edge can hold key/value attribute pairs
    in an associated attribute dictionary (the keys must be hashable).
    By default these are empty, but can be added or changed using
    add_edge, add_node or direct manipulation of the attribute
    dictionaries named graph, node and edge respectively.

    >>> G = nx.Graph(day="Friday")
    >>> G.graph
    {'day': 'Friday'}

    Add node attributes using add_node(), add_nodes_from() or G.node

    >>> G.add_node(1, time='5pm')
    >>> G.add_nodes_from([3], time='2pm')
    >>> G.node[1]
    {'time': '5pm'}
    >>> G.node[1]['room'] = 714
    >>> del G.node[1]['room'] # remove attribute
    >>> G.nodes(data=True)
    [(1, {'time': '5pm'}), (3, {'time': '2pm'})]

    Warning: adding a node to G.node does not add it to the graph.

    Add edge attributes using add_edge(), add_edges_from(), subscript
    notation, or G.edge.

    >>> G.add_edge(1, 2, weight=4.7 )
    >>> G.add_edges_from([(3,4),(4,5)], color='red')
    >>> G.add_edges_from([(1,2,{'color':'blue'}), (2,3,{'weight':8})])
    >>> G[1][2]['weight'] = 4.7
    >>> G.edge[1][2]['weight'] = 4

    **Shortcuts:**

    Many common graph features allow python syntax to speed reporting.

    >>> 1 in G     # check if node in graph
    True
    >>> [n for n in G if n<3]   # iterate through nodes
    [1, 2]
    >>> len(G)  # number of nodes in graph
    5
    >>> G[1] # adjacency dict keyed by neighbor to edge attributes
    ...            # Note: you should not change this dict manually!
    {2: {'color': 'blue', 'weight': 4}}

    The fastest way to traverse all edges of a graph is via
    adjacency_iter(), but the edges() method is often more convenient.

    >>> for n,nbrsdict in G.adjacency_iter():
    ...     for nbr,eattr in nbrsdict.items():
    ...        if 'weight' in eattr:
    ...            (n,nbr,eattr['weight'])
    (1, 2, 4)
    (2, 1, 4)
    (2, 3, 8)
    (3, 2, 8)
    >>> [ (u,v,edata['weight']) for u,v,edata in G.edges(data=True) if 'weight' in edata ]
    [(1, 2, 4), (2, 3, 8)]

    **Reporting:**

    Simple graph information is obtained using methods.
    Iterator versions of many reporting methods exist for efficiency.
    Methods exist for reporting nodes(), edges(), neighbors() and degree()
    as well as the number of nodes and edges.

    For details on these and other miscellaneous methods, see below.
    """
    def __init__(self, data=None, **attr):
        """Initialize a graph with edges, name, graph attributes.

        Parameters
        ----------
        data : input graph
            Data to initialize graph.  If data=None (default) an empty
            graph is created.  The data can be an edge list, or any
            NetworkX graph object.  If the corresponding optional Python
            packages are installed the data can also be a NumPy matrix
            or 2d ndarray, a SciPy sparse matrix, or a PyGraphviz graph.
        name : string, optional (default='')
            An optional name for the graph.
        attr : keyword arguments, optional (default= no attributes)
            Attributes to add to graph as key=value pairs.

        See Also
        --------
        convert

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G = nx.Graph(name='my graph')
        >>> e = [(1,2),(2,3),(3,4)] # list of edges
        >>> G = nx.Graph(e)

        Arbitrary graph attribute pairs (key=value) may be assigned

        >>> G=nx.Graph(e, day="Friday")
        >>> G.graph
        {'day': 'Friday'}

        """
        self.graph = {}   # dictionary for graph attributes
        self.node = {}    # empty node dict (created before convert)
        self.adj = {}     # empty adjacency dict
        # attempt to load graph with data
        if data is not None:
            convert.to_networkx_graph(data,create_using=self)
        # load graph attributes (must be after convert)
        self.graph.update(attr)
        self.edge = self.adj

    @property
    def name(self):
        return self.graph.get('name','')
    @name.setter
    def name(self, s):
        self.graph['name']=s

    def __str__(self):
        """Return the graph name.

        Returns
        -------
        name : string
            The name of the graph.

        Examples
        --------
        >>> G = nx.Graph(name='foo')
        >>> str(G)
        'foo'
        """
        return self.name

    def __iter__(self):
        """Iterate over the nodes. Use the expression 'for n in G'.

        Returns
        -------
        niter : iterator
            An iterator over all nodes in the graph.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        """
        return iter(self.node)

    def __contains__(self,n):
        """Return True if n is a node, False otherwise. Use the expression
        'n in G'.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> 1 in G
        True
        """
        try:
            return n in self.node
        except TypeError:
            return False

    def __len__(self):
        """Return the number of nodes. Use the expression 'len(G)'.

        Returns
        -------
        nnodes : int
            The number of nodes in the graph.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> len(G)
        4

        """
        return len(self.node)

    def __getitem__(self, n):
        """Return a dict of neighbors of node n.  Use the expression 'G[n]'.

        Parameters
        ----------
        n : node
           A node in the graph.

        Returns
        -------
        adj_dict : dictionary
           The adjacency dictionary for nodes connected to n.

        Notes
        -----
        G[n] is similar to G.neighbors(n) but the internal data dictionary
        is returned instead of a list.

        Assigning G[n] will corrupt the internal graph data structure.
        Use G[n] for reading data only.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G[0]
        {1: {}}
        """
        return self.adj[n]


    def add_node(self, n, attr_dict=None, **attr):
        """Add a single node n and update node attributes.

        Parameters
        ----------
        n : node
            A node can be any hashable Python object except None.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of node attributes.  Key/value pairs will
            update existing data associated with the node.
        attr : keyword arguments, optional
            Set or change attributes using key=value.

        See Also
        --------
        add_nodes_from

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_node(1)
        >>> G.add_node('Hello')
        >>> K3 = nx.Graph([(0,1),(1,2),(2,0)])
        >>> G.add_node(K3)
        >>> G.number_of_nodes()
        3

        Use keywords set/change node attributes:

        >>> G.add_node(1,size=10)
        >>> G.add_node(3,weight=0.4,UTM=('13S',382871,3972649))

        Notes
        -----
        A hashable object is one that can be used as a key in a Python
        dictionary. This includes strings, numbers, tuples of strings
        and numbers, etc.

        On many platforms hashable items also include mutables such as
        NetworkX Graphs, though one should be careful that the hash
        doesn't change on mutables.
        """
        # set up attribute dict
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dictionary.")
        if n not in self.node:
            self.adj[n] = {}
            self.node[n] = attr_dict
        else: # update attr even if node already exists
            self.node[n].update(attr_dict)


    def add_nodes_from(self, nodes, **attr):
        """Add multiple nodes.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes (list, dict, set, etc.).
            OR
            A container of (node, attribute dict) tuples.
            Node attributes are updated using the attribute dict.
        attr : keyword arguments, optional (default= no attributes)
            Update attributes for all nodes in nodes.
            Node attributes specified in nodes as a tuple
            take precedence over attributes specified generally.

        See Also
        --------
        add_node

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_nodes_from('Hello')
        >>> K3 = nx.Graph([(0,1),(1,2),(2,0)])
        >>> G.add_nodes_from(K3)
        >>> sorted(G.nodes(),key=str)
        [0, 1, 2, 'H', 'e', 'l', 'o']

        Use keywords to update specific node attributes for every node.

        >>> G.add_nodes_from([1,2], size=10)
        >>> G.add_nodes_from([3,4], weight=0.4)

        Use (node, attrdict) tuples to update attributes for specific
        nodes.

        >>> G.add_nodes_from([(1,dict(size=11)), (2,{'color':'blue'})])
        >>> G.node[1]['size']
        11
        >>> H = nx.Graph()
        >>> H.add_nodes_from(G.nodes(data=True))
        >>> H.node[1]['size']
        11

        """
        for n in nodes:
            try:
                newnode=n not in self.node
            except TypeError:
                nn,ndict = n
                if nn not in self.node:
                    self.adj[nn] = {}
                    newdict = attr.copy()
                    newdict.update(ndict)
                    self.node[nn] = newdict
                else:
                    olddict = self.node[nn]
                    olddict.update(attr)
                    olddict.update(ndict)
                continue
            if newnode:
                self.adj[n] = {}
                self.node[n] = attr.copy()
            else:
                self.node[n].update(attr)

    def remove_node(self,n):
        """Remove node n.

        Removes the node n and all adjacent edges.
        Attempting to remove a non-existent node will raise an exception.

        Parameters
        ----------
        n : node
           A node in the graph

        Raises
        -------
        NetworkXError
           If n is not in the graph.

        See Also
        --------
        remove_nodes_from

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> G.edges()
        [(0, 1), (1, 2)]
        >>> G.remove_node(1)
        >>> G.edges()
        []

        """
        adj = self.adj
        try:
            nbrs = list(adj[n].keys()) # keys handles self-loops (allow mutation later)
            del self.node[n]
        except KeyError: # NetworkXError if n not in self
            raise NetworkXError("The node %s is not in the graph."%(n,))
        for u in nbrs:
            del adj[u][n]   # remove all edges n-u in graph
        del adj[n]          # now remove node


    def remove_nodes_from(self, nodes):
        """Remove multiple nodes.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes (list, dict, set, etc.).  If a node
            in the container is not in the graph it is silently
            ignored.

        See Also
        --------
        remove_node

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> e = G.nodes()
        >>> e
        [0, 1, 2]
        >>> G.remove_nodes_from(e)
        >>> G.nodes()
        []

        """
        adj = self.adj
        for n in nodes:
            try:
                del self.node[n]
                for u in list(adj[n].keys()):   # keys() handles self-loops 
                    del adj[u][n]         #(allows mutation of dict in loop)
                del adj[n]
            except KeyError:
                pass


    def nodes_iter(self, data=False):
        """Return an iterator over the nodes.

        Parameters
        ----------
        data : boolean, optional (default=False)
               If False the iterator returns nodes.  If True
               return a two-tuple of node and node data dictionary

        Returns
        -------
        niter : iterator
            An iterator over nodes.  If data=True the iterator gives
            two-tuples containing (node, node data, dictionary)

        Notes
        -----
        If the node data is not required it is simpler and equivalent
        to use the expression 'for n in G'.

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])

        >>> [d for n,d in G.nodes_iter(data=True)]
        [{}, {}, {}]
        """
        if data:
            return iter(self.node.items())
        return iter(self.node)

    def nodes(self, data=False):
        """Return a list of the nodes in the graph.

        Parameters
        ----------
        data : boolean, optional (default=False)
               If False return a list of nodes.  If True return a
               two-tuple of node and node data dictionary

        Returns
        -------
        nlist : list
            A list of nodes.  If data=True a list of two-tuples containing
            (node, node data dictionary).

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> G.nodes()
        [0, 1, 2]
        >>> G.add_node(1, time='5pm')
        >>> G.nodes(data=True)
        [(0, {}), (1, {'time': '5pm'}), (2, {})]
        """
        return list(self.nodes_iter(data=data))

    def number_of_nodes(self):
        """Return the number of nodes in the graph.

        Returns
        -------
        nnodes : int
            The number of nodes in the graph.

        See Also
        --------
        order, __len__  which are identical

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> len(G)
        3
        """
        return len(self.node)

    def order(self):
        """Return the number of nodes in the graph.

        Returns
        -------
        nnodes : int
            The number of nodes in the graph.

        See Also
        --------
        number_of_nodes, __len__  which are identical

        """
        return len(self.node)

    def has_node(self, n):
        """Return True if the graph contains the node n.

        Parameters
        ----------
        n : node

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> G.has_node(0)
        True

        It is more readable and simpler to use

        >>> 0 in G
        True

        """
        try:
            return n in self.node
        except TypeError:
            return False

    def add_edge(self, u, v, attr_dict=None, **attr):
        """Add an edge between u and v.

        The nodes u and v will be automatically added if they are
        not already in the graph.

        Edge attributes can be specified with keywords or by providing
        a dictionary with key/value pairs.  See examples below.

        Parameters
        ----------
        u,v : nodes
            Nodes can be, for example, strings or numbers.
            Nodes must be hashable (and not None) Python objects.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of edge attributes.  Key/value pairs will
            update existing data associated with the edge.
        attr : keyword arguments, optional
            Edge data (or labels or objects) can be assigned using
            keyword arguments.

        See Also
        --------
        add_edges_from : add a collection of edges

        Notes
        -----
        Adding an edge that already exists updates the edge data.

        Many NetworkX algorithms designed for weighted graphs use as
        the edge weight a numerical value assigned to a keyword
        which by default is 'weight'.

        Examples
        --------
        The following all add the edge e=(1,2) to graph G:

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> e = (1,2)
        >>> G.add_edge(1, 2)           # explicit two-node form
        >>> G.add_edge(*e)             # single edge as tuple of two nodes
        >>> G.add_edges_from( [(1,2)] ) # add edges from iterable container

        Associate data to edges using keywords:

        >>> G.add_edge(1, 2, weight=3)
        >>> G.add_edge(1, 3, weight=7, capacity=15, length=342.7)
        """
        # set up attribute dictionary
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dictionary.")
        # add nodes
        if u not in self.node:
            self.adj[u] = {}
            self.node[u] = {}
        if v not in self.node:
            self.adj[v] = {}
            self.node[v] = {}
        # add the edge
        datadict=self.adj[u].get(v,{})
        datadict.update(attr_dict)
        self.adj[u][v] = datadict
        self.adj[v][u] = datadict


    def add_edges_from(self, ebunch, attr_dict=None, **attr):
        """Add all the edges in ebunch.

        Parameters
        ----------
        ebunch : container of edges
            Each edge given in the container will be added to the
            graph. The edges must be given as as 2-tuples (u,v) or
            3-tuples (u,v,d) where d is a dictionary containing edge
            data.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of edge attributes.  Key/value pairs will
            update existing data associated with each edge.
        attr : keyword arguments, optional
            Edge data (or labels or objects) can be assigned using
            keyword arguments.


        See Also
        --------
        add_edge : add a single edge
        add_weighted_edges_from : convenient way to add weighted edges

        Notes
        -----
        Adding the same edge twice has no effect but any edge data
        will be updated when each duplicate edge is added.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edges_from([(0,1),(1,2)]) # using a list of edge tuples
        >>> e = zip(range(0,3),range(1,4))
        >>> G.add_edges_from(e) # Add the path graph 0-1-2-3

        Associate data to edges

        >>> G.add_edges_from([(1,2),(2,3)], weight=3)
        >>> G.add_edges_from([(3,4),(1,4)], label='WN2898')
        """
        # set up attribute dict
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dictionary.")
        # process ebunch
        for e in ebunch:
            ne=len(e)
            if ne==3:
                u,v,dd = e
            elif ne==2:
                u,v = e
                dd = {}
            else:
                raise NetworkXError(\
                    "Edge tuple %s must be a 2-tuple or 3-tuple."%(e,))
            if u not in self.node:
                self.adj[u] = {}
                self.node[u] = {}
            if v not in self.node:
                self.adj[v] = {}
                self.node[v] = {}
            datadict=self.adj[u].get(v,{})
            datadict.update(attr_dict)
            datadict.update(dd)
            self.adj[u][v] = datadict
            self.adj[v][u] = datadict


    def add_weighted_edges_from(self, ebunch, weight='weight', **attr):
        """Add all the edges in ebunch as weighted edges with specified
        weights.

        Parameters
        ----------
        ebunch : container of edges
            Each edge given in the list or container will be added
            to the graph. The edges must be given as 3-tuples (u,v,w)
            where w is a number.
        weight : string, optional (default= 'weight')
            The attribute name for the edge weights to be added.
        attr : keyword arguments, optional (default= no attributes)
            Edge attributes to add/update for all edges.

        See Also
        --------
        add_edge : add a single edge
        add_edges_from : add multiple edges

        Notes
        -----
        Adding the same edge twice for Graph/DiGraph simply updates 
        the edge data.  For MultiGraph/MultiDiGraph, duplicate edges 
        are stored.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_weighted_edges_from([(0,1,3.0),(1,2,7.5)])
        """
        self.add_edges_from(((u,v,{weight:d}) for u,v,d in ebunch),**attr)

    def remove_edge(self, u, v):
        """Remove the edge between u and v.

        Parameters
        ----------
        u,v: nodes
            Remove the edge between nodes u and v.

        Raises
        ------
        NetworkXError
            If there is not an edge between u and v.

        See Also
        --------
        remove_edges_from : remove a collection of edges

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.remove_edge(0,1)
        >>> e = (1,2)
        >>> G.remove_edge(*e) # unpacks e from an edge tuple
        >>> e = (2,3,{'weight':7}) # an edge with attribute data
        >>> G.remove_edge(*e[:2]) # select first part of edge tuple
        """
        try:
            del self.adj[u][v]
            if u != v:  # self-loop needs only one entry removed
                del self.adj[v][u]
        except KeyError:
            raise NetworkXError("The edge %s-%s is not in the graph"%(u,v))



    def remove_edges_from(self, ebunch):
        """Remove all edges specified in ebunch.

        Parameters
        ----------
        ebunch: list or container of edge tuples
            Each edge given in the list or container will be removed
            from the graph. The edges can be:

                - 2-tuples (u,v) edge between u and v.
                - 3-tuples (u,v,k) where k is ignored.

        See Also
        --------
        remove_edge : remove a single edge

        Notes
        -----
        Will fail silently if an edge in ebunch is not in the graph.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> ebunch=[(1,2),(2,3)]
        >>> G.remove_edges_from(ebunch)
        """
        adj=self.adj
        for e in ebunch:
            u,v = e[:2]  # ignore edge data if present
            if u in adj and v in adj[u]:
                del adj[u][v]
                if u != v:  # self loop needs only one entry removed
                    del adj[v][u]


    def has_edge(self, u, v):
        """Return True if the edge (u,v) is in the graph.

        Parameters
        ----------
        u,v : nodes
            Nodes can be, for example, strings or numbers.
            Nodes must be hashable (and not None) Python objects.

        Returns
        -------
        edge_ind : bool
            True if edge is in the graph, False otherwise.

        Examples
        --------
        Can be called either using two nodes u,v or edge tuple (u,v)

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.has_edge(0,1)  # using two nodes
        True
        >>> e = (0,1)
        >>> G.has_edge(*e)  #  e is a 2-tuple (u,v)
        True
        >>> e = (0,1,{'weight':7})
        >>> G.has_edge(*e[:2])  # e is a 3-tuple (u,v,data_dictionary)
        True

        The following syntax are all equivalent:

        >>> G.has_edge(0,1)
        True
        >>> 1 in G[0]  # though this gives KeyError if 0 not in G
        True

        """
        try:
            return v in self.adj[u]
        except KeyError:
            return False


    def neighbors(self, n):
        """Return a list of the nodes connected to the node n.

        Parameters
        ----------
        n : node
           A node in the graph

        Returns
        -------
        nlist : list
            A list of nodes that are adjacent to n.

        Raises
        ------
        NetworkXError
            If the node n is not in the graph.

        Notes
        -----
        It is usually more convenient (and faster) to access the
        adjacency dictionary as G[n]:

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edge('a','b',weight=7)
        >>> G['a']
        {'b': {'weight': 7}}

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.neighbors(0)
        [1]

        """
        try:
            return list(self.adj[n])
        except KeyError:
            raise NetworkXError("The node %s is not in the graph."%(n,))

    def neighbors_iter(self, n):
        """Return an iterator over all neighbors of node n.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> [n for n in G.neighbors_iter(0)]
        [1]

        Notes
        -----
        It is faster to use the idiom "in G[0]", e.g.

        >>> G = nx.path_graph(4)
        >>> [n for n in G[0]]
        [1]
        """
        try:
            return iter(self.adj[n])
        except KeyError:
            raise NetworkXError("The node %s is not in the graph."%(n,))

    def edges(self, nbunch=None, data=False):
        """Return a list of edges.

        Edges are returned as tuples with optional data
        in the order (node, neighbor, data).

        Parameters
        ----------
        nbunch : iterable container, optional (default= all nodes)
            A container of nodes.  The container will be iterated
            through once.
        data : bool, optional (default=False)
            Return two tuples (u,v) (False) or three-tuples (u,v,data) (True).

        Returns
        --------
        edge_list: list of edge tuples
            Edges that are adjacent to any node in nbunch, or a list
            of all edges if nbunch is not specified.

        See Also
        --------
        edges_iter : return an iterator over the edges

        Notes
        -----
        Nodes in nbunch that are not in the graph will be (quietly) ignored.
        For directed graphs this returns the out-edges.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.edges()
        [(0, 1), (1, 2), (2, 3)]
        >>> G.edges(data=True) # default edge data is {} (empty dictionary)
        [(0, 1, {}), (1, 2, {}), (2, 3, {})]
        >>> G.edges([0,3])
        [(0, 1), (3, 2)]
        >>> G.edges(0)
        [(0, 1)]

        """
        return list(self.edges_iter(nbunch, data))

    def edges_iter(self, nbunch=None, data=False):
        """Return an iterator over the edges.

        Edges are returned as tuples with optional data
        in the order (node, neighbor, data).

        Parameters
        ----------
        nbunch : iterable container, optional (default= all nodes)
            A container of nodes.  The container will be iterated
            through once.
        data : bool, optional (default=False)
            If True, return edge attribute dict in 3-tuple (u,v,data).

        Returns
        -------
        edge_iter : iterator
            An iterator of (u,v) or (u,v,d) tuples of edges.

        See Also
        --------
        edges : return a list of edges

        Notes
        -----
        Nodes in nbunch that are not in the graph will be (quietly) ignored.
        For directed graphs this returns the out-edges.

        Examples
        --------
        >>> G = nx.Graph()   # or MultiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> [e for e in G.edges_iter()]
        [(0, 1), (1, 2), (2, 3)]
        >>> list(G.edges_iter(data=True)) # default data is {} (empty dict)
        [(0, 1, {}), (1, 2, {}), (2, 3, {})]
        >>> list(G.edges_iter([0,3]))
        [(0, 1), (3, 2)]
        >>> list(G.edges_iter(0))
        [(0, 1)]

        """
        seen={}     # helper dict to keep track of multiply stored edges
        if nbunch is None:
            nodes_nbrs = self.adj.items()
        else:
            nodes_nbrs=((n,self.adj[n]) for n in self.nbunch_iter(nbunch))
        if data:
            for n,nbrs in nodes_nbrs:
                for nbr,data in nbrs.items():
                    if nbr not in seen:
                        yield (n,nbr,data)
                seen[n]=1
        else:
            for n,nbrs in nodes_nbrs:
                for nbr in nbrs:
                    if nbr not in seen:
                        yield (n,nbr)
                seen[n] = 1
        del seen


    def get_edge_data(self, u, v, default=None):
        """Return the attribute dictionary associated with edge (u,v).

        Parameters
        ----------
        u,v : nodes
        default:  any Python object (default=None)
            Value to return if the edge (u,v) is not found.

        Returns
        -------
        edge_dict : dictionary
            The edge attribute dictionary.

        Notes
        -----
        It is faster to use G[u][v].

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G[0][1]
        {}

        Warning: Assigning G[u][v] corrupts the graph data structure.
        But it is safe to assign attributes to that dictionary,

        >>> G[0][1]['weight'] = 7
        >>> G[0][1]['weight']
        7
        >>> G[1][0]['weight']
        7

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.get_edge_data(0,1) # default edge data is {}
        {}
        >>> e = (0,1)
        >>> G.get_edge_data(*e) # tuple form
        {}
        >>> G.get_edge_data('a','b',default=0) # edge not in graph, return 0
        0
        """
        try:
            return self.adj[u][v]
        except KeyError:
            return default

    def adjacency_list(self):
        """Return an adjacency list representation of the graph.

        The output adjacency list is in the order of G.nodes().
        For directed graphs, only outgoing adjacencies are included.

        Returns
        -------
        adj_list : lists of lists
            The adjacency structure of the graph as a list of lists.

        See Also
        --------
        adjacency_iter

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.adjacency_list() # in order given by G.nodes()
        [[1], [0, 2], [1, 3], [2]]

        """
        return list(map(list,iter(self.adj.values())))

    def adjacency_iter(self):
        """Return an iterator of (node, adjacency dict) tuples for all nodes.

        This is the fastest way to look at every edge.
        For directed graphs, only outgoing adjacencies are included.

        Returns
        -------
        adj_iter : iterator
           An iterator of (node, adjacency dictionary) for all nodes in
           the graph.

        See Also
        --------
        adjacency_list

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> [(n,nbrdict) for n,nbrdict in G.adjacency_iter()]
        [(0, {1: {}}), (1, {0: {}, 2: {}}), (2, {1: {}, 3: {}}), (3, {2: {}})]

        """
        return iter(self.adj.items())

    def degree(self, nbunch=None, weight=None):
        """Return the degree of a node or nodes.

        The node degree is the number of edges adjacent to that node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd : dictionary, or number
            A dictionary with nodes as keys and degree as values or
            a number if a single node is specified.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.degree(0)
        1
        >>> G.degree([0,1])
        {0: 1, 1: 2}
        >>> list(G.degree([0,1]).values())
        [1, 2]

        """
        if nbunch in self:      # return a single node
            return next(self.degree_iter(nbunch,weight))[1]
        else:           # return a dict
            return dict(self.degree_iter(nbunch,weight))

    def degree_iter(self, nbunch=None, weight=None):
        """Return an iterator for (node, degree).

        The node degree is the number of edges adjacent to the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd_iter : an iterator
            The iterator returns two-tuples of (node, degree).

        See Also
        --------
        degree

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> list(G.degree_iter(0)) # node 0 with degree 1
        [(0, 1)]
        >>> list(G.degree_iter([0,1]))
        [(0, 1), (1, 2)]

        """
        if nbunch is None:
            nodes_nbrs = self.adj.items()
        else:
            nodes_nbrs=((n,self.adj[n]) for n in self.nbunch_iter(nbunch))
  
        if weight is None:
            for n,nbrs in nodes_nbrs:
                yield (n,len(nbrs)+(n in nbrs)) # return tuple (n,degree)
        else:
        # edge weighted graph - degree is sum of nbr edge weights
            for n,nbrs in nodes_nbrs:
                yield (n, sum((nbrs[nbr].get(weight,1) for nbr in nbrs)) +
                              (n in nbrs and nbrs[n].get(weight,1)))


    def clear(self):
        """Remove all nodes and edges from the graph.

        This also removes the name, and all graph, node, and edge attributes.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.clear()
        >>> G.nodes()
        []
        >>> G.edges()
        []

        """
        self.name = ''
        self.adj.clear()
        self.node.clear()
        self.graph.clear()

    def copy(self):
        """Return a copy of the graph.

        Returns
        -------
        G : Graph
            A copy of the graph.

        See Also
        --------
        to_directed: return a directed copy of the graph.

        Notes
        -----
        This makes a complete copy of the graph including all of the
        node or edge attributes.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> H = G.copy()

        """
        return deepcopy(self)

    def is_multigraph(self):
        """Return True if graph is a multigraph, False otherwise."""
        return False


    def is_directed(self):
        """Return True if graph is directed, False otherwise."""
        return False

    def to_directed(self):
        """Return a directed representation of the graph.

        Returns
        -------
        G : DiGraph
            A directed graph with the same name, same nodes, and with
            each edge (u,v,data) replaced by two directed edges
            (u,v,data) and (v,u,data).

        Notes
        -----
        This returns a "deepcopy" of the edge, node, and
        graph attributes which attempts to completely copy
        all of the data and references.

        This is in contrast to the similar D=DiGraph(G) which returns a
        shallow copy of the data.

        See the Python copy module for more information on shallow
        and deep copies, http://docs.python.org/library/copy.html.

        Examples
        --------
        >>> G = nx.Graph()   # or MultiGraph, etc
        >>> G.add_path([0,1])
        >>> H = G.to_directed()
        >>> H.edges()
        [(0, 1), (1, 0)]

        If already directed, return a (deep) copy

        >>> G = nx.DiGraph()   # or MultiDiGraph, etc
        >>> G.add_path([0,1])
        >>> H = G.to_directed()
        >>> H.edges()
        [(0, 1)]
        """
        from networkx import DiGraph
        G=DiGraph()
        G.name=self.name
        G.add_nodes_from(self)
        G.add_edges_from( ((u,v,deepcopy(data)) 
                           for u,nbrs in self.adjacency_iter() 
                           for v,data in nbrs.items()) )
        G.graph=deepcopy(self.graph)
        G.node=deepcopy(self.node)
        return G

    def to_undirected(self):
        """Return an undirected copy of the graph.

        Returns
        -------
        G : Graph/MultiGraph
            A deepcopy of the graph.

        See Also
        --------
        copy, add_edge, add_edges_from

        Notes
        -----
        This returns a "deepcopy" of the edge, node, and
        graph attributes which attempts to completely copy
        all of the data and references.

        This is in contrast to the similar G=DiGraph(D) which returns a
        shallow copy of the data.

        See the Python copy module for more information on shallow
        and deep copies, http://docs.python.org/library/copy.html.

        Examples
        --------
        >>> G = nx.Graph()   # or MultiGraph, etc
        >>> G.add_path([0,1])
        >>> H = G.to_directed()
        >>> H.edges()
        [(0, 1), (1, 0)]
        >>> G2 = H.to_undirected()
        >>> G2.edges()
        [(0, 1)]
        """
        return deepcopy(self)

    def subgraph(self, nbunch):
        """Return the subgraph induced on nodes in nbunch.

        The induced subgraph of the graph contains the nodes in nbunch
        and the edges between those nodes.

        Parameters
        ----------
        nbunch : list, iterable
            A container of nodes which will be iterated through once.

        Returns
        -------
        G : Graph
            A subgraph of the graph with the same edge attributes.

        Notes
        -----
        The graph, edge or node attributes just point to the original graph.
        So changes to the node or edge structure will not be reflected in
        the original graph while changes to the attributes will.

        To create a subgraph with its own copy of the edge/node attributes use:
        nx.Graph(G.subgraph(nbunch))

        If edge attributes are containers, a deep copy can be obtained using:
        G.subgraph(nbunch).copy()

        For an inplace reduction of a graph to a subgraph you can remove nodes:
        G.remove_nodes_from([ n in G if n not in set(nbunch)])

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> H = G.subgraph([0,1,2])
        >>> H.edges()
        [(0, 1), (1, 2)]
        """
        bunch =self.nbunch_iter(nbunch)
        # create new graph and copy subgraph into it
        H = self.__class__()
        # copy node and attribute dictionaries
        for n in bunch:
            H.node[n]=self.node[n]
        # namespace shortcuts for speed
        H_adj=H.adj
        self_adj=self.adj
        # add nodes and edges (undirected method)
        for n in H.node:
            Hnbrs={}
            H_adj[n]=Hnbrs
            for nbr,d in self_adj[n].items():
                if nbr in H_adj:
                    # add both representations of edge: n-nbr and nbr-n
                    Hnbrs[nbr]=d
                    H_adj[nbr][n]=d
        H.graph=self.graph
        return H


    def nodes_with_selfloops(self):
        """Return a list of nodes with self loops.

        A node with a self loop has an edge with both ends adjacent
        to that node.

        Returns
        -------
        nodelist : list
            A list of nodes with self loops.

        See Also
        --------
        selfloop_edges, number_of_selfloops

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edge(1,1)
        >>> G.add_edge(1,2)
        >>> G.nodes_with_selfloops()
        [1]
        """
        return [ n for n,nbrs in self.adj.items() if n in nbrs ]

    def selfloop_edges(self, data=False):
        """Return a list of selfloop edges.

        A selfloop edge has the same node at both ends.

        Parameters
        -----------
        data : bool, optional (default=False)
            Return selfloop edges as two tuples (u,v) (data=False)
            or three-tuples (u,v,data) (data=True)

        Returns
        -------
        edgelist : list of edge tuples
            A list of all selfloop edges.

        See Also
        --------
        nodes_with_selfloops, number_of_selfloops

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edge(1,1)
        >>> G.add_edge(1,2)
        >>> G.selfloop_edges()
        [(1, 1)]
        >>> G.selfloop_edges(data=True)
        [(1, 1, {})]
        """
        if data:
            return [ (n,n,nbrs[n])
                     for n,nbrs in self.adj.items() if n in nbrs ]
        else:
            return [ (n,n)
                     for n,nbrs in self.adj.items() if n in nbrs ]


    def number_of_selfloops(self):
        """Return the number of selfloop edges.

        A selfloop edge has the same node at both ends.

        Returns
        -------
        nloops : int
            The number of selfloops.

        See Also
        --------
        nodes_with_selfloops, selfloop_edges

        Examples
        --------
        >>> G=nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edge(1,1)
        >>> G.add_edge(1,2)
        >>> G.number_of_selfloops()
        1
        """
        return len(self.selfloop_edges())


    def size(self, weight=None):
        """Return the number of edges.

        Parameters
        ----------
        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.

        Returns
        -------
        nedges : int
            The number of edges of sum of edge weights in the graph.

        See Also
        --------
        number_of_edges

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.size()
        3

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edge('a','b',weight=2)
        >>> G.add_edge('b','c',weight=4)
        >>> G.size()
        2
        >>> G.size(weight='weight')
        6.0
        """
        s=sum(self.degree(weight=weight).values())/2
        if weight is None:
            return int(s)
        else:
            return float(s)

    def number_of_edges(self, u=None, v=None):
        """Return the number of edges between two nodes.

        Parameters
        ----------
        u,v : nodes, optional (default=all edges)
            If u and v are specified, return the number of edges between
            u and v. Otherwise return the total number of all edges.

        Returns
        -------
        nedges : int
            The number of edges in the graph.  If nodes u and v are specified
            return the number of edges between those nodes.

        See Also
        --------
        size

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.number_of_edges()
        3
        >>> G.number_of_edges(0,1)
        1
        >>> e = (0,1)
        >>> G.number_of_edges(*e)
        1
        """
        if u is None: return int(self.size())
        if v in self.adj[u]:
            return 1
        else:
            return 0


    def add_star(self, nodes, **attr):
        """Add a star.

        The first node in nodes is the middle of the star.  It is connected
        to all other nodes.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes.
        attr : keyword arguments, optional (default= no attributes)
            Attributes to add to every edge in star.

        See Also
        --------
        add_path, add_cycle

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_star([0,1,2,3])
        >>> G.add_star([10,11,12],weight=2)

        """
        nlist = list(nodes)
        v=nlist[0]
        edges=((v,n) for n in nlist[1:])
        self.add_edges_from(edges, **attr)

    def add_path(self, nodes, **attr):
        """Add a path.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes.  A path will be constructed from
            the nodes (in order) and added to the graph.
        attr : keyword arguments, optional (default= no attributes)
            Attributes to add to every edge in path.

        See Also
        --------
        add_star, add_cycle

        Examples
        --------
        >>> G=nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.add_path([10,11,12],weight=7)

        """
        nlist = list(nodes)
        edges=zip(nlist[:-1],nlist[1:])
        self.add_edges_from(edges, **attr)

    def add_cycle(self, nodes, **attr):
        """Add a cycle.

        Parameters
        ----------
        nodes: iterable container
            A container of nodes.  A cycle will be constructed from
            the nodes (in order) and added to the graph.
        attr : keyword arguments, optional (default= no attributes)
            Attributes to add to every edge in cycle.

        See Also
        --------
        add_path, add_star

        Examples
        --------
        >>> G=nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_cycle([0,1,2,3])
        >>> G.add_cycle([10,11,12],weight=7)

        """
        nlist = list(nodes)
        edges=zip(nlist,nlist[1:]+[nlist[0]])
        self.add_edges_from(edges, **attr)


    def nbunch_iter(self, nbunch=None):
        """Return an iterator of nodes contained in nbunch that are
        also in the graph.

        The nodes in nbunch are checked for membership in the graph
        and if not are silently ignored.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        Returns
        -------
        niter : iterator
            An iterator over nodes in nbunch that are also in the graph.
            If nbunch is None, iterate over all nodes in the graph.

        Raises
        ------
        NetworkXError
            If nbunch is not a node or or sequence of nodes.
            If a node in nbunch is not hashable.

        See Also
        --------
        Graph.__iter__

        Notes
        -----
        When nbunch is an iterator, the returned iterator yields values
        directly from nbunch, becoming exhausted when nbunch is exhausted.

        To test whether nbunch is a single node, one can use
        "if nbunch in self:", even after processing with this routine.

        If nbunch is not a node or a (possibly empty) sequence/iterator
        or None, a NetworkXError is raised.  Also, if any object in
        nbunch is not hashable, a NetworkXError is raised.
        """
        if nbunch is None:   # include all nodes via iterator
            bunch=iter(self.adj.keys())
        elif nbunch in self: # if nbunch is a single node
            bunch=iter([nbunch])
        else:                # if nbunch is a sequence of nodes
            def bunch_iter(nlist,adj):
                try:
                    for n in nlist:
                        if n in adj:
                            yield n
                except TypeError as e:
                    message=e.args[0]
                    import sys
                    sys.stdout.write(message)
                    # capture error for non-sequence/iterator nbunch.
                    if 'iter' in message:
                        raise NetworkXError(\
                            "nbunch is not a node or a sequence of nodes.")
                    # capture error for unhashable node.
                    elif 'hashable' in message:
                        raise NetworkXError(\
                            "Node %s in the sequence nbunch is not a valid node."%n)
                    else: 
                        raise 
            bunch=bunch_iter(nbunch,self.adj)
        return bunch

"""Base class for directed graphs."""
#    Copyright (C) 2004-2011 by
#    Aric Hagberg <hagberg@lanl.gov>
#    Dan Schult <dschult@colgate.edu>
#    Pieter Swart <swart@lanl.gov>
#    All rights reserved.
#    BSD license.
from copy import deepcopy


class DiGraph(Graph):
    """
    Base class for directed graphs.

    A DiGraph stores nodes and edges with optional data, or attributes.

    DiGraphs hold directed edges.  Self loops are allowed but multiple
    (parallel) edges are not.

    Nodes can be arbitrary (hashable) Python objects with optional
    key/value attributes.

    Edges are represented as links between nodes with optional
    key/value attributes.

    Parameters
    ----------
    data : input graph
        Data to initialize graph.  If data=None (default) an empty
        graph is created.  The data can be an edge list, or any
        NetworkX graph object.  If the corresponding optional Python
        packages are installed the data can also be a NumPy matrix
        or 2d ndarray, a SciPy sparse matrix, or a PyGraphviz graph.
    attr : keyword arguments, optional (default= no attributes)
        Attributes to add to graph as key=value pairs.

    See Also
    --------
    Graph
    MultiGraph
    MultiDiGraph

    Examples
    --------
    Create an empty graph structure (a "null graph") with no nodes and
    no edges.

    >>> G = nx.DiGraph()

    G can be grown in several ways.

    **Nodes:**

    Add one node at a time:

    >>> G.add_node(1)

    Add the nodes from any container (a list, dict, set or
    even the lines from a file or the nodes from another graph).

    >>> G.add_nodes_from([2,3])
    >>> G.add_nodes_from(range(100,110))
    >>> H=nx.Graph()
    >>> H.add_path([0,1,2,3,4,5,6,7,8,9])
    >>> G.add_nodes_from(H)

    In addition to strings and integers any hashable Python object
    (except None) can represent a node, e.g. a customized node object,
    or even another Graph.

    >>> G.add_node(H)

    **Edges:**

    G can also be grown by adding edges.

    Add one edge,

    >>> G.add_edge(1, 2)

    a list of edges,

    >>> G.add_edges_from([(1,2),(1,3)])

    or a collection of edges,

    >>> G.add_edges_from(H.edges())

    If some edges connect nodes not yet in the graph, the nodes
    are added automatically.  There are no errors when adding
    nodes or edges that already exist.

    **Attributes:**

    Each graph, node, and edge can hold key/value attribute pairs
    in an associated attribute dictionary (the keys must be hashable).
    By default these are empty, but can be added or changed using
    add_edge, add_node or direct manipulation of the attribute
    dictionaries named graph, node and edge respectively.

    >>> G = nx.DiGraph(day="Friday")
    >>> G.graph
    {'day': 'Friday'}

    Add node attributes using add_node(), add_nodes_from() or G.node

    >>> G.add_node(1, time='5pm')
    >>> G.add_nodes_from([3], time='2pm')
    >>> G.node[1]
    {'time': '5pm'}
    >>> G.node[1]['room'] = 714
    >>> del G.node[1]['room'] # remove attribute
    >>> G.nodes(data=True)
    [(1, {'time': '5pm'}), (3, {'time': '2pm'})]

    Warning: adding a node to G.node does not add it to the graph.

    Add edge attributes using add_edge(), add_edges_from(), subscript
    notation, or G.edge.

    >>> G.add_edge(1, 2, weight=4.7 )
    >>> G.add_edges_from([(3,4),(4,5)], color='red')
    >>> G.add_edges_from([(1,2,{'color':'blue'}), (2,3,{'weight':8})])
    >>> G[1][2]['weight'] = 4.7
    >>> G.edge[1][2]['weight'] = 4

    **Shortcuts:**

    Many common graph features allow python syntax to speed reporting.

    >>> 1 in G     # check if node in graph
    True
    >>> [n for n in G if n<3]   # iterate through nodes
    [1, 2]
    >>> len(G)  # number of nodes in graph
    5
    >>> G[1] # adjacency dict keyed by neighbor to edge attributes
    ...            # Note: you should not change this dict manually!
    {2: {'color': 'blue', 'weight': 4}}

    The fastest way to traverse all edges of a graph is via
    adjacency_iter(), but the edges() method is often more convenient.

    >>> for n,nbrsdict in G.adjacency_iter():
    ...     for nbr,eattr in nbrsdict.items():
    ...        if 'weight' in eattr:
    ...            (n,nbr,eattr['weight'])
    (1, 2, 4)
    (2, 3, 8)
    >>> [ (u,v,edata['weight']) for u,v,edata in G.edges(data=True) if 'weight' in edata ]
    [(1, 2, 4), (2, 3, 8)]

    **Reporting:**

    Simple graph information is obtained using methods.
    Iterator versions of many reporting methods exist for efficiency.
    Methods exist for reporting nodes(), edges(), neighbors() and degree()
    as well as the number of nodes and edges.

    For details on these and other miscellaneous methods, see below.
    """
    def __init__(self, data=None, **attr):
        """Initialize a graph with edges, name, graph attributes.

        Parameters
        ----------
        data : input graph
            Data to initialize graph.  If data=None (default) an empty
            graph is created.  The data can be an edge list, or any
            NetworkX graph object.  If the corresponding optional Python
            packages are installed the data can also be a NumPy matrix
            or 2d ndarray, a SciPy sparse matrix, or a PyGraphviz graph.
        name : string, optional (default='')
            An optional name for the graph.
        attr : keyword arguments, optional (default= no attributes)
            Attributes to add to graph as key=value pairs.

        See Also
        --------
        convert

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G = nx.Graph(name='my graph')
        >>> e = [(1,2),(2,3),(3,4)] # list of edges
        >>> G = nx.Graph(e)

        Arbitrary graph attribute pairs (key=value) may be assigned

        >>> G=nx.Graph(e, day="Friday")
        >>> G.graph
        {'day': 'Friday'}

        """
        self.graph = {} # dictionary for graph attributes
        self.node = {} # dictionary for node attributes
        # We store two adjacency lists:
        # the  predecessors of node n are stored in the dict self.pred
        # the successors of node n are stored in the dict self.succ=self.adj
        self.adj = {}  # empty adjacency dictionary
        self.pred = {}  # predecessor
        self.succ = self.adj  # successor

        # attempt to load graph with data
        if data is not None:
            convert.to_networkx_graph(data,create_using=self)
        # load graph attributes (must be after convert)
        self.graph.update(attr)
        self.edge=self.adj


    def add_node(self, n, attr_dict=None, **attr):
        """Add a single node n and update node attributes.

        Parameters
        ----------
        n : node
            A node can be any hashable Python object except None.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of node attributes.  Key/value pairs will
            update existing data associated with the node.
        attr : keyword arguments, optional
            Set or change attributes using key=value.

        See Also
        --------
        add_nodes_from

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_node(1)
        >>> G.add_node('Hello')
        >>> K3 = nx.Graph([(0,1),(1,2),(2,0)])
        >>> G.add_node(K3)
        >>> G.number_of_nodes()
        3

        Use keywords set/change node attributes:

        >>> G.add_node(1,size=10)
        >>> G.add_node(3,weight=0.4,UTM=('13S',382871,3972649))

        Notes
        -----
        A hashable object is one that can be used as a key in a Python
        dictionary. This includes strings, numbers, tuples of strings
        and numbers, etc.

        On many platforms hashable items also include mutables such as
        NetworkX Graphs, though one should be careful that the hash
        doesn't change on mutables.
        """
        # set up attribute dict
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dictionary.")
        if n not in self.succ:
            self.succ[n] = {}
            self.pred[n] = {}
            self.node[n] = attr_dict
        else: # update attr even if node already exists
            self.node[n].update(attr_dict)


    def add_nodes_from(self, nodes, **attr):
        """Add multiple nodes.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes (list, dict, set, etc.).
            OR
            A container of (node, attribute dict) tuples.
            Node attributes are updated using the attribute dict.
        attr : keyword arguments, optional (default= no attributes)
            Update attributes for all nodes in nodes.
            Node attributes specified in nodes as a tuple
            take precedence over attributes specified generally.

        See Also
        --------
        add_node

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_nodes_from('Hello')
        >>> K3 = nx.Graph([(0,1),(1,2),(2,0)])
        >>> G.add_nodes_from(K3)
        >>> sorted(G.nodes(),key=str)
        [0, 1, 2, 'H', 'e', 'l', 'o']

        Use keywords to update specific node attributes for every node.

        >>> G.add_nodes_from([1,2], size=10)
        >>> G.add_nodes_from([3,4], weight=0.4)

        Use (node, attrdict) tuples to update attributes for specific
        nodes.

        >>> G.add_nodes_from([(1,dict(size=11)), (2,{'color':'blue'})])
        >>> G.node[1]['size']
        11
        >>> H = nx.Graph()
        >>> H.add_nodes_from(G.nodes(data=True))
        >>> H.node[1]['size']
        11

        """
        for n in nodes:
            try:
                newnode=n not in self.succ
            except TypeError:
                nn,ndict = n
                if nn not in self.succ:
                    self.succ[nn] = {}
                    self.pred[nn] = {}
                    newdict = attr.copy()
                    newdict.update(ndict)
                    self.node[nn] = newdict
                else:
                    olddict = self.node[nn]
                    olddict.update(attr)
                    olddict.update(ndict)
                continue
            if newnode:
                self.succ[n] = {}
                self.pred[n] = {}
                self.node[n] = attr.copy()
            else:
                self.node[n].update(attr)

    def remove_node(self, n):
        """Remove node n.

        Removes the node n and all adjacent edges.
        Attempting to remove a non-existent node will raise an exception.

        Parameters
        ----------
        n : node
           A node in the graph

        Raises
        -------
        NetworkXError
           If n is not in the graph.

        See Also
        --------
        remove_nodes_from

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> G.edges()
        [(0, 1), (1, 2)]
        >>> G.remove_node(1)
        >>> G.edges()
        []

        """
        try:
            nbrs=self.succ[n]
            del self.node[n]
        except KeyError: # NetworkXError if n not in self
            raise NetworkXError("The node %s is not in the digraph."%(n,))
        for u in nbrs:
            del self.pred[u][n] # remove all edges n-u in digraph
        del self.succ[n]          # remove node from succ
        for u in self.pred[n]:
            del self.succ[u][n] # remove all edges n-u in digraph
        del self.pred[n]          # remove node from pred


    def remove_nodes_from(self, nbunch):
        """Remove multiple nodes.

        Parameters
        ----------
        nodes : iterable container
            A container of nodes (list, dict, set, etc.).  If a node
            in the container is not in the graph it is silently
            ignored.

        See Also
        --------
        remove_node

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2])
        >>> e = G.nodes()
        >>> e
        [0, 1, 2]
        >>> G.remove_nodes_from(e)
        >>> G.nodes()
        []

        """
        for n in nbunch:
            try:
                succs=self.succ[n]
                del self.node[n]
                for u in succs:
                    del self.pred[u][n] # remove all edges n-u in digraph
                del self.succ[n]          # now remove node
                for u in self.pred[n]:
                    del self.succ[u][n] # remove all edges n-u in digraph
                del self.pred[n]          # now remove node
            except KeyError:
                pass # silent failure on remove


    def add_edge(self, u, v, attr_dict=None, **attr):
        """Add an edge between u and v.

        The nodes u and v will be automatically added if they are
        not already in the graph.

        Edge attributes can be specified with keywords or by providing
        a dictionary with key/value pairs.  See examples below.

        Parameters
        ----------
        u,v : nodes
            Nodes can be, for example, strings or numbers.
            Nodes must be hashable (and not None) Python objects.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of edge attributes.  Key/value pairs will
            update existing data associated with the edge.
        attr : keyword arguments, optional
            Edge data (or labels or objects) can be assigned using
            keyword arguments.

        See Also
        --------
        add_edges_from : add a collection of edges

        Notes
        -----
        Adding an edge that already exists updates the edge data.

        Many NetworkX algorithms designed for weighted graphs use as
        the edge weight a numerical value assigned to a keyword
        which by default is 'weight'.

        Examples
        --------
        The following all add the edge e=(1,2) to graph G:

        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> e = (1,2)
        >>> G.add_edge(1, 2)           # explicit two-node form
        >>> G.add_edge(*e)             # single edge as tuple of two nodes
        >>> G.add_edges_from( [(1,2)] ) # add edges from iterable container

        Associate data to edges using keywords:

        >>> G.add_edge(1, 2, weight=3)
        >>> G.add_edge(1, 3, weight=7, capacity=15, length=342.7)
        """
        # set up attribute dict
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dictionary.")
        # add nodes
        if u not in self.succ:
            self.succ[u]={}
            self.pred[u]={}
            self.node[u] = {}
        if v not in self.succ:
            self.succ[v]={}
            self.pred[v]={}
            self.node[v] = {}
        # add the edge
        datadict=self.adj[u].get(v,{})
        datadict.update(attr_dict)
        self.succ[u][v]=datadict
        self.pred[v][u]=datadict

    def add_edges_from(self, ebunch, attr_dict=None, **attr):
        """Add all the edges in ebunch.

        Parameters
        ----------
        ebunch : container of edges
            Each edge given in the container will be added to the
            graph. The edges must be given as as 2-tuples (u,v) or
            3-tuples (u,v,d) where d is a dictionary containing edge
            data.
        attr_dict : dictionary, optional (default= no attributes)
            Dictionary of edge attributes.  Key/value pairs will
            update existing data associated with each edge.
        attr : keyword arguments, optional
            Edge data (or labels or objects) can be assigned using
            keyword arguments.


        See Also
        --------
        add_edge : add a single edge
        add_weighted_edges_from : convenient way to add weighted edges

        Notes
        -----
        Adding the same edge twice has no effect but any edge data
        will be updated when each duplicate edge is added.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_edges_from([(0,1),(1,2)]) # using a list of edge tuples
        >>> e = zip(range(0,3),range(1,4))
        >>> G.add_edges_from(e) # Add the path graph 0-1-2-3

        Associate data to edges

        >>> G.add_edges_from([(1,2),(2,3)], weight=3)
        >>> G.add_edges_from([(3,4),(1,4)], label='WN2898')
        """
        # set up attribute dict
        if attr_dict is None:
            attr_dict=attr
        else:
            try:
                attr_dict.update(attr)
            except AttributeError:
                raise NetworkXError(\
                    "The attr_dict argument must be a dict.")
        # process ebunch
        for e in ebunch:
            ne = len(e)
            if ne==3:
                u,v,dd = e
                assert hasattr(dd,"update")
            elif ne==2:
                u,v = e
                dd = {}
            else:
                raise NetworkXError(\
                    "Edge tuple %s must be a 2-tuple or 3-tuple."%(e,))
            if u not in self.succ:
                self.succ[u] = {}
                self.pred[u] = {}
                self.node[u] = {}
            if v not in self.succ:
                self.succ[v] = {}
                self.pred[v] = {}
                self.node[v] = {}
            datadict=self.adj[u].get(v,{})
            datadict.update(attr_dict)
            datadict.update(dd)
            self.succ[u][v] = datadict
            self.pred[v][u] = datadict


    def remove_edge(self, u, v):
        """Remove the edge between u and v.

        Parameters
        ----------
        u,v: nodes
            Remove the edge between nodes u and v.

        Raises
        ------
        NetworkXError
            If there is not an edge between u and v.

        See Also
        --------
        remove_edges_from : remove a collection of edges

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.remove_edge(0,1)
        >>> e = (1,2)
        >>> G.remove_edge(*e) # unpacks e from an edge tuple
        >>> e = (2,3,{'weight':7}) # an edge with attribute data
        >>> G.remove_edge(*e[:2]) # select first part of edge tuple
        """
        try:
            del self.succ[u][v]
            del self.pred[v][u]
        except KeyError:
            raise NetworkXError("The edge %s-%s not in graph."%(u,v))


    def remove_edges_from(self, ebunch):
        """Remove all edges specified in ebunch.

        Parameters
        ----------
        ebunch: list or container of edge tuples
            Each edge given in the list or container will be removed
            from the graph. The edges can be:

                - 2-tuples (u,v) edge between u and v.
                - 3-tuples (u,v,k) where k is ignored.

        See Also
        --------
        remove_edge : remove a single edge

        Notes
        -----
        Will fail silently if an edge in ebunch is not in the graph.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> ebunch=[(1,2),(2,3)]
        >>> G.remove_edges_from(ebunch)
        """
        for e in ebunch:
            (u,v)=e[:2]  # ignore edge data
            if u in self.succ and v in self.succ[u]:
                del self.succ[u][v]
                del self.pred[v][u]


    def has_successor(self, u, v):
        """Return True if node u has successor v.

        This is true if graph has the edge u->v.
        """
        return (u in self.succ and v in self.succ[u])

    def has_predecessor(self, u, v):
        """Return True if node u has predecessor v.

        This is true if graph has the edge u<-v.
        """
        return (u in self.pred and v in self.pred[u])

    def successors_iter(self,n):
        """Return an iterator over successor nodes of n.

        neighbors_iter() and successors_iter() are the same.
        """
        try:
            return iter(self.succ[n])
        except KeyError:
            raise NetworkXError("The node %s is not in the digraph."%(n,))

    def predecessors_iter(self,n):
        """Return an iterator over predecessor nodes of n."""
        try:
            return iter(self.pred[n])
        except KeyError:
            raise NetworkXError("The node %s is not in the digraph."%(n,))

    def successors(self, n):
        """Return a list of successor nodes of n.

        neighbors() and successors() are the same function.
        """
        return list(self.successors_iter(n))

    def predecessors(self, n):
        """Return a list of predecessor nodes of n."""
        return list(self.predecessors_iter(n))


    # digraph definitions
    neighbors = successors
    neighbors_iter = successors_iter

    def edges_iter(self, nbunch=None, data=False):
        """Return an iterator over the edges.

        Edges are returned as tuples with optional data
        in the order (node, neighbor, data).

        Parameters
        ----------
        nbunch : iterable container, optional (default= all nodes)
            A container of nodes.  The container will be iterated
            through once.
        data : bool, optional (default=False)
            If True, return edge attribute dict in 3-tuple (u,v,data).

        Returns
        -------
        edge_iter : iterator
            An iterator of (u,v) or (u,v,d) tuples of edges.

        See Also
        --------
        edges : return a list of edges

        Notes
        -----
        Nodes in nbunch that are not in the graph will be (quietly) ignored.
        For directed graphs this returns the out-edges.

        Examples
        --------
        >>> G = nx.DiGraph()   # or MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> [e for e in G.edges_iter()]
        [(0, 1), (1, 2), (2, 3)]
        >>> list(G.edges_iter(data=True)) # default data is {} (empty dict)
        [(0, 1, {}), (1, 2, {}), (2, 3, {})]
        >>> list(G.edges_iter([0,2]))
        [(0, 1), (2, 3)]
        >>> list(G.edges_iter(0))
        [(0, 1)]

        """
        if nbunch is None:
            nodes_nbrs=self.adj.items()
        else:
            nodes_nbrs=((n,self.adj[n]) for n in self.nbunch_iter(nbunch))
        if data:
            for n,nbrs in nodes_nbrs:
                for nbr,data in nbrs.items():
                    yield (n,nbr,data)
        else:
            for n,nbrs in nodes_nbrs:
                for nbr in nbrs:
                    yield (n,nbr)

    # alias out_edges to edges
    out_edges_iter=edges_iter
    out_edges=Graph.edges

    def in_edges_iter(self, nbunch=None, data=False):
        """Return an iterator over the incoming edges.

        Parameters
        ----------
        nbunch : iterable container, optional (default= all nodes)
            A container of nodes.  The container will be iterated
            through once.
        data : bool, optional (default=False)
            If True, return edge attribute dict in 3-tuple (u,v,data).

        Returns
        -------
        in_edge_iter : iterator
            An iterator of (u,v) or (u,v,d) tuples of incoming edges.

        See Also
        --------
        edges_iter : return an iterator of edges
        """
        if nbunch is None:
            nodes_nbrs=self.pred.items()
        else:
            nodes_nbrs=((n,self.pred[n]) for n in self.nbunch_iter(nbunch))
        if data:
            for n,nbrs in nodes_nbrs:
                for nbr,data in nbrs.items():
                    yield (nbr,n,data)
        else:
            for n,nbrs in nodes_nbrs:
                for nbr in nbrs:
                    yield (nbr,n)

    def in_edges(self, nbunch=None, data=False):
        """Return a list of the incoming edges.

        See Also
        --------
        edges : return a list of edges
        """
        return list(self.in_edges_iter(nbunch, data))

    def degree_iter(self, nbunch=None, weight=None):
        """Return an iterator for (node, degree).

        The node degree is the number of edges adjacent to the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd_iter : an iterator
            The iterator returns two-tuples of (node, degree).

        See Also
        --------
        degree, in_degree, out_degree, in_degree_iter, out_degree_iter

        Examples
        --------
        >>> G = nx.DiGraph()   # or MultiDiGraph
        >>> G.add_path([0,1,2,3])
        >>> list(G.degree_iter(0)) # node 0 with degree 1
        [(0, 1)]
        >>> list(G.degree_iter([0,1]))
        [(0, 1), (1, 2)]

        """
        if nbunch is None:
            nodes_nbrs=zip(iter(self.succ.items()),iter(self.pred.items()))
        else:
            nodes_nbrs=zip(
                ((n,self.succ[n]) for n in self.nbunch_iter(nbunch)),
                ((n,self.pred[n]) for n in self.nbunch_iter(nbunch)))

        if weight is None:
            for (n,succ),(n2,pred) in nodes_nbrs:
                yield (n,len(succ)+len(pred))
        else:
        # edge weighted graph - degree is sum of edge weights
            for (n,succ),(n2,pred) in nodes_nbrs:
               yield (n,
                      sum((succ[nbr].get(weight,1) for nbr in succ))+
                      sum((pred[nbr].get(weight,1) for nbr in pred)))


    def in_degree_iter(self, nbunch=None, weight=None):
        """Return an iterator for (node, in-degree).

        The node in-degree is the number of edges pointing in to the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd_iter : an iterator
            The iterator returns two-tuples of (node, in-degree).

        See Also
        --------
        degree, in_degree, out_degree, out_degree_iter

        Examples
        --------
        >>> G = nx.DiGraph()
        >>> G.add_path([0,1,2,3])
        >>> list(G.in_degree_iter(0)) # node 0 with degree 0
        [(0, 0)]
        >>> list(G.in_degree_iter([0,1]))
        [(0, 0), (1, 1)]

        """
        if nbunch is None:
            nodes_nbrs=self.pred.items()
        else:
            nodes_nbrs=((n,self.pred[n]) for n in self.nbunch_iter(nbunch))

        if weight is None:
            for n,nbrs in nodes_nbrs:
                yield (n,len(nbrs))
        else:
        # edge weighted graph - degree is sum of edge weights
            for n,nbrs in nodes_nbrs:
                yield (n, sum(data.get(weight,1) for data in nbrs.values()))


    def out_degree_iter(self, nbunch=None, weight=None):
        """Return an iterator for (node, out-degree).

        The node out-degree is the number of edges pointing out of the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd_iter : an iterator
            The iterator returns two-tuples of (node, out-degree).

        See Also
        --------
        degree, in_degree, out_degree, in_degree_iter

        Examples
        --------
        >>> G = nx.DiGraph()
        >>> G.add_path([0,1,2,3])
        >>> list(G.out_degree_iter(0)) # node 0 with degree 1
        [(0, 1)]
        >>> list(G.out_degree_iter([0,1]))
        [(0, 1), (1, 1)]

        """
        if nbunch is None:
            nodes_nbrs=self.succ.items()
        else:
            nodes_nbrs=((n,self.succ[n]) for n in self.nbunch_iter(nbunch))

        if weight is None:
            for n,nbrs in nodes_nbrs:
                yield (n,len(nbrs))
        else:
        # edge weighted graph - degree is sum of edge weights
            for n,nbrs in nodes_nbrs:
                yield (n, sum(data.get(weight,1) for data in nbrs.values()))


    def in_degree(self, nbunch=None, weight=None):
        """Return the in-degree of a node or nodes.

        The node in-degree is the number of edges pointing in to the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd : dictionary, or number
            A dictionary with nodes as keys and in-degree as values or
            a number if a single node is specified.

        See Also
        --------
        degree, out_degree, in_degree_iter

        Examples
        --------
        >>> G = nx.DiGraph()   # or MultiDiGraph
        >>> G.add_path([0,1,2,3])
        >>> G.in_degree(0)
        0
        >>> G.in_degree([0,1])
        {0: 0, 1: 1}
        >>> list(G.in_degree([0,1]).values())
        [0, 1]
        """
        if nbunch in self:      # return a single node
            return next(self.in_degree_iter(nbunch,weight))[1]
        else:           # return a dict
            return dict(self.in_degree_iter(nbunch,weight))

    def out_degree(self, nbunch=None, weight=None):
        """Return the out-degree of a node or nodes.

        The node out-degree is the number of edges pointing out of the node.

        Parameters
        ----------
        nbunch : iterable container, optional (default=all nodes)
            A container of nodes.  The container will be iterated
            through once.

        weight : string or None, optional (default=None)
           The edge attribute that holds the numerical value used 
           as a weight.  If None, then each edge has weight 1.
           The degree is the sum of the edge weights adjacent to the node.

        Returns
        -------
        nd : dictionary, or number
            A dictionary with nodes as keys and out-degree as values or
            a number if a single node is specified.

        Examples
        --------
        >>> G = nx.DiGraph()   # or MultiDiGraph
        >>> G.add_path([0,1,2,3])
        >>> G.out_degree(0)
        1
        >>> G.out_degree([0,1])
        {0: 1, 1: 1}
        >>> list(G.out_degree([0,1]).values())
        [1, 1]


        """
        if nbunch in self:      # return a single node
            return next(self.out_degree_iter(nbunch,weight))[1]
        else:           # return a dict
            return dict(self.out_degree_iter(nbunch,weight))

    def clear(self):
        """Remove all nodes and edges from the graph.

        This also removes the name, and all graph, node, and edge attributes.

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> G.clear()
        >>> G.nodes()
        []
        >>> G.edges()
        []

        """
        self.succ.clear()
        self.pred.clear()
        self.node.clear()
        self.graph.clear()


    def is_multigraph(self):
        """Return True if graph is a multigraph, False otherwise."""
        return False


    def is_directed(self):
        """Return True if graph is directed, False otherwise."""
        return True

    def to_directed(self):
        """Return a directed copy of the graph.

        Returns
        -------
        G : DiGraph
            A deepcopy of the graph.

        Notes
        -----
        This returns a "deepcopy" of the edge, node, and
        graph attributes which attempts to completely copy
        all of the data and references.

        This is in contrast to the similar D=DiGraph(G) which returns a
        shallow copy of the data.

        See the Python copy module for more information on shallow
        and deep copies, http://docs.python.org/library/copy.html.

        Examples
        --------
        >>> G = nx.Graph()   # or MultiGraph, etc
        >>> G.add_path([0,1])
        >>> H = G.to_directed()
        >>> H.edges()
        [(0, 1), (1, 0)]

        If already directed, return a (deep) copy

        >>> G = nx.DiGraph()   # or MultiDiGraph, etc
        >>> G.add_path([0,1])
        >>> H = G.to_directed()
        >>> H.edges()
        [(0, 1)]
        """
        return deepcopy(self)

    def to_undirected(self, reciprocal=False):
        """Return an undirected representation of the digraph.

        Parameters
        ----------
        reciprocal : bool (optional)
          If True only keep edges that appear in both directions 
          in the original digraph. 

        Returns
        -------
        G : Graph
            An undirected graph with the same name and nodes and
            with edge (u,v,data) if either (u,v,data) or (v,u,data)
            is in the digraph.  If both edges exist in digraph and
            their edge data is different, only one edge is created
            with an arbitrary choice of which edge data to use.
            You must check and correct for this manually if desired.

        Notes
        -----
        If edges in both directions (u,v) and (v,u) exist in the
        graph, attributes for the new undirected edge will be a combination of
        the attributes of the directed edges.  The edge data is updated
        in the (arbitrary) order that the edges are encountered.  For
        more customized control of the edge attributes use add_edge().

        This returns a "deepcopy" of the edge, node, and
        graph attributes which attempts to completely copy
        all of the data and references.

        This is in contrast to the similar G=DiGraph(D) which returns a
        shallow copy of the data.

        See the Python copy module for more information on shallow
        and deep copies, http://docs.python.org/library/copy.html.
        """
        H=Graph()
        H.name=self.name
        H.add_nodes_from(self)
        if reciprocal is True:
            H.add_edges_from( (u,v,deepcopy(d))
                              for u,nbrs in self.adjacency_iter()
                              for v,d in nbrs.items() 
                              if v in self.pred[u])
        else:
            H.add_edges_from( (u,v,deepcopy(d))
                              for u,nbrs in self.adjacency_iter()
                              for v,d in nbrs.items() )
        H.graph=deepcopy(self.graph)
        H.node=deepcopy(self.node)
        return H


    def reverse(self, copy=True):
        """Return the reverse of the graph.

        The reverse is a graph with the same nodes and edges
        but with the directions of the edges reversed.

        Parameters
        ----------
        copy : bool optional (default=True)
            If True, return a new DiGraph holding the reversed edges.
            If False, reverse the reverse graph is created using
            the original graph (this changes the original graph).
        """
        if copy:
            H = self.__class__(name="Reverse of (%s)"%self.name)
            H.add_nodes_from(self)
            H.add_edges_from( (v,u,deepcopy(d)) for u,v,d 
                              in self.edges(data=True) )
            H.graph=deepcopy(self.graph)
            H.node=deepcopy(self.node)
        else:
            self.pred,self.succ=self.succ,self.pred
            self.adj=self.succ
            H=self
        return H


    def subgraph(self, nbunch):
        """Return the subgraph induced on nodes in nbunch.

        The induced subgraph of the graph contains the nodes in nbunch
        and the edges between those nodes.

        Parameters
        ----------
        nbunch : list, iterable
            A container of nodes which will be iterated through once.

        Returns
        -------
        G : Graph
            A subgraph of the graph with the same edge attributes.

        Notes
        -----
        The graph, edge or node attributes just point to the original graph.
        So changes to the node or edge structure will not be reflected in
        the original graph while changes to the attributes will.

        To create a subgraph with its own copy of the edge/node attributes use:
        nx.Graph(G.subgraph(nbunch))

        If edge attributes are containers, a deep copy can be obtained using:
        G.subgraph(nbunch).copy()

        For an inplace reduction of a graph to a subgraph you can remove nodes:
        G.remove_nodes_from([ n in G if n not in set(nbunch)])

        Examples
        --------
        >>> G = nx.Graph()   # or DiGraph, MultiGraph, MultiDiGraph, etc
        >>> G.add_path([0,1,2,3])
        >>> H = G.subgraph([0,1,2])
        >>> H.edges()
        [(0, 1), (1, 2)]
        """
        bunch = self.nbunch_iter(nbunch)
        # create new graph and copy subgraph into it
        H = self.__class__()
        # copy node and attribute dictionaries
        for n in bunch:
            H.node[n]=self.node[n]
        # namespace shortcuts for speed
        H_succ=H.succ
        H_pred=H.pred
        self_succ=self.succ
        # add nodes
        for n in H:
            H_succ[n]={}
            H_pred[n]={}
        # add edges
        for u in H_succ:
            Hnbrs=H_succ[u]
            for v,datadict in self_succ[u].items():
                if v in H_succ:
                    # add both representations of edge: u-v and v-u
                    Hnbrs[v]=datadict
                    H_pred[v][u]=datadict
        H.graph=self.graph
        return H


DEFAULT_RISKS = {
    INTERNET_RISK : ( "INTERNET_RISK", (195, 255, 0) ),
    PRIVACY_RISK : ( "PRIVACY_RISK", (255, 255, 51) ),
    PHONE_RISK : ( "PHONE_RISK", ( 255, 216, 0 ) ),
    SMS_RISK : ( "SMS_RISK", ( 255, 93, 0 ) ),
    MONEY_RISK : ( "MONEY_RISK", ( 255, 0, 0 ) ),
}

DEXCLASSLOADER_COLOR = (0, 0, 0)
ACTIVITY_COLOR = (51, 255, 51)
SERVICE_COLOR = (0, 204, 204)
RECEIVER_COLOR = (204, 51, 204)

ID_ATTRIBUTES = {
    "type" : 0,
    "class_name" : 1,
    "method_name" : 2,
    "descriptor" : 3,
    "permissions" : 4,
    "permissions_level" : 5,
    "dynamic_code" : 6,
}

class GVMAnalysis :
    def __init__(self, vmx, apk) :
        self.vmx = vmx
        self.vm = self.vmx.get_vm()

        self.nodes = {}
        self.nodes_id = {}
        self.entry_nodes = [] 
        self.G = DiGraph()

        for j in self.vmx.get_tainted_packages().get_internal_packages() :
            src_class_name, src_method_name, src_descriptor = j.get_src( self.vm.get_class_manager() )
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.vm.get_class_manager() )

            n1 = self._get_node( src_class_name, src_method_name, src_descriptor )
            n2 = self._get_node( dst_class_name, dst_method_name, dst_descriptor )

            self.G.add_edge( n1.id, n2.id )
            n1.add_edge( n2, j )

        if apk != None :
            for i in apk.get_activities() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "(Landroid/os/Bundle;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "activity" } )
                    n1.set_attributes( { "color" : ACTIVITY_COLOR } )
                    n2 = self._get_new_node_from( n1, "ACTIVITY" )
                    n2.set_attributes( { "color" : ACTIVITY_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_services() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "()V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "service" } )
                    n1.set_attributes( { "color" : SERVICE_COLOR } )
                    n2 = self._get_new_node_from( n1, "SERVICE" )
                    n2.set_attributes( { "color" : SERVICE_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_receivers() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onReceive", "(Landroid/content/Context; Landroid/content/Intent;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "receiver" } )
                    n1.set_attributes( { "color" : RECEIVER_COLOR } )
                    n2 = self._get_new_node_from( n1, "RECEIVER" )
                    n2.set_attributes( { "color" : RECEIVER_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )

        # Specific Java/Android library
        for c in self.vm.get_classes() :
            #if c.get_superclassname() == "Landroid/app/Service;" :
            #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
            #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )

            #    self.G.add_edge( n1.id, n2.id )
            if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
                for i in self.vm.get_method("run") :
                    if i.get_class_name() == c.get_name() :
                        n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
                        n2 = self._get_node( i.get_class_name(), "start", i.get_descriptor() ) 
                       
                        # link from start to run
                        self.G.add_edge( n2.id, n1.id )
                        n2.add_edge( n1, {} )

                        # link from init to start
                        for init in self.vm.get_method("<init>") :
                            if init.get_class_name() == c.get_name() :
                                n3 = self._get_node( init.get_class_name(), "<init>", init.get_descriptor() )
                                #n3 = self._get_node( i.get_class_name(), "<init>", i.get_descriptor() )
                                self.G.add_edge( n3.id, n2.id )
                                n3.add_edge( n2, {} )

            #elif c.get_superclassname() == "Landroid/os/AsyncTask;" :
            #    for i in self.vm.get_method("doInBackground") :
            #        if i.get_class_name() == c.get_name() :
            #            n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
            #            n2 = self._get_exist_node( i.get_class_name(), "execute", i.get_descriptor() )
            #            print n1, n2, i.get_descriptor()
                        #for j in self.vm.get_method("doInBackground") :
                        #    n2 = self._get_exist_node( i.get_class_name(), j.get_name(), j.get_descriptor() )
                        #    print n1, n2
                        # n2 = self._get_node( i.get_class_name(), "
            #    raise("ooo")

        #for j in self.vmx.tainted_packages.get_internal_new_packages() :
        #    print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
        #                                            j.get_bb().start + j.get_idx(), \
        #                                            j.get_class_name(), j.get_name(), j.get_descriptor())


        list_permissions = self.vmx.get_permissions( [] ) 
        for x in list_permissions :
            for j in list_permissions[ x ] :
                if isinstance(j, PathVar) :
                  continue

                src_class_name, src_method_name, src_descriptor = j.get_src( self.vm.get_class_manager() )
                dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.vm.get_class_manager() )
                n1 = self._get_exist_node( dst_class_name, dst_method_name, dst_descriptor )

                if n1 == None :
                    continue

                n1.set_attributes( { "permissions" : 1 } )
                n1.set_attributes( { "permissions_level" : DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ x ][0] } )
                n1.set_attributes( { "permissions_details" : x } )

                try :
                    for tmp_perm in PERMISSIONS_RISK[ x ] :
                        if tmp_perm in DEFAULT_RISKS :
                            n2 = self._get_new_node( dst_class_name,
                                                     dst_method_name,
                                                     dst_descriptor + " " + DEFAULT_RISKS[ tmp_perm ][0],
                                                     DEFAULT_RISKS[ tmp_perm ][0] )
                            n2.set_attributes( { "color" : DEFAULT_RISKS[ tmp_perm ][1] } )
                            self.G.add_edge( n2.id, n1.id )

                            n1.add_risk( DEFAULT_RISKS[ tmp_perm ][0] )
                            n1.add_api( x, src_class_name + "-" + src_method_name + "-" + src_descriptor )
                except KeyError :
                    pass

        # Tag DexClassLoader
        for m, _ in self.vmx.get_tainted_packages().get_packages() :
            if m.get_name() == "Ldalvik/system/DexClassLoader;" :
                for path in m.get_paths() :
                    if path.get_access_flag() == TAINTED_PACKAGE_CREATE :
                        src_class_name, src_method_name, src_descriptor = path.get_src( self.vm.get_class_manager() )
                        n1 = self._get_exist_node( src_class_name, src_method_name, src_descriptor )
                        n2 = self._get_new_node( dst_class_name, dst_method_name, dst_descriptor + " " + "DEXCLASSLOADER",
                                                 "DEXCLASSLOADER" )

                        n1.set_attributes( { "dynamic_code" : "true" } )
                        n2.set_attributes( { "color" : DEXCLASSLOADER_COLOR } )
                        self.G.add_edge( n2.id, n1.id )

                        n1.add_risk( "DEXCLASSLOADER" )

    def _get_exist_node(self, class_name, method_name, descriptor) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        try :
            return self.nodes[ key ]
        except KeyError :
            return None

    def _get_node(self, class_name, method_name, descriptor) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes :
            self.nodes[ key ] = NodeF( len(self.nodes), class_name, method_name, descriptor )
            self.nodes_id[ self.nodes[ key ].id ] = self.nodes[ key ]

        return self.nodes[ key ]

    def _get_new_node_from(self, n, label) :
        return self._get_new_node( n.class_name, n.method_name, n.descriptor + label, label )

    def _get_new_node(self, class_name, method_name, descriptor, label) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes :
            self.nodes[ key ] = NodeF( len(self.nodes), class_name, method_name, descriptor, label, False )
            self.nodes_id[ self.nodes[ key ].id ] = self.nodes[ key ]

        return self.nodes[ key ]

    def set_new_attributes(self, cm) :
        for i in self.G.nodes() :
            n1 = self.nodes_id[ i ]
            m1 = self.vm.get_method_descriptor( n1.class_name, n1.method_name, n1.descriptor )

            H = cm( self.vmx, m1 )

            n1.set_attributes( H )

    def export_to_gexf(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        buff += "<gexf xmlns=\"http://www.gephi.org/gexf\" xmlns:viz=\"http://www.gephi.org/gexf/viz\">\n"
        buff += "<graph type=\"static\">\n"

        buff += "<attributes class=\"node\" type=\"static\">\n" 
        buff += "<attribute default=\"normal\" id=\"%d\" title=\"type\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "type"]
        buff += "<attribute id=\"%d\" title=\"class_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "class_name"]
        buff += "<attribute id=\"%d\" title=\"method_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "method_name"]
        buff += "<attribute id=\"%d\" title=\"descriptor\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "descriptor"]


        buff += "<attribute default=\"0\" id=\"%d\" title=\"permissions\" type=\"integer\"/>\n" % ID_ATTRIBUTES[ "permissions"]
        buff += "<attribute default=\"normal\" id=\"%d\" title=\"permissions_level\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "permissions_level"]
        
        buff += "<attribute default=\"false\" id=\"%d\" title=\"dynamic_code\" type=\"boolean\"/>\n" % ID_ATTRIBUTES[ "dynamic_code"]
        buff += "</attributes>\n"   

        buff += "<nodes>\n"
        for node in self.G.nodes() :
            buff += "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label))
            buff += self.nodes_id[ node ].get_attributes_gexf()
            buff += "</node>\n"
        buff += "</nodes>\n"


        buff += "<edges>\n"
        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1
        buff += "</edges>\n"


        buff += "</graph>\n"
        buff += "</gexf>\n"

        return buff

    def export_to_gml(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
        buff += "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:y=\"http://www.yworks.com/xml/graphml\" xmlns:yed=\"http://www.yworks.com/xml/yed/3\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://www.yworks.com/xml/schema/graphml/1.1/ygraphml.xsd\">\n"

        buff += "<key attr.name=\"description\" attr.type=\"string\" for=\"node\" id=\"d5\"/>\n"
        buff += "<key for=\"node\" id=\"d6\" yfiles.type=\"nodegraphics\"/>\n"

        buff += "<graph edgedefault=\"directed\" id=\"G\">\n"

        for node in self.G.nodes() :
            buff += "<node id=\"%d\">\n" % (node)
            #fd.write( "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label)) )
            buff += self.nodes_id[ node ].get_attributes_gml()
            buff += "</node>\n"

        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1

        buff += "</graph>\n"
        buff += "</graphml>\n"
        
        return buff

    def get_paths_method(self, method) :
        return self.get_paths( method.get_class_name(), method.get_name(), method.get_descriptor() )

    def get_paths(self, class_name, method_name, descriptor) :
        import connectivity_approx as ca
        paths = []
        key = "%s %s %s" % (class_name, method_name, descriptor)
       
        if key not in self.nodes :
            return paths

        for origin in self.G.nodes() : #self.entry_nodes :
            if ca.vertex_connectivity_approx(self.G, origin, self.nodes[ key ].id) > 0 :
                for path in ca.node_independent_paths(self.G, origin, self.nodes[ key ].id) :
                    if self.nodes_id[ path[0] ].real == True :
                        paths.append( path )
        return paths

    def print_paths_method(self, method) :
        self.print_paths( method.get_class_name(), method.get_name(), method.get_descriptor() )

    def print_paths(self, class_name, method_name, descriptor) :
        paths = self.get_paths( class_name, method_name, descriptor )
        for path in paths :
            print path, ":"
            print "\t",
            for p in path[:-1] :
                print self.nodes_id[ p ].label, "-->",
            print self.nodes_id[ path[-1] ].label

DEFAULT_NODE_TYPE = "normal"
DEFAULT_NODE_PERM = 0
DEFAULT_NODE_PERM_LEVEL = -1 

PERMISSIONS_LEVEL = {
    "dangerous" : 3,
    "signatureOrSystem" : 2,
    "signature" : 1,
    "normal" : 0,
}

COLOR_PERMISSIONS_LEVEL = {
    "dangerous"                 : (255, 0, 0),
    "signatureOrSystem"         : (255, 63, 63),
    "signature"                 : (255, 132, 132),
    "normal"                    : (255, 181, 181),
}

class NodeF :
    def __init__(self, id, class_name, method_name, descriptor, label=None, real=True) :
        self.class_name = class_name
        self.method_name = method_name 
        self.descriptor = descriptor

        self.id = id
        self.real = real
        self.risks = []
        self.api = {} 
        self.edges = {}

        if label == None : 
            self.label = "%s %s %s" % (class_name, method_name, descriptor)
        else :
            self.label = label

        self.attributes = { "type" : DEFAULT_NODE_TYPE,
                            "color" : None,
                            "permissions" : DEFAULT_NODE_PERM,
                            "permissions_level" : DEFAULT_NODE_PERM_LEVEL,
                            "permissions_details" : set(),
                            "dynamic_code" : "false",
                          }

    def add_edge(self, n, idx) :
        try :
            self.edges[ n ].append( idx )
        except KeyError :
            self.edges[ n ] = []
            self.edges[ n ].append( idx )

    def get_attributes_gexf(self) :
        buff = ""
        
        if self.attributes[ "color" ] != None : 
            buff += "<viz:color r=\"%d\" g=\"%d\" b=\"%d\"/>\n" % (self.attributes[ "color" ][0], self.attributes[ "color" ][1], self.attributes[ "color" ][2])
        
        buff += "<attvalues>\n"
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["class_name"], escape(self.class_name))
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["method_name"], escape(self.method_name))
        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["descriptor"], escape(self.descriptor))
        
        
        if self.attributes[ "type" ] != DEFAULT_NODE_TYPE :
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["type"], self.attributes[ "type" ])
        if self.attributes[ "permissions" ] != DEFAULT_NODE_PERM :
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["permissions"], self.attributes[ "permissions" ])
            buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["permissions_level"], self.attributes[ "permissions_level_name" ])


        buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES["dynamic_code"], self.attributes[ "dynamic_code" ])

        buff += "</attvalues>\n"

        return buff

    def get_attributes_gml(self) :
        buff = ""
        
        buff += "<data key=\"d6\">\n"
        buff += "<y:ShapeNode>\n"
       
        height = 10 
        width = max(len(self.class_name), len(self.method_name))
        width = max(width, len(self.descriptor))

        buff += "<y:Geometry height=\"%f\" width=\"%f\"/>\n" % (16 * height, 8 * width)
        if self.attributes[ "color" ] != None : 
            buff += "<y:Fill color=\"#%02x%02x%02x\" transparent=\"false\"/>\n" % (self.attributes[ "color" ][0], self.attributes[ "color" ][1], self.attributes[ "color" ][2])

        buff += "<y:NodeLabel alignment=\"left\" autoSizePolicy=\"content\" fontFamily=\"Dialog\" fontSize=\"13\" fontStyle=\"plain\" hasBackgroundColor=\"false\" hasLineColor=\"false\" modelName=\"internal\" modelPosition=\"c\" textColor=\"#000000\" visible=\"true\">\n"

        label = self.class_name + "\n" + self.method_name + "\n" + self.descriptor
        buff += escape(label)

        buff += "</y:NodeLabel>\n"
        buff += "</y:ShapeNode>\n"
        buff += "</data>\n"

        return buff

    def get_attributes(self) :
        return self.attributes

    def get_attribute(self, name) :
        return self.attributes[ name ]

    def set_attributes(self, values) :
        for i in values :
            if i == "permissions" :
                self.attributes[ "permissions" ] += values[i]
            elif i == "permissions_level" :
                if values[i] > self.attributes[ "permissions_level" ] :
                    self.attributes[ "permissions_level" ] = PERMISSIONS_LEVEL[ values[i] ]
                    self.attributes[ "permissions_level_name" ] = values[i]
                    self.attributes[ "color" ] = COLOR_PERMISSIONS_LEVEL[ values[i] ]
            elif i == "permissions_details" :
                self.attributes[ i ].add( values[i] )
            else :
                self.attributes[ i ] = values[i]

    def add_risk(self, risk) :
        if risk not in self.risks :
            self.risks.append( risk )

    def add_api(self, perm, api) :
        if perm not in self.api :
            self.api[ perm ] = []

        if api not in self.api[ perm ] :
            self.api[ perm ].append( api )
