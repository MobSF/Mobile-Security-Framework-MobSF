import unittest

from altgraph import GraphError
from altgraph.Graph import Graph

class TestGraph (unittest.TestCase):

    def test_nodes(self):
        graph = Graph()

        self.assertEqual(graph.node_list(), [])

        o1 = object()
        o1b = object()
        o2 = object()
        graph.add_node(1, o1)
        graph.add_node(1, o1b)
        graph.add_node(2, o2)
        graph.add_node(3)

        self.assertRaises(TypeError, graph.add_node, [])

        self.assertTrue(graph.node_data(1) is o1)
        self.assertTrue(graph.node_data(2) is o2)
        self.assertTrue(graph.node_data(3) is None)

        self.assertTrue(1 in graph)
        self.assertTrue(2 in graph)
        self.assertTrue(3 in graph)

        self.assertEqual(graph.number_of_nodes(), 3)
        self.assertEqual(graph.number_of_hidden_nodes(), 0)
        self.assertEqual(graph.hidden_node_list(), [])
        self.assertEqual(list(sorted(graph)), [1, 2, 3])

        graph.hide_node(1)
        graph.hide_node(2)
        graph.hide_node(3)


        self.assertEqual(graph.number_of_nodes(), 0)
        self.assertEqual(graph.number_of_hidden_nodes(), 3)
        self.assertEqual(list(sorted(graph.hidden_node_list())), [1, 2, 3])

        self.assertFalse(1 in graph)
        self.assertFalse(2 in graph)
        self.assertFalse(3 in graph)

        graph.add_node(1)
        self.assertFalse(1 in graph)

        graph.restore_node(1)
        self.assertTrue(1 in graph)
        self.assertFalse(2 in graph)
        self.assertFalse(3 in graph)

        graph.restore_all_nodes()
        self.assertTrue(1 in graph)
        self.assertTrue(2 in graph)
        self.assertTrue(3 in graph)

        self.assertEqual(list(sorted(graph.node_list())), [1, 2, 3])

        v = graph.describe_node(1)
        self.assertEqual(v, (1, o1, [], []))

    def test_edges(self):
        graph = Graph()
        graph.add_node(1)
        graph.add_node(2)
        graph.add_node(3)
        graph.add_node(4)
        graph.add_node(5)

        self.assertTrue(isinstance(graph.edge_list(), list))

        graph.add_edge(1, 2)
        graph.add_edge(4, 5, 'a')

        self.assertRaises(GraphError, graph.add_edge, 'a', 'b', create_nodes=False)

        self.assertEqual(graph.number_of_hidden_edges(), 0)
        self.assertEqual(graph.number_of_edges(), 2)
        e = graph.edge_by_node(1, 2)
        self.assertTrue(isinstance(e, int))
        graph.hide_edge(e)
        self.assertEqual(graph.number_of_hidden_edges(), 1)
        self.assertEqual(graph.number_of_edges(), 1)
        e2 = graph.edge_by_node(1, 2)
        self.assertTrue(e2 is None)

        graph.restore_edge(e)
        e2 = graph.edge_by_node(1, 2)
        self.assertEqual(e, e2)
        self.assertEqual(graph.number_of_hidden_edges(), 0)

        self.assertEqual(graph.number_of_edges(), 2)

        e1 = graph.edge_by_node(1, 2)
        e2 = graph.edge_by_node(4, 5)
        graph.hide_edge(e1)
        graph.hide_edge(e2)

        self.assertEqual(graph.number_of_edges(), 0)
        graph.restore_all_edges()
        self.assertEqual(graph.number_of_edges(), 2)

        self.assertEqual(graph.edge_by_id(e1), (1,2))
        self.assertRaises(GraphError, graph.edge_by_id, (e1+1)*(e2+1)+1)

        self.assertEqual(list(sorted(graph.edge_list())), [e1, e2])

        self.assertEqual(graph.describe_edge(e1), (e1, 1, 1, 2))
        self.assertEqual(graph.describe_edge(e2), (e2, 'a', 4, 5))

        self.assertEqual(graph.edge_data(e1), 1)
        self.assertEqual(graph.edge_data(e2), 'a')

        self.assertEqual(graph.head(e2), 4)
        self.assertEqual(graph.tail(e2), 5)

        graph.add_edge(1, 3)
        graph.add_edge(1, 5)
        graph.add_edge(4, 1)

        self.assertEqual(list(sorted(graph.out_nbrs(1))), [2, 3, 5])
        self.assertEqual(list(sorted(graph.inc_nbrs(1))), [4])
        self.assertEqual(list(sorted(graph.inc_nbrs(5))), [1, 4])
        self.assertEqual(list(sorted(graph.all_nbrs(1))), [2, 3, 4, 5])

        graph.add_edge(5, 1)
        self.assertEqual(list(sorted(graph.all_nbrs(5))), [1, 4])

        self.assertEqual(graph.out_degree(1), 3)
        self.assertEqual(graph.inc_degree(2), 1)
        self.assertEqual(graph.inc_degree(5), 2)
        self.assertEqual(graph.all_degree(5), 3)

        v = graph.out_edges(4)
        self.assertTrue(isinstance(v, list))
        self.assertEqual(graph.edge_by_id(v[0]), (4, 5))

        v = graph.out_edges(1)
        for e in v:
            self.assertEqual(graph.edge_by_id(e)[0], 1)

        v = graph.inc_edges(1)
        self.assertTrue(isinstance(v, list))
        self.assertEqual(graph.edge_by_id(v[0]), (4, 1))

        v = graph.inc_edges(5)
        for e in v:
            self.assertEqual(graph.edge_by_id(e)[1], 5)

        v = graph.all_edges(5)
        for e in v:
            self.assertTrue(graph.edge_by_id(e)[1] == 5 or graph.edge_by_id(e)[0] == 5)

        e1 = graph.edge_by_node(1, 2)
        self.assertTrue(isinstance(e1, int))
        graph.hide_node(1)
        self.assertRaises(GraphError, graph.edge_by_node, 1, 2)
        graph.restore_node(1)
        e2 = graph.edge_by_node(1, 2)
        self.assertEqual(e1, e2)



    def test_toposort(self):
        graph = Graph()
        graph.add_node(1)
        graph.add_node(2)
        graph.add_node(3)
        graph.add_node(4)
        graph.add_node(5)

        graph.add_edge(1, 2)
        graph.add_edge(1, 3)
        graph.add_edge(2, 4)
        graph.add_edge(3, 5)

        ok, result = graph.forw_topo_sort()
        self.assertTrue(ok)
        for idx in range(1, 6):
            self.assertTrue(idx in result)

        self.assertTrue(result.index(1) < result.index(2))
        self.assertTrue(result.index(1) < result.index(3))
        self.assertTrue(result.index(2) < result.index(4))
        self.assertTrue(result.index(3) < result.index(5))

        ok, result = graph.back_topo_sort()
        self.assertTrue(ok)
        for idx in range(1, 6):
            self.assertTrue(idx in result)
        self.assertTrue(result.index(2) < result.index(1))
        self.assertTrue(result.index(3) < result.index(1))
        self.assertTrue(result.index(4) < result.index(2))
        self.assertTrue(result.index(5) < result.index(3))


        # Same graph as before, but with edges
        # reversed, which means we should get
        # the same results as before if using
        # back_topo_sort rather than forw_topo_sort
        # (and v.v.)

        graph = Graph()
        graph.add_node(1)
        graph.add_node(2)
        graph.add_node(3)
        graph.add_node(4)
        graph.add_node(5)

        graph.add_edge(2, 1)
        graph.add_edge(3, 1)
        graph.add_edge(4, 2)
        graph.add_edge(5, 3)

        ok, result = graph.back_topo_sort()
        self.assertTrue(ok)
        for idx in range(1, 6):
            self.assertTrue(idx in result)

        self.assertTrue(result.index(1) < result.index(2))
        self.assertTrue(result.index(1) < result.index(3))
        self.assertTrue(result.index(2) < result.index(4))
        self.assertTrue(result.index(3) < result.index(5))

        ok, result = graph.forw_topo_sort()
        self.assertTrue(ok)
        for idx in range(1, 6):
            self.assertTrue(idx in result)
        self.assertTrue(result.index(2) < result.index(1))
        self.assertTrue(result.index(3) < result.index(1))
        self.assertTrue(result.index(4) < result.index(2))
        self.assertTrue(result.index(5) < result.index(3))


        # Create a cycle
        graph.add_edge(1, 5)
        ok, result = graph.forw_topo_sort()
        self.assertFalse(ok)
        ok, result = graph.back_topo_sort()
        self.assertFalse(ok)

    def test_bfs_subgraph(self):
        graph = Graph()
        graph.add_edge(1, 2)
        graph.add_edge(1, 4)
        graph.add_edge(2, 4)
        graph.add_edge(4, 8)
        graph.add_edge(4, 9)
        graph.add_edge(4, 10)
        graph.add_edge(8, 10)

        subgraph = graph.forw_bfs_subgraph(10)
        self.assertTrue(isinstance(subgraph, Graph))
        self.assertEqual(subgraph.number_of_nodes(), 1)
        self.assertTrue(10 in subgraph)
        self.assertEqual(subgraph.number_of_edges(), 0)

        subgraph = graph.forw_bfs_subgraph(4)
        self.assertTrue(isinstance(subgraph, Graph))
        self.assertEqual(subgraph.number_of_nodes(), 4)
        self.assertTrue(4 in subgraph)
        self.assertTrue(8 in subgraph)
        self.assertTrue(9 in subgraph)
        self.assertTrue(10 in subgraph)
        self.assertEqual(subgraph.number_of_edges(), 4)
        e = subgraph.edge_by_node(4, 8)
        e = subgraph.edge_by_node(4, 9)
        e = subgraph.edge_by_node(4, 10)
        e = subgraph.edge_by_node(8, 10)

        # same graph as before, but switch around
        # edges. This results in the same test results
        # but now for back_bfs_subgraph rather than
        # forw_bfs_subgraph

        graph = Graph()
        graph.add_edge(2, 1)
        graph.add_edge(4, 1)
        graph.add_edge(4, 2)
        graph.add_edge(8, 4)
        graph.add_edge(9, 4)
        graph.add_edge(10, 4)
        graph.add_edge(10, 8)

        subgraph = graph.back_bfs_subgraph(10)
        self.assertTrue(isinstance(subgraph, Graph))
        self.assertEqual(subgraph.number_of_nodes(), 1)
        self.assertTrue(10 in subgraph)
        self.assertEqual(subgraph.number_of_edges(), 0)

        subgraph = graph.back_bfs_subgraph(4)
        self.assertTrue(isinstance(subgraph, Graph))
        self.assertEqual(subgraph.number_of_nodes(), 4)
        self.assertTrue(4 in subgraph)
        self.assertTrue(8 in subgraph)
        self.assertTrue(9 in subgraph)
        self.assertTrue(10 in subgraph)
        self.assertEqual(subgraph.number_of_edges(), 4)
        e = subgraph.edge_by_node(4, 8)
        e = subgraph.edge_by_node(4, 9)
        e = subgraph.edge_by_node(4, 10)
        e = subgraph.edge_by_node(8, 10)

    def test_iterdfs(self):
        graph = Graph()
        graph.add_edge("1", "1.1")
        graph.add_edge("1", "1.2")
        graph.add_edge("1", "1.3")
        graph.add_edge("1.1", "1.1.1")
        graph.add_edge("1.1", "1.1.2")
        graph.add_edge("1.2", "1.2.1")
        graph.add_edge("1.2", "1.2.2")
        graph.add_edge("1.2.2", "1.2.2.1")
        graph.add_edge("1.2.2", "1.2.2.2")
        graph.add_edge("1.2.2", "1.2.2.3")

        result = list(graph.iterdfs("1"))
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])
        result = list(graph.iterdfs("1", "1.2.1"))
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1'
        ])

        result = graph.forw_dfs("1")
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])
        result = graph.forw_dfs("1", "1.2.1")
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1'
        ])

        graph = Graph()
        graph.add_edge("1.1", "1")
        graph.add_edge("1.2", "1")
        graph.add_edge("1.3", "1")
        graph.add_edge("1.1.1", "1.1")
        graph.add_edge("1.1.2", "1.1")
        graph.add_edge("1.2.1", "1.2")
        graph.add_edge("1.2.2", "1.2")
        graph.add_edge("1.2.2.1", "1.2.2")
        graph.add_edge("1.2.2.2", "1.2.2")
        graph.add_edge("1.2.2.3", "1.2.2")

        result = list(graph.iterdfs("1", forward=False))
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])
        result = list(graph.iterdfs("1", "1.2.1", forward=False))
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1'
        ])
        result = graph.back_dfs("1")
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])
        result = graph.back_dfs("1", "1.2.1")
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1'
        ])


        # Introduce cyle:
        graph.add_edge("1", "1.2")
        result = list(graph.iterdfs("1", forward=False))
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])

        result = graph.back_dfs("1")
        self.assertEqual(result, [
            '1', '1.3', '1.2', '1.2.2', '1.2.2.3', '1.2.2.2',
            '1.2.2.1', '1.2.1', '1.1', '1.1.2', '1.1.1'
        ])


    def test_iterdata(self):
        graph = Graph()
        graph.add_node("1", "I")
        graph.add_node("1.1", "I.I")
        graph.add_node("1.2", "I.II")
        graph.add_node("1.3", "I.III")
        graph.add_node("1.1.1", "I.I.I")
        graph.add_node("1.1.2", "I.I.II")
        graph.add_node("1.2.1", "I.II.I")
        graph.add_node("1.2.2", "I.II.II")
        graph.add_node("1.2.2.1", "I.II.II.I")
        graph.add_node("1.2.2.2", "I.II.II.II")
        graph.add_node("1.2.2.3", "I.II.II.III")

        graph.add_edge("1", "1.1")
        graph.add_edge("1", "1.2")
        graph.add_edge("1", "1.3")
        graph.add_edge("1.1", "1.1.1")
        graph.add_edge("1.1", "1.1.2")
        graph.add_edge("1.2", "1.2.1")
        graph.add_edge("1.2", "1.2.2")
        graph.add_edge("1.2.2", "1.2.2.1")
        graph.add_edge("1.2.2", "1.2.2.2")
        graph.add_edge("1.2.2", "1.2.2.3")

        result = list(graph.iterdata("1", forward=True))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II', 'I.II.II', 'I.II.II.III', 'I.II.II.II',
            'I.II.II.I', 'I.II.I', 'I.I', 'I.I.II', 'I.I.I'
        ])

        result = list(graph.iterdata("1", end="1.2.1", forward=True))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II', 'I.II.II', 'I.II.II.III', 'I.II.II.II',
            'I.II.II.I', 'I.II.I'
        ])

        result = list(graph.iterdata("1", condition=lambda n: len(n) < 6, forward=True))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II',
            'I.I', 'I.I.I'
        ])


        # And the revese option:
        graph = Graph()
        graph.add_node("1", "I")
        graph.add_node("1.1", "I.I")
        graph.add_node("1.2", "I.II")
        graph.add_node("1.3", "I.III")
        graph.add_node("1.1.1", "I.I.I")
        graph.add_node("1.1.2", "I.I.II")
        graph.add_node("1.2.1", "I.II.I")
        graph.add_node("1.2.2", "I.II.II")
        graph.add_node("1.2.2.1", "I.II.II.I")
        graph.add_node("1.2.2.2", "I.II.II.II")
        graph.add_node("1.2.2.3", "I.II.II.III")

        graph.add_edge("1.1", "1")
        graph.add_edge("1.2", "1")
        graph.add_edge("1.3", "1")
        graph.add_edge("1.1.1", "1.1")
        graph.add_edge("1.1.2", "1.1")
        graph.add_edge("1.2.1", "1.2")
        graph.add_edge("1.2.2", "1.2")
        graph.add_edge("1.2.2.1", "1.2.2")
        graph.add_edge("1.2.2.2", "1.2.2")
        graph.add_edge("1.2.2.3", "1.2.2")

        result = list(graph.iterdata("1", forward=False))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II', 'I.II.II', 'I.II.II.III', 'I.II.II.II',
            'I.II.II.I', 'I.II.I', 'I.I', 'I.I.II', 'I.I.I'
        ])

        result = list(graph.iterdata("1", end="1.2.1", forward=False))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II', 'I.II.II', 'I.II.II.III', 'I.II.II.II',
            'I.II.II.I', 'I.II.I'
        ])

        result = list(graph.iterdata("1", condition=lambda n: len(n) < 6, forward=False))
        self.assertEqual(result, [
            'I', 'I.III', 'I.II',
            'I.I', 'I.I.I'
        ])

    def test_bfs(self):
        graph = Graph()
        graph.add_edge("1", "1.1")
        graph.add_edge("1.1", "1.1.1")
        graph.add_edge("1.1", "1.1.2")
        graph.add_edge("1.1.2", "1.1.2.1")
        graph.add_edge("1.1.2", "1.1.2.2")
        graph.add_edge("1", "1.2")
        graph.add_edge("1", "1.3")
        graph.add_edge("1.2", "1.2.1")

        self.assertEqual(graph.forw_bfs("1"),
                ['1', '1.1', '1.2', '1.3', '1.1.1', '1.1.2', '1.2.1', '1.1.2.1', '1.1.2.2'])
        self.assertEqual(graph.forw_bfs("1", "1.1.1"),
                ['1', '1.1', '1.2', '1.3', '1.1.1'])


        # And the "reverse" graph
        graph = Graph()
        graph.add_edge("1.1", "1")
        graph.add_edge("1.1.1", "1.1")
        graph.add_edge("1.1.2", "1.1")
        graph.add_edge("1.1.2.1", "1.1.2")
        graph.add_edge("1.1.2.2", "1.1.2")
        graph.add_edge("1.2", "1")
        graph.add_edge("1.3", "1")
        graph.add_edge("1.2.1", "1.2")

        self.assertEqual(graph.back_bfs("1"),
                ['1', '1.1', '1.2', '1.3', '1.1.1', '1.1.2', '1.2.1', '1.1.2.1', '1.1.2.2'])
        self.assertEqual(graph.back_bfs("1", "1.1.1"),
                ['1', '1.1', '1.2', '1.3', '1.1.1'])



        # check cycle handling
        graph.add_edge("1", "1.2.1")
        self.assertEqual(graph.back_bfs("1"),
                ['1', '1.1', '1.2', '1.3', '1.1.1', '1.1.2', '1.2.1', '1.1.2.1', '1.1.2.2'])


    def test_connected(self):
        graph = Graph()
        graph.add_node(1)
        graph.add_node(2)
        graph.add_node(3)
        graph.add_node(4)

        self.assertFalse(graph.connected())

        graph.add_edge(1, 2)
        graph.add_edge(3, 4)
        self.assertFalse(graph.connected())

        graph.add_edge(2, 3)
        graph.add_edge(4, 1)
        self.assertTrue(graph.connected())

    def test_edges_complex(self):
        g = Graph()
        g.add_edge(1, 2)
        e = g.edge_by_node(1,2)
        g.hide_edge(e)
        g.hide_node(2)
        self.assertRaises(GraphError, g.restore_edge, e)

        g.restore_all_edges()
        self.assertRaises(GraphError, g.edge_by_id, e)

    def test_clust_coef(self):
        g = Graph()
        g.add_edge(1, 2)
        g.add_edge(1, 3)
        g.add_edge(1, 4)
        self.assertEqual(g.clust_coef(1), 0)

        g.add_edge(2, 5)
        g.add_edge(3, 5)
        g.add_edge(4, 5)
        self.assertEqual(g.clust_coef(1), 0)

        g.add_edge(2, 3)
        self.assertEqual(g.clust_coef(1), 1./6)
        g.add_edge(2, 4)
        self.assertEqual(g.clust_coef(1), 2./6)
        g.add_edge(4, 2)
        self.assertEqual(g.clust_coef(1), 3./6)

        g.add_edge(2, 3)
        g.add_edge(2, 4)
        g.add_edge(3, 4)
        g.add_edge(3, 2)
        g.add_edge(4, 2)
        g.add_edge(4, 3)
        self.assertEqual(g.clust_coef(1), 1)


    def test_get_hops(self):
        graph = Graph()
        graph.add_edge(1, 2)
        graph.add_edge(1, 3)
        graph.add_edge(2, 4)
        graph.add_edge(4, 5)
        graph.add_edge(5, 7)
        graph.add_edge(7, 8)

        self.assertEqual(graph.get_hops(1),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)])

        self.assertEqual(graph.get_hops(1, 5),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3)])

        graph.add_edge(5, 1)
        graph.add_edge(7, 1)
        graph.add_edge(7, 4)

        self.assertEqual(graph.get_hops(1),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)])

        # And the reverse graph
        graph = Graph()
        graph.add_edge(2, 1)
        graph.add_edge(3, 1)
        graph.add_edge(4, 2)
        graph.add_edge(5, 4)
        graph.add_edge(7, 5)
        graph.add_edge(8, 7)

        self.assertEqual(graph.get_hops(1, forward=False),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)])

        self.assertEqual(graph.get_hops(1, 5, forward=False),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3)])

        graph.add_edge(1, 5)
        graph.add_edge(1, 7)
        graph.add_edge(4, 7)

        self.assertEqual(graph.get_hops(1, forward=False),
            [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)])


    def test_constructor(self):
        graph = Graph(iter([
                (1, 2),
                (2, 3, 'a'),
                (1, 3),
                (3, 4),
            ]))
        self.assertEqual(graph.number_of_nodes(), 4)
        self.assertEqual(graph.number_of_edges(), 4)
        try:
            graph.edge_by_node(1,2)
            graph.edge_by_node(2,3)
            graph.edge_by_node(1,3)
            graph.edge_by_node(3,4)
        except GraphError:
            self.fail("Incorrect graph")

        self.assertEqual(graph.edge_data(graph.edge_by_node(2, 3)), 'a')

        self.assertRaises(GraphError, Graph, [(1,2,3,4)])

if __name__ == "__main__": # pragma: no cover
    unittest.main()
