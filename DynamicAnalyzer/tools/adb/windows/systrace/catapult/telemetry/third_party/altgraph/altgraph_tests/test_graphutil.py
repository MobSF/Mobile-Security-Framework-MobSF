import unittest
from altgraph import GraphUtil
from altgraph import Graph, GraphError

class TestGraphUtil (unittest.TestCase):

    def test_generate_random(self):
        g =  GraphUtil.generate_random_graph(10, 50)
        self.assertEqual(g.number_of_nodes(), 10)
        self.assertEqual(g.number_of_edges(), 50)

        seen = set()

        for e in g.edge_list():
            h, t = g.edge_by_id(e)
            self.assertFalse(h == t)
            self.assertTrue((h, t) not in seen)
            seen.add((h, t))

        g =  GraphUtil.generate_random_graph(5, 30, multi_edges=True)
        self.assertEqual(g.number_of_nodes(), 5)
        self.assertEqual(g.number_of_edges(), 30)

        seen = set()

        for e in g.edge_list():
            h, t = g.edge_by_id(e)
            self.assertFalse(h == t)
            if (h, t) in seen:
                break
            seen.add((h, t))

        else:
            self.fail("no duplicates?")

        g =  GraphUtil.generate_random_graph(5, 21, self_loops=True)
        self.assertEqual(g.number_of_nodes(), 5)
        self.assertEqual(g.number_of_edges(), 21)

        seen = set()

        for e in g.edge_list():
            h, t = g.edge_by_id(e)
            self.assertFalse((h, t) in seen)
            if h == t:
                break
            seen.add((h, t))

        else:
            self.fail("no self loops?")

        self.assertRaises(GraphError, GraphUtil.generate_random_graph, 5, 21)
        g = GraphUtil.generate_random_graph(5, 21, True)
        self.assertRaises(GraphError, GraphUtil.generate_random_graph, 5, 26, True)

    def test_generate_scale_free(self):
        graph = GraphUtil.generate_scale_free_graph(50, 10)
        self.assertEqual(graph.number_of_nodes(), 500)

        counts = {}
        for node in graph:
            degree = graph.inc_degree(node)
            try:
                counts[degree] += 1
            except KeyError:
                counts[degree] = 1

        total_counts = sum(counts.values())
        P = {}
        for degree, count in counts.items():
            P[degree] = count * 1.0 / total_counts

        # XXX: use algoritm <http://stackoverflow.com/questions/3433486/how-to-do-exponential-and-logarithmic-curve-fitting-in-python-i-found-only-polyn>
        # to check if P[degree] ~ degree ** G (for some G)

        #print sorted(P.items())

        #print sorted([(count, degree) for degree, count in counts.items()])

        #self.fail("missing tests for GraphUtil.generate_scale_free_graph")

    def test_filter_stack(self):
        g = Graph.Graph()
        g.add_node("1", "N.1")
        g.add_node("1.1", "N.1.1")
        g.add_node("1.1.1", "N.1.1.1")
        g.add_node("1.1.2", "N.1.1.2")
        g.add_node("1.1.3", "N.1.1.3")
        g.add_node("1.1.1.1", "N.1.1.1.1")
        g.add_node("1.1.1.2", "N.1.1.1.2")
        g.add_node("1.1.2.1", "N.1.1.2.1")
        g.add_node("1.1.2.2", "N.1.1.2.2")
        g.add_node("1.1.2.3", "N.1.1.2.3")
        g.add_node("2", "N.2")

        g.add_edge("1", "1.1")
        g.add_edge("1.1", "1.1.1")
        g.add_edge("1.1", "1.1.2")
        g.add_edge("1.1", "1.1.3")
        g.add_edge("1.1.1", "1.1.1.1")
        g.add_edge("1.1.1", "1.1.1.2")
        g.add_edge("1.1.2", "1.1.2.1")
        g.add_edge("1.1.2", "1.1.2.2")
        g.add_edge("1.1.2", "1.1.2.3")

        v, r, o =  GraphUtil.filter_stack(g, "1", [
            lambda n: n != "N.1.1.1", lambda n: n != "N.1.1.2.3" ])

        self.assertEqual(v,
            set(["1", "1.1", "1.1.1", "1.1.2", "1.1.3",
                "1.1.1.1", "1.1.1.2", "1.1.2.1", "1.1.2.2",
                "1.1.2.3"]))
        self.assertEqual(r, set([
                "1.1.1", "1.1.2.3"]))

        o.sort()
        self.assertEqual(o,
            [
                ("1.1", "1.1.1.1"),
                ("1.1", "1.1.1.2")
            ])

        v, r, o =  GraphUtil.filter_stack(g, "1", [
            lambda n: n != "N.1.1.1", lambda n: n != "N.1.1.1.2" ])

        self.assertEqual(v,
            set(["1", "1.1", "1.1.1", "1.1.2", "1.1.3",
                "1.1.1.1", "1.1.1.2", "1.1.2.1", "1.1.2.2",
                "1.1.2.3"]))
        self.assertEqual(r, set([
                "1.1.1", "1.1.1.2"]))

        self.assertEqual(o,
            [
                ("1.1", "1.1.1.1"),
            ])


if __name__ == "__main__": # pragma: no cover
    unittest.main()
