import unittest
import sys
from altgraph.ObjectGraph import ObjectGraph
from altgraph.Graph import Graph

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class Node (object):
    def __init__(self, graphident):
        self.graphident = graphident

class SubNode (Node):
    pass

class ArgNode (object):
    def __init__(self, graphident, *args, **kwds):
        self.graphident = graphident
        self.args = args
        self.kwds = kwds

    def __repr__(self):
        return '<ArgNode %s>'%(self.graphident,)

class TestObjectGraph (unittest.TestCase):

    def test_constructor(self):
        graph = ObjectGraph()
        self.assertTrue(isinstance(graph, ObjectGraph))

        g = Graph()
        graph = ObjectGraph(g)
        self.assertTrue(graph.graph is g)
        self.assertEqual(graph.debug, 0)
        self.assertEqual(graph.indent, 0)

        graph = ObjectGraph(debug=5)
        self.assertEqual(graph.debug, 5)

    def test_repr(self):
        graph = ObjectGraph()
        self.assertEqual(repr(graph), '<ObjectGraph>')


    def testNodes(self):
        graph = ObjectGraph()
        n1 = Node("n1")
        n2 = Node("n2")
        n3 = Node("n3")
        n4 = Node("n4")

        n1b = Node("n1")

        self.assertTrue(graph.getIdent(graph)  is graph)
        self.assertTrue(graph.getRawIdent(graph)  is graph)

        graph.addNode(n1)
        graph.addNode(n2)
        graph.addNode(n3)

        self.assertTrue(n1 in graph)
        self.assertFalse(n4 in graph)
        self.assertTrue("n1" in graph)
        self.assertFalse("n4" in graph)

        self.assertTrue(graph.findNode(n1) is n1)
        self.assertTrue(graph.findNode(n1b) is n1)
        self.assertTrue(graph.findNode(n2) is n2)
        self.assertTrue(graph.findNode(n4) is None)
        self.assertTrue(graph.findNode("n1") is n1)
        self.assertTrue(graph.findNode("n2") is n2)
        self.assertTrue(graph.findNode("n4") is None)

        self.assertEqual(graph.getRawIdent(n1), "n1")
        self.assertEqual(graph.getRawIdent(n1b), "n1")
        self.assertEqual(graph.getRawIdent(n4), "n4")
        self.assertEqual(graph.getRawIdent("n1"), None)

        self.assertEqual(graph.getIdent(n1), "n1")
        self.assertEqual(graph.getIdent(n1b), "n1")
        self.assertEqual(graph.getIdent(n4), "n4")
        self.assertEqual(graph.getIdent("n1"), "n1")

        self.assertTrue(n3 in graph)
        graph.removeNode(n3)
        self.assertTrue(n3 not in graph)
        graph.addNode(n3)
        self.assertTrue(n3 in graph)

        n = graph.createNode(SubNode, "n1")
        self.assertTrue(n is n1)

        n = graph.createNode(SubNode, "n8")
        self.assertTrue(isinstance(n, SubNode))
        self.assertTrue(n in graph)
        self.assertTrue(graph.findNode("n8") is n)

        n = graph.createNode(ArgNode, "args", 1, 2, 3, a='a', b='b')
        self.assertTrue(isinstance(n, ArgNode))
        self.assertTrue(n in graph)
        self.assertTrue(graph.findNode("args") is n)
        self.assertEqual(n.args, (1, 2, 3))
        self.assertEqual(n.kwds, {'a':'a', 'b':'b'})

    def testEdges(self):
        graph = ObjectGraph()
        n1 = graph.createNode(ArgNode, "n1", 1)
        n2 = graph.createNode(ArgNode, "n2", 1)
        n3 = graph.createNode(ArgNode, "n3", 1)
        n4 = graph.createNode(ArgNode, "n4", 1)

        graph.createReference(n1, n2, "n1-n2")
        graph.createReference("n1", "n3", "n1-n3")
        graph.createReference("n2", n3)

        g = graph.graph
        e = g.edge_by_node("n1", "n2")
        self.assertTrue(e is not None)
        self.assertEqual(g.edge_data(e), "n1-n2")

        e = g.edge_by_node("n1", "n3")
        self.assertTrue(e is not None)
        self.assertEqual(g.edge_data(e), "n1-n3")

        e = g.edge_by_node("n2", "n3")
        self.assertTrue(e is not None)
        self.assertEqual(g.edge_data(e), None)

        e = g.edge_by_node("n1", "n4")
        self.assertTrue(e is None)

        graph.removeReference(n1, n2)
        e = g.edge_by_node("n1", "n2")
        self.assertTrue(e is None)

        graph.removeReference("n1", "n3")
        e = g.edge_by_node("n1", "n3")
        self.assertTrue(e is None)

        graph.createReference(n1, n2, "foo")
        e = g.edge_by_node("n1", "n2")
        self.assertTrue(e is not None)
        self.assertEqual(g.edge_data(e), "foo")


    def test_flatten(self):
        graph = ObjectGraph()
        n1 = graph.createNode(ArgNode, "n1", 1)
        n2 = graph.createNode(ArgNode, "n2", 2)
        n3 = graph.createNode(ArgNode, "n3", 3)
        n4 = graph.createNode(ArgNode, "n4", 4)
        n5 = graph.createNode(ArgNode, "n5", 5)
        n6 = graph.createNode(ArgNode, "n6", 6)
        n7 = graph.createNode(ArgNode, "n7", 7)
        n8 = graph.createNode(ArgNode, "n8", 8)

        graph.createReference(graph, n1)
        graph.createReference(graph, n7)
        graph.createReference(n1, n2)
        graph.createReference(n1, n4)
        graph.createReference(n2, n3)
        graph.createReference(n2, n5)
        graph.createReference(n5, n6)
        graph.createReference(n4, n6)
        graph.createReference(n4, n2)

        self.assertFalse(isinstance(graph.flatten(), list))

        fl = list(graph.flatten())
        self.assertTrue(n1 in fl)
        self.assertTrue(n2 in fl)
        self.assertTrue(n3 in fl)
        self.assertTrue(n4 in fl)
        self.assertTrue(n5 in fl)
        self.assertTrue(n6 in fl)
        self.assertTrue(n7 in fl)
        self.assertFalse(n8 in fl)

        fl = list(graph.flatten(start=n2))
        self.assertFalse(n1 in fl)
        self.assertTrue(n2 in fl)
        self.assertTrue(n3 in fl)
        self.assertFalse(n4 in fl)
        self.assertTrue(n5 in fl)
        self.assertTrue(n6 in fl)
        self.assertFalse(n7 in fl)
        self.assertFalse(n8 in fl)

        graph.createReference(n1, n5)
        fl = list(graph.flatten(lambda n: n.args[0] % 2 != 0))
        self.assertTrue(n1 in fl)
        self.assertFalse(n2 in fl)
        self.assertFalse(n3 in fl)
        self.assertFalse(n4 in fl)
        self.assertTrue(n5 in fl)
        self.assertFalse(n6 in fl)
        self.assertTrue(n7 in fl)
        self.assertFalse(n8 in fl)

    def test_iter_nodes(self):
        graph = ObjectGraph()
        n1 = graph.createNode(ArgNode, "n1", 1)
        n2 = graph.createNode(ArgNode, "n2", 2)
        n3 = graph.createNode(ArgNode, "n3", 3)
        n4 = graph.createNode(ArgNode, "n4", 4)
        n5 = graph.createNode(ArgNode, "n5", 5)
        n6 = graph.createNode(ArgNode, "n6", 5)

        nodes = graph.nodes()
        if sys.version[0] == '2':
            self.assertTrue(hasattr(nodes, 'next'))
        else:
            self.assertTrue(hasattr(nodes, '__next__'))
        self.assertTrue(hasattr(nodes, '__iter__'))

        nodes = list(nodes)
        self.assertEqual(len(nodes), 6)
        self.assertTrue(n1 in nodes)
        self.assertTrue(n2 in nodes)
        self.assertTrue(n3 in nodes)
        self.assertTrue(n4 in nodes)
        self.assertTrue(n5 in nodes)
        self.assertTrue(n6 in nodes)

    def test_get_edges(self):
        graph = ObjectGraph()
        n1 = graph.createNode(ArgNode, "n1", 1)
        n2 = graph.createNode(ArgNode, "n2", 2)
        n3 = graph.createNode(ArgNode, "n3", 3)
        n4 = graph.createNode(ArgNode, "n4", 4)
        n5 = graph.createNode(ArgNode, "n5", 5)
        n6 = graph.createNode(ArgNode, "n6", 5)

        graph.createReference(n1, n2)
        graph.createReference(n1, n3)
        graph.createReference(n3, n1)
        graph.createReference(n5, n1)
        graph.createReference(n2, n4)
        graph.createReference(n2, n5)
        graph.createReference(n6, n2)

        outs, ins = graph.get_edges(n1)

        self.assertFalse(isinstance(outs, list))
        self.assertFalse(isinstance(ins, list))

        ins = list(ins)
        outs = list(outs)


        self.assertTrue(n1 not in outs)
        self.assertTrue(n2 in outs)
        self.assertTrue(n3 in outs)
        self.assertTrue(n4 not in outs)
        self.assertTrue(n5 not in outs)
        self.assertTrue(n6 not in outs)

        self.assertTrue(n1 not in ins)
        self.assertTrue(n2 not in ins)
        self.assertTrue(n3 in ins)
        self.assertTrue(n4 not in ins)
        self.assertTrue(n5 in ins)
        self.assertTrue(n6 not in ins)

    def test_filterStack(self):
        graph = ObjectGraph()
        n1 = graph.createNode(ArgNode, "n1", 0)
        n11 = graph.createNode(ArgNode, "n1.1", 1)
        n12 = graph.createNode(ArgNode, "n1.2", 0)
        n111 = graph.createNode(ArgNode, "n1.1.1", 0)
        n112 = graph.createNode(ArgNode, "n1.1.2",2)
        n2 = graph.createNode(ArgNode, "n2", 0)
        n3 = graph.createNode(ArgNode, "n2", 0)

        graph.createReference(None, n1)
        graph.createReference(None, n2)
        graph.createReference(n1, n11)
        graph.createReference(n1, n12)
        graph.createReference(n11, n111)
        graph.createReference(n11, n112)

        self.assertTrue(n1 in graph)
        self.assertTrue(n2 in graph)
        self.assertTrue(n11 in graph)
        self.assertTrue(n12 in graph)
        self.assertTrue(n111 in graph)
        self.assertTrue(n112 in graph)
        self.assertTrue(n2 in graph)
        self.assertTrue(n3 in graph)

        visited, removes, orphans = graph.filterStack(
                [lambda n: n.args[0] != 1, lambda n: n.args[0] != 2])

        self.assertEqual(visited, 6)
        self.assertEqual(removes, 2)
        self.assertEqual(orphans, 1)

        e = graph.graph.edge_by_node(n1.graphident, n111.graphident)
        self.assertEqual(graph.graph.edge_data(e), "orphan")

        self.assertTrue(n1 in graph)
        self.assertTrue(n2 in graph)
        self.assertTrue(n11 not in graph)
        self.assertTrue(n12 in graph)
        self.assertTrue(n111 in graph)
        self.assertTrue(n112 not in graph)
        self.assertTrue(n2 in graph)
        self.assertTrue(n3 in graph)


class TestObjectGraphIO (unittest.TestCase):
    def setUp(self):
        self._stdout = sys.stdout

    def tearDown(self):
        sys.stdout = self._stdout

    def test_msg(self):
        graph = ObjectGraph()

        sys.stdout = fp = StringIO()
        graph.msg(0, "foo")
        self.assertEqual(fp.getvalue(), "foo \n")

        sys.stdout = fp = StringIO()
        graph.msg(5, "foo")
        self.assertEqual(fp.getvalue(), "")

        sys.stdout = fp = StringIO()
        graph.debug = 10
        graph.msg(5, "foo")
        self.assertEqual(fp.getvalue(), "foo \n")

        sys.stdout = fp = StringIO()
        graph.msg(0, "foo", 1, "a")
        self.assertEqual(fp.getvalue(), "foo 1 'a'\n")

        sys.stdout = fp = StringIO()
        graph.msgin(0, "hello", "world")
        graph.msg(0, "test me")
        graph.msgout(0, "bye bye")
        self.assertEqual(fp.getvalue(), "hello 'world'\n  test me \nbye bye \n")


if __name__ == "__main__": # pragma: no cover
    unittest.main()
