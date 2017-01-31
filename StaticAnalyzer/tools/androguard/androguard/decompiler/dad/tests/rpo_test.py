"""Tests for rpo."""

import sys
sys.path.append('.')

import unittest
from androguard.decompiler.dad import graph
from androguard.decompiler.dad import node


class NodeTest(node.Node):
    def __init__(self, name):
        super(NodeTest, self).__init__(name)

    def __str__(self):
        return '%s (%d)' % (self.name, self.num)


class RpoTest(unittest.TestCase):
    def _getNode(self, node_map, n):
        ret_node = node_map.get(n)
        if not ret_node:
            ret_node = node_map[n] = NodeTest(n)
            self.graph.add_node(ret_node)
        return ret_node

    def _createGraphFrom(self, edges):
        node_map = {}
        for n, childs in edges.iteritems():
            if n is None:
                continue
            parent_node = self._getNode(node_map, n)
            for child in childs:
                child_node = self._getNode(node_map, child)
                self.graph.add_edge(parent_node, child_node)
        self.graph.entry = node_map[edges[None]]
        return node_map

    def _verifyRpo(self, node_map, expected_rpo):
        for n1, n2 in expected_rpo.iteritems():
            self.assertEqual(node_map[n1].num, n2)

    def setUp(self):
        self.graph = graph.Graph()

    def tearDown(self):
        self.graph = None

    def testTarjanGraph(self):
        edges = {None: 'r',
                'r': ['a', 'b', 'c'],
                'a': ['d'],
                'b': ['a', 'd', 'e'],
                'c': ['f', 'g'],
                'd': ['l'],
                'e': ['h'],
                'f': ['i'],
                'g': ['i', 'j'],
                'h': ['e', 'k'],
                'i': ['k'],
                'j': ['i'],
                'k': ['i', 'r'],
                'l': ['h']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testTarjan_graph', '/tmp')
        expected_rpo = {'r': 1, 'a': 7, 'b': 6, 'c': 2,
                        'd': 8, 'e': 13, 'f': 5,
                        'g': 3, 'h': 10, 'i': 12,
                        'j': 4, 'k': 11, 'l': 9}
        self._verifyRpo(n_map, expected_rpo)

    def testFirstGraph(self):
        edges = {None: 'r',
                'r': ['w1', 'x1', 'z5'],
                'w1': ['w2'], 'w2': ['w3'],
                'w3': ['w4'], 'w4': ['w5'],
                'x1': ['x2'], 'x2': ['x3'],
                'x3': ['x4'], 'x4': ['x5'], 'x5': ['y1'],
                'y1': ['w1', 'w2', 'w3', 'w4', 'w5', 'y2'],
                'y2': ['w1', 'w2', 'w3', 'w4', 'w5', 'y3'],
                'y3': ['w1', 'w2', 'w3', 'w4', 'w5', 'y4'],
                'y4': ['w1', 'w2', 'w3', 'w4', 'w5', 'y5'],
                'y5': ['w1', 'w2', 'w3', 'w4', 'w5', 'z1'],
                'z1': ['z2'],
                'z2': ['z1', 'z3'],
                'z3': ['z2', 'z4'],
                'z4': ['z3', 'z5'],
                'z5': ['z4']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testFirst_graph', '/tmp')
        expected_rpo = {'r': 1, 'x1': 2, 'x2': 3, 'x3': 4, 'x4': 5, 'x5': 6,
                        'w1': 17, 'w2': 18, 'w3': 19, 'w4': 20, 'w5': 21,
                        'y1': 7, 'y2': 8, 'y3': 9, 'y4': 10, 'y5': 11,
                        'z1': 12, 'z2': 13, 'z3': 14, 'z4': 15, 'z5': 16}
        self._verifyRpo(n_map, expected_rpo)

    def testSecondGraph(self):
        edges = {None: 'r',
                'r': ['y1', 'x12'],
                'x11': ['x12', 'x22'],
                'x12': ['x11'],
                'x21': ['x22'],
                'x22': ['x21'],
                'y1': ['y2', 'x11'],
                'y2': ['x21']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testSecond_graph', '/tmp')
        expected_rpo = {'r': 1, 'x11': 3, 'x12': 4, 'x21': 6, 'x22': 7,
                        'y1': 2, 'y2': 5}
        self._verifyRpo(n_map, expected_rpo)

    def testThirdGraph(self):
        edges = {None: 'r',
                'r': ['w', 'y1'],
                'w': ['x1', 'x2'],
                'x2': ['x1'],
                'y1': ['y2'],
                'y2': ['x2']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        ##self.graph.draw('_testThird_graph', '/tmp')
        expected_rpo = {'r': 1, 'w': 4, 'x1': 6, 'x2': 5, 'y1': 2, 'y2': 3}
        self._verifyRpo(n_map, expected_rpo)

    def testFourthGraph(self):
        edges = {None: 'r',
                'r': ['x1', 'y1', 'y2'],
                'x1': ['x2'],
                'x2': ['y1', 'y2']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testFourth_graph', '/tmp')
        expected_rpo = {'r': 1, 'x1': 2, 'x2': 3, 'y1': 5, 'y2': 4}
        self._verifyRpo(n_map, expected_rpo)

    def testFifthGraph(self):
        edges = {None: 'r',
                'r': ['a', 'i'],
                'a': ['b', 'c'],
                'b': ['c', 'e', 'g'],
                'c': ['d'],
                'd': ['i'],
                'e': ['c', 'f'],
                'f': ['i'],
                'g': ['h'],
                'h': ['d', 'f', 'i']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testFifth_graph', '/tmp')
        expected_rpo = {'r': 1, 'a': 2, 'b': 3, 'c': 8,
                        'd': 9, 'e': 6, 'f': 7, 'g': 4,
                        'h': 5, 'i': 10}
        self._verifyRpo(n_map, expected_rpo)

    def testLinearVitGraph(self):
        edges = {None: 'r',
                'r': ['w', 'y'],
                'w': ['x1'],
                'y': ['x7'],
                'x1': ['x2'],
                'x2': ['x1', 'x3'],
                'x3': ['x2', 'x4'],
                'x4': ['x3', 'x5'],
                'x5': ['x4', 'x6'],
                'x6': ['x5', 'x7'],
                'x7': ['x6']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testLinearVit_graph', '/tmp')
        expected_rpo = {'r': 1, 'w': 3, 'x1': 4, 'x2': 5, 'x3': 6,
                        'x4': 7, 'x5': 8, 'x6': 9, 'x7': 10, 'y': 2}
        self._verifyRpo(n_map, expected_rpo)

    def testCrossGraph(self):
        edges = {None: 'r',
                'r': ['a', 'd'],
                'a': ['b'],
                'b': ['c'],
                'c': ['a', 'd', 'g'],
                'd': ['e'],
                'e': ['f'],
                'f': ['a', 'd', 'g']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testCross_graph', '/tmp')
        expected_rpo = {'r': 1, 'a': 2, 'b': 3, 'c': 4,
                        'd': 5, 'e': 6, 'f': 7, 'g': 8}
        self._verifyRpo(n_map, expected_rpo)

    def testTVerifyGraph(self):
        edges = {None: 'n1',
                'n1': ['n2', 'n8'],
                'n2': ['n3'],
                'n3': ['n4', 'n8', 'n9'],
                'n4': ['n3', 'n5', 'n6', 'n7'],
                'n5': ['n4'],
                'n6': ['n5'],
                'n7': ['n6'],
                'n8': ['n9', 'n12'],
                'n9': ['n10', 'n11', 'n12'],
                'n10': ['n11'],
                'n11': ['n7'],
                'n12': ['n10']}
        n_map = self._createGraphFrom(edges)
        self.graph.compute_rpo()
        #self.graph.draw('_testTVerify_graph', '/tmp')
        expected_rpo = {'n1': 1, 'n2': 2, 'n3': 3,
                        'n4': 9, 'n5': 12, 'n6': 11,
                        'n7': 10, 'n8': 4, 'n9': 5,
                        'n10': 7, 'n11': 8, 'n12': 6}
        self._verifyRpo(n_map, expected_rpo)

if __name__ == '__main__':
    unittest.main()
