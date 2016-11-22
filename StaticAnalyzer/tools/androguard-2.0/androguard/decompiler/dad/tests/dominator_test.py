"""Tests for graph."""

import sys
sys.path.append('.')

import unittest
from androguard.decompiler.dad import graph
from androguard.decompiler.dad import node


class DominatorTest(unittest.TestCase):

    def setUp(self):
        self.graph = graph.Graph()

    def tearDown(self):
        self.graph = None

    def testTarjanGraph(self):
        edges = {'r': ['a', 'b', 'c'],
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
        expected_dominators = {
            'r': None,
            'a': 'r', 'b': 'r', 'c': 'r',
            'd': 'r', 'e': 'r', 'f': 'c',
            'g': 'c', 'h': 'r', 'i': 'r',
            'j': 'g', 'k': 'r', 'l': 'd'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testFirstGraph(self):
        edges = {
          'r': ['w1', 'x1', 'z5'],
          'w1': ['w2'], 'w2': ['w3'], 'w3': ['w4'], 'w4': ['w5'],
          'x1': ['x2'], 'x2': ['x3'], 'x3': ['x4'], 'x4': ['x5'], 'x5': ['y1'],
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
        expected_dominators = {
            'r': None,
            'w1': 'r', 'w2': 'r', 'w3': 'r', 'w4': 'r', 'w5': 'r',
            'x1': 'r', 'x2': 'x1', 'x3': 'x2', 'x4': 'x3', 'x5': 'x4',
            'y1': 'x5', 'y2': 'y1', 'y3': 'y2', 'y4': 'y3', 'y5': 'y4',
            'z1': 'r', 'z2': 'r', 'z3': 'r', 'z4': 'r', 'z5': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testSecondGraph(self):
        edges = {'r': ['y1', 'x12'],
                 'y1': ['y2', 'x11'],
                 'y2': ['x21'],
                 'x11': ['x12', 'x22'],
                 'x12': ['x11'],
                 'x21': ['x22'],
                 'x22': ['x21']}
        expected_dominators = {
            'r': None,
            'y1': 'r', 'y2': 'y1',
            'x11': 'r', 'x12': 'r',
            'x21': 'r', 'x22': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testThirdGraph(self):
        edges = {'r': ['w', 'y1'],
                 'w': ['x1', 'x2'],
                 'y1': ['y2'],
                 'y2': ['x2'],
                 'x2': ['x1']}
        expected_dominators = {
            'r': None,
            'w': 'r', 'x1': 'r', 'y1': 'r',
            'y2': 'y1', 'x1': 'r', 'x2': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testFourthGraph(self):
        edges = {'r': ['x1', 'y1', 'y2'],
                 'x1': ['x2'],
                 'x2': ['y1', 'y2']}
        expected_dominators = {
            'r': None,
            'x1': 'r', 'x2': 'x1',
            'y1': 'r', 'y2': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testFifthGraph(self):
        edges = {'r': ['a', 'i'],
                 'a': ['b', 'c'],
                 'b': ['c', 'e', 'g'],
                 'c': ['d'],
                 'd': ['i'],
                 'e': ['c', 'f'],
                 'f': ['i'],
                 'g': ['h'],
                 'h': ['d', 'f', 'i']}
        expected_dominators = {
            'r': None,
            'a': 'r', 'b': 'a', 'c': 'a',
            'd': 'a', 'e': 'b', 'f': 'b',
            'g': 'b', 'h': 'g', 'i': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testLinearVitGraph(self):
        edges = {'r': ['w', 'y'],
                 'w': ['x1'],
                 'y': ['x7'],
                 'x1': ['x2'],
                 'x2': ['x1', 'x3'],
                 'x3': ['x2', 'x4'],
                 'x4': ['x3', 'x5'],
                 'x5': ['x4', 'x6'],
                 'x6': ['x5', 'x7'],
                 'x7': ['x6']}
        expected_dominators = {
            'r': None,
            'w': 'r', 'y': 'r',
            'x1': 'r', 'x2': 'r', 'x3': 'r',
            'x4': 'r', 'x5': 'r', 'x6': 'r',
            'x7': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testCrossGraph(self):
        edges = {'r': ['a', 'd'],
                 'a': ['b'],
                 'b': ['c'],
                 'c': ['a', 'd', 'g'],
                 'd': ['e'],
                 'e': ['f'],
                 'f': ['a', 'd', 'g']}
        expected_dominators = {'r': None,
                    'a': 'r', 'b': 'a', 'c': 'b',
                    'd': 'r', 'e': 'd', 'f': 'e',
                    'g': 'r'}
        self.graph.entry = 'r'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

    def testTVerifyGraph(self):
        edges = {'n1': ['n2', 'n8'],
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
        expected_dominators = {
            'n1': None,
            'n2': 'n1', 'n3': 'n1', 'n4': 'n1',
            'n5': 'n1', 'n6': 'n1', 'n7': 'n1',
            'n8': 'n1', 'n9': 'n1', 'n10': 'n1',
            'n11': 'n1', 'n12': 'n1'}
        self.graph.entry = 'n1'
        self.graph.edges = edges
        self.graph.nodes = expected_dominators.keys()
        self.assertEqual(
            expected_dominators, self.graph.immediate_dominators())

if __name__ == '__main__':
    unittest.main()
