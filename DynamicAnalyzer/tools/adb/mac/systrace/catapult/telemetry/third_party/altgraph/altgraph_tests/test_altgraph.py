#!/usr/bin/env py.test
import os
import sys

from altgraph import Graph, GraphAlgo
import unittest

class BasicTests (unittest.TestCase):
    def setUp(self):
        self.edges = [
            (1,2), (2,4), (1,3), (2,4), (3,4), (4,5), (6,5), (6,14), (14,15),
            (6, 15), (5,7), (7, 8), (7,13), (12,8), (8,13), (11,12), (11,9),
            (13,11), (9,13), (13,10)
        ]

        # these are the edges
        self.store = {}
        self.g = Graph.Graph()
        for head, tail in self.edges:
            self.store[head] = self.store[tail] = None
            self.g.add_edge(head, tail)

    def test_num_edges(self):
        # check the parameters
        self.assertEqual(self.g.number_of_nodes(), len(self.store))
        self.assertEqual(self.g.number_of_edges(), len(self.edges))

    def test_forw_bfs(self):
        # do a forward bfs
        self.assertEqual( self.g.forw_bfs(1),
                [1, 2, 3, 4, 5, 7, 8, 13, 11, 10, 12, 9])


    def test_get_hops(self):
        # diplay the hops and hop numbers between nodes
        self.assertEqual(self.g.get_hops(1, 8),
                [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3), (7, 4), (8, 5)])

    def test_shortest_path(self):
        self.assertEqual(GraphAlgo.shortest_path(self.g, 1, 12),
                [1, 2, 4, 5, 7, 13, 11, 12])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
