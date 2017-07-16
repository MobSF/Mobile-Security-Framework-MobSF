import unittest

from altgraph import GraphStat
from altgraph import Graph
import sys

class TestDegreesDist (unittest.TestCase):

    def test_simple(self):
        a = Graph.Graph()
        self.assertEqual(GraphStat.degree_dist(a), [])

        a.add_node(1)
        a.add_node(2)
        a.add_node(3)

        self.assertEqual(GraphStat.degree_dist(a), GraphStat._binning([0, 0, 0]))

        for x in range(100):
            a.add_node(x)

        for x in range(1, 100):
            for y in range(1, 50):
                if x % y == 0:
                    a.add_edge(x, y)

        counts_inc = []
        counts_out = []
        for n in a:
            counts_inc.append(a.inc_degree(n))
            counts_out.append(a.out_degree(n))

        self.assertEqual(GraphStat.degree_dist(a), GraphStat._binning(counts_out))
        self.assertEqual(GraphStat.degree_dist(a, mode='inc'), GraphStat._binning(counts_inc))

class TestBinning (unittest.TestCase):
    def test_simple(self):

        # Binning [0, 100) into 10 bins
        a = list(range(100))
        out = GraphStat._binning(a, limits=(0, 100), bin_num=10)

        self.assertEqual(out,
                [ (x*1.0, 10) for x in range(5, 100, 10) ])


        # Check that outliers are ignored.
        a = list(range(100))
        out = GraphStat._binning(a, limits=(0, 90), bin_num=9)

        self.assertEqual(out,
                [ (x*1.0, 10) for x in range(5, 90, 10) ])


        out = GraphStat._binning(a, limits=(0, 100), bin_num=15)
        binSize = 100 / 15.0
        result = [0]*15
        for i in range(100):
            bin = int(i/binSize)
            try:
                result[bin] += 1
            except IndexError:
                pass

        result = [ (i * binSize + binSize/2, result[i]) for i in range(len(result))]

        self.assertEqual(result, out)

if __name__ == "__main__": # pragma: no cover
    unittest.main()
