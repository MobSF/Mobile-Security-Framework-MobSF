"""Tests for def_use."""

import sys
sys.path.append('.')

import collections
import mock
import unittest
from androguard.decompiler.dad import dataflow
from androguard.decompiler.dad import graph
from androguard.decompiler.dad import node
from androguard.decompiler.dad import instruction
from androguard.decompiler.dad import basic_blocks


class DataflowTest(unittest.TestCase):

    def _CreateMockIns(self, uses, lhs=None):
        mock_ins = mock.create_autospec(instruction.IRForm)
        mock_ins.get_used_vars.return_value = uses
        mock_ins.get_lhs.return_value = lhs
        return mock_ins

    def _CreateMockNode(self, node_name, start_ins_idx, lins):
        mock_node = mock.create_autospec(
            basic_blocks.BasicBlock, _name=node_name)
        mock_node.__repr__ = mock.Mock(return_value=node_name)
        loc_ins = []
        ins_idx = start_ins_idx
        for ins in lins:
            uses, lhs = ins
            mock_ins = self._CreateMockIns(uses)
            mock_ins.get_lhs.return_value = lhs
            loc_ins.append((ins_idx, mock_ins))
            ins_idx += 1
        mock_node.get_loc_with_ins.return_value = loc_ins
        return mock_node

    def _CreateMockGraph(self, lparams, lidx_ins):
        entry = mock.create_autospec(basic_blocks.BasicBlock)
        rpo = [entry]
        node_num = 1
        for idx, lins in lidx_ins:
            rpo.append(self._CreateMockNode('n%d' % node_num, idx, lins))
            node_num += 1
        G = mock.create_autospec(graph.Graph)
        G.rpo = rpo
        return G

    """
      This tests the reach def analysis with:
            int GCD(int a, int b){
          node1:
            0.     int c = a;
            1.     int d = b;
          node2:
            2.     if(c == 0)
          node3:
            3.       ret = d; (goto 9.)
          node4:
            4.     while(d != 0){
          node5
            5.       if(c > d)
          node6:
            6.         c = c - d;
          node7:     else
            7.         d = d - c;
          node8:   }
            8.     ret = c;
          node9:
            9.     return ret;
            }
    """
    def testReachDefGCD(self):
        n1 = self._CreateMockNode('n1', 0, [(['a'], 'c'),
                                          (['b'], 'd')])
        n2 = self._CreateMockNode('n2', 2, [(['c'], None)])
        n3 = self._CreateMockNode('n3', 3, [(['d'], 'ret')])
        n4 = self._CreateMockNode('n4', 4, [(['d'], None)])
        n5 = self._CreateMockNode('n5', 5, [(['c', 'd'], None)])
        n6 = self._CreateMockNode('n6', 6, [(['c', 'd'], 'c')])
        n7 = self._CreateMockNode('n7', 7, [(['c', 'd'], 'd')])
        n8 = self._CreateMockNode('n8', 8, [(['c'], 'ret')])
        n9 = self._CreateMockNode('n9', 9, [(['ret'], None)])

        sucs = {n1: [n2], n2: [n3, n4], n3: [n9],
                n4: [n5, n8], n5: [n6, n7], n6: [n8],
                n7: [n8], n8: [n9]}
        preds = collections.defaultdict(list)
        for pred, lsucs in sucs.iteritems():
            for suc in lsucs:
                preds[suc].append(pred)

        def add_edge(x, y):
            sucs.setdefault(x, []).append(y)
            preds.setdefault(y, []).append(x)

        graph_mock = mock.create_autospec(graph.Graph)
        graph_mock.entry = n1
        graph_mock.exit = n9
        graph_mock.rpo = [n1, n2, n3, n4, n5, n6, n7, n8, n9]
        graph_mock.all_preds.side_effect = lambda x: preds[x]
        graph_mock.all_sucs.side_effect = lambda x: sucs.get(x, [])
        graph_mock.add_edge.side_effect = add_edge

        with mock.patch.object(dataflow, 'DummyNode') as dummynode_mock:
            dummy_entry_mock = mock.Mock(name='entry')
            dummy_exit_mock = mock.Mock(name='exit')
            for dummy_mock in dummy_entry_mock, dummy_exit_mock:
                dummy_mock.get_loc_with_ins.return_value = []
            dummynode_mock.side_effect = [dummy_entry_mock, dummy_exit_mock]
            analysis = dataflow.reach_def_analysis(graph_mock, set(['a', 'b']))
        expected_A = {dummy_entry_mock: set([-2, -1]),
                      n1: set([-2, -1, 0, 1]),
                      n2: set([-2, -1, 0, 1]),
                      n3: set([-2, -1, 0, 1, 3]),
                      n4: set([-2, -1, 0, 1]),
                      n5: set([-2, -1, 0, 1]),
                      n6: set([-2, -1, 1, 6]),
                      n7: set([-2, -1, 0, 7]),
                      n8: set([-2, -1, 0, 1, 6, 7, 8]),
                      n9: set([-2, -1, 0, 1, 3, 6, 7, 8]),
                      dummy_exit_mock: set([-2, -1, 0, 1, 3, 6, 7, 8])}
        expected_R = {n1: set([-2, -1]),
                      n2: set([-2, -1, 0, 1]),
                      n3: set([-2, -1, 0, 1]),
                      n4: set([-2, -1, 0, 1]),
                      n5: set([-2, -1, 0, 1]),
                      n6: set([-2, -1, 0, 1]),
                      n7: set([-2, -1, 0, 1]),
                      n8: set([-2, -1, 0, 1, 6, 7]),
                      n9: set([-2, -1, 0, 1, 3, 6, 7, 8]),
                      dummy_exit_mock: set([-2, -1, 0, 1, 3, 6, 7, 8])}
        expected_def_to_loc = {'a': set([-1]),
                              'b': set([-2]),
                              'c': set([0, 6]),
                              'd': set([1, 7]),
                              'ret': set([3, 8])}
        self.assertDictEqual(analysis.A, expected_A)
        self.assertDictEqual(analysis.R, expected_R)
        self.assertDictEqual(analysis.def_to_loc, expected_def_to_loc)

    @mock.patch.object(dataflow, 'reach_def_analysis')
    def testDefUseGCD(self, mock_reach_def):
        """Test def use with the GCD function above."""
        n1 = self._CreateMockNode('n1', 0, [(['a'], 'c'),
                                            (['b'], 'd')])
        n2 = self._CreateMockNode('n2', 2, [(['c'], None)])
        n3 = self._CreateMockNode('n3', 3, [(['d'], 'ret')])
        n4 = self._CreateMockNode('n4', 4, [(['d'], None)])
        n5 = self._CreateMockNode('n5', 5, [(['c', 'd'], None)])
        n6 = self._CreateMockNode('n6', 6, [(['c', 'd'], 'c')])
        n7 = self._CreateMockNode('n7', 7, [(['c', 'd'], 'd')])
        n8 = self._CreateMockNode('n8', 8, [(['c'], 'ret')])
        n9 = self._CreateMockNode('n9', 9, [(['ret'], None)])

        graph_mock = mock.create_autospec(graph.Graph)
        graph_mock.rpo = [n1, n2, n3, n4, n5, n6, n7, n8, n9]

        mock_analysis = mock_reach_def.return_value
        mock_analysis.def_to_loc = {'a': set([-1]), 'b': set([-2]),
                                    'c': set([0, 6]), 'd': set([1, 7]),
                                    'ret': set([3, 8])}
        mock_analysis.defs = {n1: {'c': set([0]), 'd': set([1])},
                              n2: {}, n3: {'ret': set([3])},
                              n4: {}, n5: {}, n6: {'c': set([6])},
                              n7: {'d': set([7])}, n8: {'ret': set([8])},
                              n9: {}}
        mock_analysis.R = {n1: set([-2, -1]),
                           n2: set([-2, -1, 0, 1]),
                           n3: set([-2, -1, 0, 1]),
                           n4: set([-2, -1, 0, 1]),
                           n5: set([-2, -1, 0, 1]),
                           n6: set([-2, -1, 0, 1]),
                           n7: set([-2, -1, 0, 1]),
                           n8: set([-2, -1, 0, 1, 6, 7]),
                           n9: set([-2, -1, 0, 1, 3, 6, 7, 8])}
        expected_du = {('a', -1): [0],
                       ('b', -2): [1],
                       ('c', 0): [2, 5, 6, 7, 8],
                       ('c', 6): [8],
                       ('d', 1): [3, 4, 5, 6, 7],
                       ('ret', 3): [9],
                       ('ret', 8): [9]}
        expected_ud = {('a', 0): [-1], ('b', 1): [-2],
                       ('c', 2): [0], ('c', 5): [0],
                       ('c', 6): [0], ('c', 7): [0],
                       ('c', 8): [0, 6], ('d', 3): [1],
                       ('d', 4): [1], ('d', 5): [1],
                       ('d', 6): [1], ('d', 7): [1],
                       ('ret', 9): [3, 8]}
        ud, du = dataflow.build_def_use(graph_mock, mock.sentinel)
        self.assertItemsEqual(du, expected_du)
        for entry in du:
            self.assertItemsEqual(du[entry], expected_du[entry])
        self.assertItemsEqual(ud, expected_ud)
        for entry in ud:
            self.assertItemsEqual(ud[entry], expected_ud[entry])

    @mock.patch.object(dataflow, 'reach_def_analysis')
    def testDefUseIfBool(self, mock_reach_def):
        n1 = self._CreateMockNode('n1', 0, [([], 0), ([2], None)])
        n2 = self._CreateMockNode('n1', 2, [([3], None)])
        n3 = self._CreateMockNode('n3', 3, [([3], None)])
        n4 = self._CreateMockNode('n4', 4, [([], 0)])
        n5 = self._CreateMockNode('n5', 5, [([0], 0)])
        n6 = self._CreateMockNode('n6', 6, [([2], 1),
                                            ([0, 1], 0)])
        n7 = self._CreateMockNode('n7', 8, [([0], None)])

        graph_mock = mock.create_autospec(graph.Graph)
        graph_mock.rpo = [n1, n2, n3, n4, n5, n6, n7]

        mock_analysis = mock_reach_def.return_value
        mock_analysis.def_to_loc = {0: set([0, 4, 5, 7]),
                                    1: set([6]),
                                    2: set([-1]),
                                    3: set([-2])}
        mock_analysis.defs = {n1: {0: set([0])},
                              n2: {},
                              n3: {},
                              n4: {0: set([4])},
                              n5: {0: set([5])},
                              n6: {0: set([7]), 1: set([6])},
                              n7: {}}

        mock_analysis.R = {n1: set([-1, -2]),
                           n2: set([0, -2, -1]),
                           n3: set([0, -1, -2]),
                           n4: set([0, -2, -1]),
                           n5: set([0, -2, -1]),
                           n6: set([0, -1, -2]),
                           n7: set([4, -1, 6, 7, -2, 5])}

        expected_du = {(0, 0): [7, 5],
                       (0, 4): [8],
                       (0, 5): [8],
                       (0, 7): [8],
                       (1, 6): [7],
                       (2, -1): [6, 1],
                       (3, -2): [2, 3]}
        expected_ud = {(0, 5): [0],
                       (0, 7): [0],
                       (0, 8): [4, 5, 7],
                       (1, 7): [6],
                       (2, 1): [-1],
                       (2, 6): [-1],
                       (3, 2): [-2],
                       (3, 3): [-2]}

        ud, du = dataflow.build_def_use(graph_mock, mock.sentinel)
        self.assertEqual(du, expected_du)
        self.assertEqual(ud, expected_ud)

    def testGroupVariablesGCD(self):
        du = {('a', -1): [0],
              ('b', -2): [1],
              ('c', 0): [2, 5, 6, 7, 8],
              ('c', 6): [8],
              ('d', 1): [3, 4, 5, 6, 7],
              ('ret', 3): [9],
              ('ret', 8): [9]}
        ud = {('a', 0): [-1], ('b', 1): [-2],
              ('c', 2): [0], ('c', 5): [0],
              ('c', 6): [0], ('c', 7): [0],
              ('c', 8): [0, 6], ('d', 3): [1],
              ('d', 4): [1], ('d', 5): [1],
              ('d', 6): [1], ('d', 7): [1],
              ('ret', 9): [3, 8]}
        expected_groups = {'a': [([-1], [0])],
                           'b': [([-2], [1])],
                           'c': [([0, 6], [8, 2, 5, 6, 7])],
                           'd': [([1], [3, 4, 5, 6, 7])],
                           'ret': [([3, 8], [9])]}
        groups = dataflow.group_variables(['a', 'b', 'c', 'd', 'ret'], du, ud)
        self.assertEqual(groups, expected_groups)

    def testGroupVariablesIfBool(self):
        du = {(0, 0): [7, 5],
              (0, 4): [8],
              (0, 5): [8],
              (0, 7): [8],
              (1, 6): [7],
              (2, -1): [6, 1],
              (3, -2): [2, 3]}
        ud = {(0, 5): [0],
              (0, 7): [0],
              (0, 8): [4, 5, 7],
              (1, 7): [6],
              (2, 1): [-1],
              (2, 6): [-1],
              (3, 2): [-2],
              (3, 3): [-2]}
        groups = dataflow.group_variables([0, 1, 2, 3], du, ud)
        expected_groups = {0: [([0], [5, 7]), ([4, 5, 7], [8])],
                           1: [([6], [7])],
                           2: [([-1], [1, 6])],
                           3: [([-2], [2, 3])]}
        self.assertItemsEqual(groups, expected_groups)
        for entry in groups:
            self.assertItemsEqual(groups[entry], expected_groups[entry])

    @mock.patch.object(dataflow, 'group_variables')
    def testSplitVariablesGCD(self, group_variables_mock):
        group = {'a': [([-1], [0])],
                 'b': [([-2], [1])],
                 'c': [([0, 6], [2, 5, 6, 7, 8])],
                 'd': [([1], [3, 4, 5, 6, 7])],
                 'ret': [([3, 8], [9])]}
        group_variables_mock.return_value = group
        dataflow.split_variables(
            mock.sentinel, [0, 1, 2, 3, 4], mock.sentinel, mock.sentinel)

    @mock.patch.object(dataflow, 'group_variables')
    def testSplitVariablesIfBool(self, group_variables_mock):
        group = {0: [([0], [5, 7]), ([4, 5, 7], [8])],
                 1: [([6], [7])],
                 2: [([-1], [1, 6])],
                 3: [([-2], [2, 3])]}
        group_variables_mock.return_value = group
        param1_mock = mock.Mock()
        param2_mock = mock.Mock()
        var0_mock = mock.Mock()
        var1_mock = mock.Mock()
        lvars = {0: var0_mock, 1: var1_mock, 2: param1_mock, 3: param2_mock}
        du = {(0, 0): [7, 5],
              (0, 4): [8],
              (0, 5): [8],
              (0, 7): [8],
              (1, 6): [7],
              (2, -1): [6, 1],
              (3, -2): [2, 3]}
        ud = {(0, 5): [0],
              (0, 7): [0],
              (0, 8): [4, 5, 7],
              (1, 7): [6],
              (2, 1): [-1],
              (2, 6): [-1],
              (3, 2): [-2],
              (3, 3): [-2]}
        graph_mock = mock.Mock()
        dataflow.split_variables(graph_mock, lvars, du, ud)

        expected_du = {(1, 6): [7],
                       (2, -1): [6, 1],
                       (3, -2): [2, 3],
                       (4, 0): [7, 5],
                       (5, 4): [8],
                       (5, 5): [8],
                       (5, 7): [8]}
        expected_ud = {(1, 7): [6],
                       (2, 1): [-1],
                       (2, 6): [-1],
                       (3, 2): [-2],
                       (3, 3): [-2],
                       (4, 5): [0],
                       (4, 7): [0],
                       (5, 8): [4, 5, 7]}
        self.assertEqual(du, expected_du)
        self.assertEqual(ud, expected_ud)


if __name__ == '__main__':
    unittest.main()
