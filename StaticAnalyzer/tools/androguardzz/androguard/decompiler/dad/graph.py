# This file is part of Androguard.
#
# Copyright (c) 2012 Geoffroy Gueguen <geoffroy.gueguen@gmail.com>
# All Rights Reserved.
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

import logging
from androguard.decompiler.dad.basic_blocks import (build_node_from_block,
                                                    StatementBlock, CondBlock,
                                                    GenInvokeRetName)
from androguard.decompiler.dad.util import common_dom


logger = logging.getLogger('dad.graph')


class Graph():
    def __init__(self):
        self.entry = None
        self.exit = None
        self.nodes = set()
        self.rpo = []
        self.edges = {}
        self.reverse_edges = {}
        self.loc_to_ins = None
        self.loc_to_node = None

    def get_entry(self):
        return self.entry

    def get_exit(self):
        return self.exit

    def set_entry(self, node):
        self.entry = node

    def set_exit(self, node):
        self.exit = node

    def sucs(self, node):
        return self.edges.get(node, [])

    def preds(self, node):
        return self.reverse_edges.get(node, [])

    def get_rpo(self):
        return self.rpo

    def add_node(self, node):
        self.nodes.add(node)

    def add_edge(self, e1, e2):
        lsucs = self.edges.setdefault(e1, [])
        if e2 not in lsucs:
            lsucs.append(e2)
        lpreds = self.reverse_edges.setdefault(e2, [])
        if e1 not in lpreds:
            lpreds.append(e1)

    def remove_node(self, node):
        preds = self.reverse_edges.pop(node, [])
        for pred in preds:
            self.edges[pred].remove(node)

        succs = self.edges.get(node, [])
        for suc in succs:
            self.reverse_edges[suc].remove(node)

        self.nodes.remove(node)
        if node in self.rpo:
            self.rpo.remove(node)
        del node

    def number_ins(self):
        self.loc_to_ins = {}
        self.loc_to_node = {}
        num = 0
        for node in self.rpo:
            start_node = num
            num = node.number_ins(num)
            end_node = num - 1
            self.loc_to_ins.update(node.get_loc_with_ins())
            self.loc_to_node[(start_node, end_node)] = node

    def get_ins_from_loc(self, loc):
        return self.loc_to_ins.get(loc)

    def get_node_from_loc(self, loc):
        for (start, end), node in self.loc_to_node.iteritems():
            if start <= loc <= end:
                return node

    def remove_ins(self, loc):
        ins = self.get_ins_from_loc(loc)
        self.get_node_from_loc(loc).remove_ins(loc, ins)
        self.loc_to_ins.pop(loc)

    def split_if_nodes(self):
        '''
        Split IfNodes in two nodes, the first node is the header node, the
        second one is only composed of the jump condition.
        '''
        node_map = {}
        to_update = set()
        for node in self.nodes.copy():
            if node.is_cond():
                if len(node.get_ins()) > 1:
                    pre_ins = node.get_ins()[:-1]
                    last_ins = node.get_ins()[-1]
                    pre_node = StatementBlock('%s-pre' % node.name, pre_ins)
                    cond_node = CondBlock('%s-cond' % node.name, [last_ins])
                    node_map[node] = pre_node

                    pre_node.copy_from(node)
                    cond_node.copy_from(node)
                    pre_node.set_stmt()
                    cond_node.set_true(node.true)
                    cond_node.set_false(node.false)

                    lpreds = self.preds(node)
                    lsuccs = self.sucs(node)

                    for pred in lpreds:
                        pred_node = node_map.get(pred, pred)
                        if pred is node:
                            pred_node = cond_node
                        if pred.is_cond():  # and not (pred is node):
                            if pred.true is node:
                                pred_node.set_true(pre_node)
                            if pred.false is node:
                                pred_node.set_false(pre_node)
                        self.add_edge(pred_node, pre_node)
                    for suc in lsuccs:
                        self.add_edge(cond_node, node_map.get(suc, suc))

                    if node is self.entry:
                        self.set_entry(pre_node)

                    self.add_node(pre_node)
                    self.add_node(cond_node)
                    self.add_edge(pre_node, cond_node)
                    pre_node.update_attribute_with(node_map)
                    cond_node.update_attribute_with(node_map)
                    self.remove_node(node)
            else:
                to_update.add(node)
        for node in to_update:
            node.update_attribute_with(node_map)

    def simplify(self):
        '''
        Simplify the CFG by merging/deleting statement nodes when possible:
        If statement B follows statement A and if B has no other predecessor
        besides A, then we can merge A and B into a new statement node.
        We also remove nodes which do nothing except redirecting the control
        flow (nodes which only contains a goto).
        '''
        redo = True
        while redo:
            redo = False
            for node in self.nodes.copy():
                if node.is_stmt() and node in self.nodes:
                    suc = self.sucs(node)[0]
                    if len(node.get_ins()) == 0:
                        suc = self.edges.get(node)[0]
                        if node is suc:
                            continue
                        node_map = {node: suc}
                        for pred in self.preds(node):
                            pred.update_attribute_with(node_map)
                            self.add_edge(pred, suc)
                        redo = True
                        if node is self.entry:
                            self.entry = suc
                        self.remove_node(node)
                    elif (suc.is_stmt() and len(self.preds(suc)) == 1
                            and not ((node is suc) or (suc is self.entry))):
                        ins_to_merge = suc.get_ins()
                        node.add_ins(ins_to_merge)
                        new_suc = self.sucs(suc)[0]
                        if new_suc:
                            self.add_edge(node, new_suc)
                        redo = True
                        self.remove_node(suc)

    def _traverse(self, node, visit, res):
        if node in visit:
            return
        visit.add(node)
        for suc in self.sucs(node):
            self._traverse(suc, visit, res)
        res.insert(0, node)

    def compute_rpo(self):
        '''
        Number the nodes in reverse post order.
        An RPO traversal visit as many predecessors of a node as possible
        before visiting the node itself.
        If reverse is True, the RPO is done on the reverse graph.
        '''
        visit = set()
        res = []
        self._traverse(self.entry, visit, res)
        for i, n in enumerate(res, 1):
            n.num = i
            self.rpo.append(n)

    def reset_rpo(self):
        self.rpo = []
        self.compute_rpo()

    def post_order(self, start=None, visited=None, res=None):
        '''
        Return the nodes of the graph in post-order i.e we visit all the
        children of a node before visiting the node itself.
        '''
        if visited is None:
            res = []
            visited = set()
            start = self.entry
        visited.add(start)
        for suc in self.sucs(start):
            if not suc in visited:
                self.post_order(suc, visited, res)
        res.append(start)
        return res

    def draw(self, name, dname, draw_branches=True):
        import pydot
        g = pydot.Dot()
        g.set_node_defaults(**{'color': 'lightgray', 'style': 'filled',
                    'shape': 'box', 'fontname': 'Courier', 'fontsize': '10'})
        for node in sorted(self.nodes, key=lambda x: x.num):
            if draw_branches and node.is_cond():
                edge_true = pydot.Edge(str(node), str(node.true))
                edge_false = pydot.Edge(str(node), str(node.false))
                edge_true.set_color('green')
                edge_false.set_color('red')
                g.add_edge(edge_true)
                g.add_edge(edge_false)
            else:
                succs = self.sucs(node)
                for suc in succs:
                    edge = pydot.Edge(str(node), str(suc))
                    edge.set_color('blue')
                    g.add_edge(edge)
        g.write_png('%s/%s.png' % (dname, name))

    def immediate_dominators(self):
        '''
        Create a mapping of the nodes of a graph with their corresponding
        immediate dominator
        '''
        idom = dict((n, None) for n in self.nodes)
        for node in self.get_rpo():
            for pred in self.preds(node):
                if pred.num < node.num:
                    idom[node] = common_dom(idom, idom[node], pred)
        return idom

    def dominator_tree(self, immediate_dominators):
        dom_tree = Graph()
        for n, idom_n in immediate_dominators.items():
            dom_tree.add_node(n)
            if idom_n:
                dom_tree.add_edge(idom_n, n)
        dom_tree.set_entry(self.entry)
        dom_tree.set_exit(self.exit)
        return dom_tree

    def __len__(self):
        return len(self.nodes)

    def __repr__(self):
        return str(self.nodes)

    def __iter__(self):
        for node in self.nodes:
            yield node


def bfs(start):
    to_visit = [start]
    visited = set([start])
    while to_visit:
        node = to_visit.pop(0)
        yield node
        for _, _, child in node.childs:
            if child not in visited:
                to_visit.append(child)
                visited.add(child)


def construct(start_block, vmap, exceptions):
    # Exceptions are not yet handled. An exception block has no parent, so
    # we can skip them by doing a BFS on the basic blocks.
    bfs_blocks = bfs(start_block)

    graph = Graph()
    gen_ret = GenInvokeRetName()

    # Construction of a mapping of basic blocks into Nodes
    block_to_node = {}
    for block in bfs_blocks:
        node = block_to_node.get(block)
        if node is None:
            node = build_node_from_block(block, vmap, gen_ret)
            block_to_node[block] = node
        for _, _, child_block in block.childs:
            child_node = block_to_node.get(child_block)
            if child_node is None:
                child_node = build_node_from_block(child_block, vmap, gen_ret)
                block_to_node[child_block] = child_node
            graph.add_edge(node, child_node)
            if node.is_switch():
                node.add_case(child_node)
            if node.is_cond():
                if_target = ((block.end / 2) - (block.last_length / 2) +
                             node.off_last_ins)
                child_addr = child_block.start / 2
                if if_target == child_addr:
                    node.set_true(child_node)
                else:
                    node.set_false(child_node)
        # Check that both branch of the if point to something
        # It may happen that both branch point to the same node, in this case
        # the false branch will be None. So we set it to the right node.
        # TODO: In this situation, we should transform the condition node into
        # a statement node
        if node.is_cond() and node.false is None:
            node.set_false(node.true)

        graph.add_node(node)

    graph.set_entry(block_to_node[start_block])
    del block_to_node, bfs_blocks

    graph.compute_rpo()
    graph.number_ins()

    # Create a list of Node which are 'return' node
    # There should be one and only one node of this type
    # If this is not the case, try to continue anyway by setting the exit node
    # to the one which has the greatest RPO number (not necessarily the case)
    lexit_nodes = [node for node in graph if node.is_return()]

    if len(lexit_nodes) > 1:
        # Not sure that this case is possible...
        logger.error('Multiple exit nodes found !')
        graph.set_exit(graph.get_rpo()[-1])
    elif len(lexit_nodes) < 1:
        # A method can have no return if it has throw statement(s) or if its
        # body is a while(1) whitout break/return.
        logger.debug('No exit node found !')
    else:
        graph.set_exit(lexit_nodes[0])

    return graph
