# This file is part of Androguard.
#
# Copyright (c) 2012 Geoffroy Gueguen <geoffroy.gueguen@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from collections import defaultdict
from androguard.decompiler.dad.basic_blocks import (build_node_from_block,
                                                    StatementBlock, CondBlock)
from androguard.decompiler.dad.util import get_type
from androguard.decompiler.dad.instruction import Variable

logger = logging.getLogger('dad.graph')


class Graph(object):
    def __init__(self):
        self.entry = None
        self.exit = None
        self.nodes = list()
        self.rpo = []
        self.edges = defaultdict(list)
        self.catch_edges = defaultdict(list)
        self.reverse_edges = defaultdict(list)
        self.reverse_catch_edges = defaultdict(list)
        self.loc_to_ins = None
        self.loc_to_node = None

    def sucs(self, node):
        return self.edges.get(node, [])

    def all_sucs(self, node):
        return self.edges.get(node, []) + self.catch_edges.get(node, [])

    def preds(self, node):
        return [n for n in self.reverse_edges.get(node, [])
                if not n.in_catch]

    def all_preds(self, node):
        return (self.reverse_edges.get(node, []) +
                self.reverse_catch_edges.get(node, []))

    def add_node(self, node):
        self.nodes.append(node)

    def add_edge(self, e1, e2):
        lsucs = self.edges[e1]
        if e2 not in lsucs:
            lsucs.append(e2)
        lpreds = self.reverse_edges[e2]
        if e1 not in lpreds:
            lpreds.append(e1)

    def add_catch_edge(self, e1, e2):
        lsucs = self.catch_edges[e1]
        if e2 not in lsucs:
            lsucs.append(e2)
        lpreds = self.reverse_catch_edges[e2]
        if e1 not in lpreds:
            lpreds.append(e1)

    def remove_node(self, node):
        preds = self.reverse_edges.get(node, [])
        for pred in preds:
            self.edges[pred].remove(node)

        succs = self.edges.get(node, [])
        for suc in succs:
            self.reverse_edges[suc].remove(node)

        exc_preds = self.reverse_catch_edges.pop(node, [])
        for pred in exc_preds:
            self.catch_edges[pred].remove(node)

        exc_succs = self.catch_edges.pop(node, [])
        for suc in exc_succs:
            self.reverse_catch_edges[suc].remove(node)

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
            self.loc_to_node[start_node, end_node] = node

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

    def compute_rpo(self):
        '''
        Number the nodes in reverse post order.
        An RPO traversal visit as many predecessors of a node as possible
        before visiting the node itself.
        '''
        nb = len(self.nodes) + 1
        for node in self.post_order():
            node.num = nb - node.po
        self.rpo = sorted(self.nodes, key=lambda n: n.num)

    def post_order(self):
        '''
        Return the nodes of the graph in post-order i.e we visit all the
        children of a node before visiting the node itself.
        '''
        def _visit(n, cnt):
            visited.add(n)
            for suc in self.all_sucs(n):
                if not suc in visited:
                    for cnt, s in _visit(suc, cnt):
                        yield cnt, s
            n.po = cnt
            yield cnt + 1, n
        visited = set()
        for _, node in _visit(self.entry, 1):
            yield node

    def draw(self, name, dname, draw_branches=True):
        from pydot import Dot, Edge
        g = Dot()
        g.set_node_defaults(color='lightgray', style='filled', shape='box',
                            fontname='Courier', fontsize='10')
        for node in sorted(self.nodes, key=lambda x: x.num):
            if draw_branches and node.type.is_cond:
                g.add_edge(Edge(str(node), str(node.true), color='green'))
                g.add_edge(Edge(str(node), str(node.false), color='red'))
            else:
                for suc in self.sucs(node):
                    g.add_edge(Edge(str(node), str(suc), color='blue'))
            for except_node in self.catch_edges.get(node, []):
                g.add_edge(Edge(str(node), str(except_node),
                                color='black', style='dashed'))

        g.write_png('%s/%s.png' % (dname, name))

    def immediate_dominators(self):
        return dom_lt(self)

    def __len__(self):
        return len(self.nodes)

    def __repr__(self):
        return str(self.nodes)

    def __iter__(self):
        for node in self.nodes:
            yield node


def split_if_nodes(graph):
    '''
    Split IfNodes in two nodes, the first node is the header node, the
    second one is only composed of the jump condition.
    '''
    node_map = {n: n for n in graph}
    to_update = set()
    for node in graph.nodes[:]:
        if node.type.is_cond:
            if len(node.get_ins()) > 1:
                pre_ins = node.get_ins()[:-1]
                last_ins = node.get_ins()[-1]
                pre_node = StatementBlock('%s-pre' % node.name, pre_ins)
                cond_node = CondBlock('%s-cond' % node.name, [last_ins])
                node_map[node] = pre_node
                node_map[pre_node] = pre_node
                node_map[cond_node] = cond_node

                pre_node.copy_from(node)
                cond_node.copy_from(node)
                for var in node.var_to_declare:
                    pre_node.add_variable_declaration(var)
                pre_node.type.is_stmt = True
                cond_node.true = node.true
                cond_node.false = node.false

                for pred in graph.all_preds(node):
                    pred_node = node_map[pred]
                    # Verify that the link is not an exception link
                    if node not in graph.sucs(pred):
                        graph.add_catch_edge(pred_node, pre_node)
                        continue
                    if pred is node:
                        pred_node = cond_node
                    if pred.type.is_cond:  # and not (pred is node):
                        if pred.true is node:
                            pred_node.true = pre_node
                        if pred.false is node:
                            pred_node.false = pre_node
                    graph.add_edge(pred_node, pre_node)
                for suc in graph.sucs(node):
                    graph.add_edge(cond_node, node_map[suc])

                # We link all the exceptions to the pre node instead of the
                # condition node, which should not trigger any of them.
                for suc in graph.catch_edges.get(node, []):
                    graph.add_catch_edge(pre_node, node_map[suc])

                if node is graph.entry:
                    graph.entry = pre_node

                graph.add_node(pre_node)
                graph.add_node(cond_node)
                graph.add_edge(pre_node, cond_node)
                pre_node.update_attribute_with(node_map)
                cond_node.update_attribute_with(node_map)
                graph.remove_node(node)
        else:
            to_update.add(node)
    for node in to_update:
        node.update_attribute_with(node_map)


def simplify(graph):
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
        node_map = {}
        to_update = set()
        for node in graph.nodes[:]:
            if node.type.is_stmt and node in graph:
                sucs = graph.all_sucs(node)
                if len(sucs) != 1:
                    continue
                suc = sucs[0]
                if len(node.get_ins()) == 0:
                    if any(pred.type.is_switch
                            for pred in graph.all_preds(node)):
                        continue
                    if node is suc:
                        continue
                    node_map[node] = suc

                    for pred in graph.all_preds(node):
                        pred.update_attribute_with(node_map)
                        if node not in graph.sucs(pred):
                            graph.add_catch_edge(pred, suc)
                            continue
                        graph.add_edge(pred, suc)
                    redo = True
                    if node is graph.entry:
                        graph.entry = suc
                    graph.remove_node(node)
                elif (suc.type.is_stmt and
                      len(graph.all_preds(suc)) == 1 and
                      not (suc in graph.catch_edges) and
                      not ((node is suc) or (suc is graph.entry))):
                    ins_to_merge = suc.get_ins()
                    node.add_ins(ins_to_merge)
                    for var in suc.var_to_declare:
                        node.add_variable_declaration(var)
                    new_suc = graph.sucs(suc)[0]
                    if new_suc:
                        graph.add_edge(node, new_suc)
                    for exception_suc in graph.catch_edges.get(suc, []):
                        graph.add_catch_edge(node, exception_suc)
                    redo = True
                    graph.remove_node(suc)
            else:
                to_update.add(node)
        for node in to_update:
            node.update_attribute_with(node_map)


def dom_lt(graph):
    '''Dominator algorithm from Lengaeur-Tarjan'''
    def _dfs(v, n):
        semi[v] = n = n + 1
        vertex[n] = label[v] = v
        ancestor[v] = 0
        for w in graph.all_sucs(v):
            if not semi[w]:
                parent[w] = v
                n = _dfs(w, n)
            pred[w].add(v)
        return n

    def _compress(v):
        u = ancestor[v]
        if ancestor[u]:
            _compress(u)
            if semi[label[u]] < semi[label[v]]:
                label[v] = label[u]
            ancestor[v] = ancestor[u]

    def _eval(v):
        if ancestor[v]:
            _compress(v)
            return label[v]
        return v

    def _link(v, w):
        ancestor[w] = v

    parent, ancestor, vertex = {}, {}, {}
    label, dom = {}, {}
    pred, bucket = defaultdict(set), defaultdict(set)

    # Step 1:
    semi = {v: 0 for v in graph.nodes}
    n = _dfs(graph.entry, 0)
    for i in xrange(n, 1, -1):
        w = vertex[i]
    # Step 2:
        for v in pred[w]:
            u = _eval(v)
            y = semi[w] = min(semi[w], semi[u])
        bucket[vertex[y]].add(w)
        pw = parent[w]
        _link(pw, w)
    # Step 3:
        bpw = bucket[pw]
        while bpw:
            v = bpw.pop()
            u = _eval(v)
            dom[v] = u if semi[u] < semi[v] else pw
    # Step 4:
    for i in range(2, n + 1):
        w = vertex[i]
        dw = dom[w]
        if dw != vertex[semi[w]]:
            dom[w] = dom[dw]
    dom[graph.entry] = None
    return dom


def bfs(start):
    to_visit = [start]
    visited = set([start])
    while to_visit:
        node = to_visit.pop(0)
        yield node
        if node.exception_analysis:
            for _, _, exception in node.exception_analysis.exceptions:
                if exception not in visited:
                    to_visit.append(exception)
                    visited.add(exception)
        for _, _, child in node.childs:
            if child not in visited:
                to_visit.append(child)
                visited.add(child)


class GenInvokeRetName(object):
    def __init__(self):
        self.num = 0
        self.ret = None

    def new(self):
        self.num += 1
        self.ret = Variable('tmp%d' % self.num)
        return self.ret

    def set_to(self, ret):
        self.ret = ret

    def last(self):
        return self.ret


def make_node(graph, block, block_to_node, vmap, gen_ret):
    node = block_to_node.get(block)
    if node is None:
        node = build_node_from_block(block, vmap, gen_ret)
        block_to_node[block] = node
    if block.exception_analysis:
        for _type, _, exception_target in block.exception_analysis.exceptions:
            exception_node = block_to_node.get(exception_target)
            if exception_node is None:
                exception_node = build_node_from_block(exception_target,
                                                        vmap, gen_ret, _type)
                exception_node.set_catch_type(_type)
                exception_node.in_catch = True
                block_to_node[exception_target] = exception_node
            graph.add_catch_edge(node, exception_node)
    for _, _, child_block in block.childs:
        child_node = block_to_node.get(child_block)
        if child_node is None:
            child_node = build_node_from_block(child_block, vmap, gen_ret)
            block_to_node[child_block] = child_node
        graph.add_edge(node, child_node)
        if node.type.is_switch:
            node.add_case(child_node)
        if node.type.is_cond:
            if_target = ((block.end / 2) - (block.last_length / 2) +
                          node.off_last_ins)
            child_addr = child_block.start / 2
            if if_target == child_addr:
                node.true = child_node
            else:
                node.false = child_node

    # Check that both branch of the if point to something
    # It may happen that both branch point to the same node, in this case
    # the false branch will be None. So we set it to the right node.
    # TODO: In this situation, we should transform the condition node into
    # a statement node
    if node.type.is_cond and node.false is None:
        node.false = node.true

    return node


def construct(start_block, vmap, exceptions):
    bfs_blocks = bfs(start_block)

    graph = Graph()
    gen_ret = GenInvokeRetName()

    # Construction of a mapping of basic blocks into Nodes
    block_to_node = {}

    exceptions_start_block = []
    for exception in exceptions:
        for _, _, block in exception.exceptions:
            exceptions_start_block.append(block)

    for block in bfs_blocks:
        node = make_node(graph, block, block_to_node, vmap, gen_ret)
        graph.add_node(node)

    graph.entry = block_to_node[start_block]
    del block_to_node, bfs_blocks

    graph.compute_rpo()
    graph.number_ins()

    for node in graph.rpo:
        preds = [pred for pred in graph.all_preds(node)
                 if pred.num < node.num]
        if preds and all(pred.in_catch for pred in preds):
            node.in_catch = True

    # Create a list of Node which are 'return' node
    # There should be one and only one node of this type
    # If this is not the case, try to continue anyway by setting the exit node
    # to the one which has the greatest RPO number (not necessarily the case)
    lexit_nodes = [node for node in graph if node.type.is_return]

    if len(lexit_nodes) > 1:
        # Not sure that this case is possible...
        logger.error('Multiple exit nodes found !')
        graph.exit = graph.rpo[-1]
    elif len(lexit_nodes) < 1:
        # A method can have no return if it has throw statement(s) or if its
        # body is a while(1) whitout break/return.
        logger.debug('No exit node found !')
    else:
        graph.exit = lexit_nodes[0]

    return graph
