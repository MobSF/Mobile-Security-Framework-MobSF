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
from androguard.decompiler.dad.basic_blocks import (CatchBlock,
                                                    Condition,
                                                    LoopBlock,
                                                    ShortCircuitBlock,
                                                    TryBlock)
from androguard.decompiler.dad.graph import Graph
from androguard.decompiler.dad.node import Interval
from androguard.decompiler.dad.util import common_dom


logger = logging.getLogger('dad.control_flow')


def intervals(graph):
    '''
    Compute the intervals of the graph
    Returns
        interval_graph: a graph of the intervals of G
        interv_heads: a dict of (header node, interval)
    '''
    interval_graph = Graph()  # graph of intervals
    heads = [graph.entry]  # list of header nodes
    interv_heads = {}  # interv_heads[i] = interval of header i
    processed = dict([(i, False) for i in graph])
    edges = defaultdict(list)

    while heads:
        head = heads.pop(0)

        if not processed[head]:
            processed[head] = True
            interv_heads[head] = Interval(head)

            # Check if there is a node which has all its predecessor in the
            # current interval. If there is, add that node to the interval and
            # repeat until all the possible nodes have been added.
            change = True
            while change:
                change = False
                for node in graph.rpo[1:]:
                    if all(
                      p in interv_heads[head] for p in graph.all_preds(node)):
                        change |= interv_heads[head].add_node(node)

            # At this stage, a node which is not in the interval, but has one
            # of its predecessor in it, is the header of another interval. So
            # we add all such nodes to the header list.
            for node in graph:
                if node not in interv_heads[head] and node not in heads:
                    if any(
                      p in interv_heads[head] for p in graph.all_preds(node)):
                        edges[interv_heads[head]].append(node)
                        assert(node not in heads)
                        heads.append(node)

            interval_graph.add_node(interv_heads[head])
            interv_heads[head].compute_end(graph)

    # Edges is a mapping of 'Interval -> [header nodes of interval successors]'
    for interval, heads in edges.items():
        for head in heads:
            interval_graph.add_edge(interval, interv_heads[head])

    interval_graph.entry = graph.entry.interval
    if graph.exit:
        interval_graph.exit = graph.exit.interval

    return interval_graph, interv_heads


def derived_sequence(graph):
    '''
    Compute the derived sequence of the graph G
    The intervals of G are collapsed into nodes, intervals of these nodes are
    built, and the process is repeated iteratively until we obtain a single
    node (if the graph is not irreducible)
    '''
    deriv_seq = [graph]
    deriv_interv = []
    single_node = False

    while not single_node:

        interv_graph, interv_heads = intervals(graph)
        deriv_interv.append(interv_heads)

        single_node = len(interv_graph) == 1
        if not single_node:
            deriv_seq.append(interv_graph)

        graph = interv_graph
        graph.compute_rpo()

    return deriv_seq, deriv_interv


def mark_loop_rec(graph, node, s_num, e_num, interval, nodes_in_loop):
    if node in nodes_in_loop:
        return
    nodes_in_loop.append(node)
    for pred in graph.all_preds(node):
        if s_num < pred.num <= e_num and pred in interval:
            mark_loop_rec(graph, pred, s_num, e_num, interval, nodes_in_loop)


def mark_loop(graph, start, end, interval):
    logger.debug('MARKLOOP : %s END : %s', start, end)
    head = start.get_head()
    latch = end.get_end()
    nodes_in_loop = [head]
    mark_loop_rec(graph, latch, head.num, latch.num, interval, nodes_in_loop)
    head.startloop = True
    head.latch = latch
    return nodes_in_loop


def loop_type(start, end, nodes_in_loop):
    if end.type.is_cond:
        if start.type.is_cond:
            if start.true in nodes_in_loop and start.false in nodes_in_loop:
                start.looptype.is_posttest = True
            else:
                start.looptype.is_pretest = True
        else:
            start.looptype.is_posttest = True
    else:
        if start.type.is_cond:
            if start.true in nodes_in_loop and start.false in nodes_in_loop:
                start.looptype.is_endless = True
            else:
                start.looptype.is_pretest = True
        else:
            start.looptype.is_endless = True


def loop_follow(start, end, nodes_in_loop):
    follow = None
    if start.looptype.is_pretest:
        if start.true in nodes_in_loop:
            follow = start.false
        else:
            follow = start.true
    elif start.looptype.is_posttest:
        if end.true in nodes_in_loop:
            follow = end.false
        else:
            follow = end.true
    else:
        num_next = float('inf')
        for node in nodes_in_loop:
            if node.type.is_cond:
                if (node.true.num < num_next
                        and node.true not in nodes_in_loop):
                    follow = node.true
                    num_next = follow.num
                elif (node.false.num < num_next
                        and node.false not in nodes_in_loop):
                    follow = node.false
                    num_next = follow.num
    start.follow['loop'] = follow
    for node in nodes_in_loop:
        node.follow['loop'] = follow
    logger.debug('Start of loop %s', start)
    logger.debug('Follow of loop: %s', start.follow['loop'])


def loop_struct(graphs_list, intervals_list):
    first_graph = graphs_list[0]
    for i, graph in enumerate(graphs_list):
        interval = intervals_list[i]
        for head in sorted(interval.keys(), key=lambda x: x.num):
            loop_nodes = []
            for node in graph.all_preds(head):
                if node.interval is head.interval:
                    lnodes = mark_loop(first_graph, head, node, head.interval)
                    for lnode in lnodes:
                        if lnode not in loop_nodes:
                            loop_nodes.append(lnode)
            head.get_head().loop_nodes = loop_nodes


def if_struct(graph, idoms):
    unresolved = set()
    for node in graph.post_order():
        if node.type.is_cond:
            ldominates = []
            for n, idom in idoms.iteritems():
                if node is idom and len(graph.reverse_edges.get(n, [])) > 1:
                    ldominates.append(n)
            if len(ldominates) > 0:
                n = max(ldominates, key=lambda x: x.num)
                node.follow['if'] = n
                for x in unresolved.copy():
                    if node.num < x.num < n.num:
                        x.follow['if'] = n
                        unresolved.remove(x)
            else:
                unresolved.add(node)
    return unresolved


def switch_struct(graph, idoms):
    unresolved = set()
    for node in graph.post_order():
        if node.type.is_switch:
            m = node
            for suc in graph.sucs(node):
                if idoms[suc] is not node:
                    m = common_dom(idoms, node, suc)
            ldominates = []
            for n, dom in idoms.iteritems():
                if m is dom and len(graph.all_preds(n)) > 1:
                    ldominates.append(n)
            if len(ldominates) > 0:
                n = max(ldominates, key=lambda x: x.num)
                node.follow['switch'] = n
                for x in unresolved:
                    x.follow['switch'] = n
                unresolved = set()
            else:
                unresolved.add(node)
            node.order_cases()


# TODO: deal with preds which are in catch
def short_circuit_struct(graph, idom, node_map):
    def MergeNodes(node1, node2, is_and, is_not):
        lpreds = set()
        ldests = set()
        for node in (node1, node2):
            lpreds.update(graph.preds(node))
            ldests.update(graph.sucs(node))
            graph.remove_node(node)
            done.add(node)
        lpreds.difference_update((node1, node2))
        ldests.difference_update((node1, node2))

        entry = graph.entry in (node1, node2)

        new_name = '%s+%s' % (node1.name, node2.name)
        condition = Condition(node1, node2, is_and, is_not)

        new_node = ShortCircuitBlock(new_name, condition)
        for old_n, new_n in node_map.iteritems():
            if new_n in (node1, node2):
                node_map[old_n] = new_node
        node_map[node1] = new_node
        node_map[node2] = new_node
        idom[new_node] = idom[node1]
        idom.pop(node1)
        idom.pop(node2)
        new_node.copy_from(node1)

        graph.add_node(new_node)

        for pred in lpreds:
            pred.update_attribute_with(node_map)
            graph.add_edge(node_map.get(pred, pred), new_node)
        for dest in ldests:
            graph.add_edge(new_node, node_map.get(dest, dest))
        if entry:
            graph.entry = new_node
        return new_node

    change = True
    while change:
        change = False
        done = set()
        for node in graph.post_order():
            if node.type.is_cond and node not in done:
                then = node.true
                els = node.false
                if node in (then, els):
                    continue
                if then.type.is_cond and len(graph.preds(then)) == 1:
                    if node in (then.true, then.false):
                        continue
                    if then.false is els:  # node && t
                        change = True
                        merged_node = MergeNodes(node, then, True, False)
                        merged_node.true = then.true
                        merged_node.false = els
                    elif then.true is els:  # !node || t
                        change = True
                        merged_node = MergeNodes(node, then, False, True)
                        merged_node.true = els
                        merged_node.false = then.false
                elif els.type.is_cond and len(graph.preds(els)) == 1:
                    if node in (els.false, els.true):
                        continue
                    if els.false is then:  # !node && e
                        change = True
                        merged_node = MergeNodes(node, els, True, True)
                        merged_node.true = els.true
                        merged_node.false = then
                    elif els.true is then:  # node || e
                        change = True
                        merged_node = MergeNodes(node, els, False, False)
                        merged_node.true = then
                        merged_node.false = els.false
            done.add(node)
        if change:
            graph.compute_rpo()


def while_block_struct(graph, node_map):
    change = False
    for node in graph.rpo[:]:
        if node.startloop:
            change = True
            new_node = LoopBlock(node.name, node)
            node_map[node] = new_node
            new_node.copy_from(node)

            entry = node is graph.entry
            lpreds = graph.preds(node)
            lsuccs = graph.sucs(node)

            for pred in lpreds:
                graph.add_edge(node_map.get(pred, pred), new_node)

            for suc in lsuccs:
                graph.add_edge(new_node, node_map.get(suc, suc))
            if entry:
                graph.entry = new_node

            if node.type.is_cond:
                new_node.true = node.true
                new_node.false = node.false

            graph.add_node(new_node)
            graph.remove_node(node)

    if change:
        graph.compute_rpo()


def catch_struct(graph, idoms):
    block_try_nodes = {}
    node_map = {}
    for catch_block in graph.reverse_catch_edges:
        if catch_block in graph.catch_edges:
            continue
        catch_node = CatchBlock(catch_block)

        try_block = idoms[catch_block]
        try_node = block_try_nodes.get(try_block)
        if try_node is None:
            block_try_nodes[try_block] = TryBlock(try_block)
            try_node = block_try_nodes[try_block]

            node_map[try_block] = try_node
            for pred in graph.all_preds(try_block):
                pred.update_attribute_with(node_map)
                if try_block in graph.sucs(pred):
                    graph.edges[pred].remove(try_block)
                graph.add_edge(pred, try_node)

            if try_block.type.is_stmt:
                follow = graph.sucs(try_block)
                if follow:
                    try_node.follow = graph.sucs(try_block)[0]
                else:
                    try_node.follow = None
            elif try_block.type.is_cond:
                loop_follow = try_block.follow['loop']
                if loop_follow:
                    try_node.follow = loop_follow
                else:
                    try_node.follow = try_block.follow['if']
            elif try_block.type.is_switch:
                try_node.follow = try_block.follow['switch']
            else:  # return or throw
                try_node.follow = None

        try_node.add_catch_node(catch_node)
    for node in graph.nodes:
        node.update_attribute_with(node_map)
    if graph.entry in node_map:
        graph.entry = node_map[graph.entry]


def update_dom(idoms, node_map):
    for n, dom in idoms.iteritems():
        idoms[n] = node_map.get(dom, dom)


def identify_structures(graph, idoms):
    Gi, Li = derived_sequence(graph)
    switch_struct(graph, idoms)
    loop_struct(Gi, Li)
    node_map = {}

    short_circuit_struct(graph, idoms, node_map)
    update_dom(idoms, node_map)

    if_unresolved = if_struct(graph, idoms)

    while_block_struct(graph, node_map)
    update_dom(idoms, node_map)

    loop_starts = []
    for node in graph.rpo:
        node.update_attribute_with(node_map)
        if node.startloop:
            loop_starts.append(node)
    for node in loop_starts:
        loop_type(node, node.latch, node.loop_nodes)
        loop_follow(node, node.latch, node.loop_nodes)

    for node in if_unresolved:
        follows = [n for n in (node.follow['loop'],
                               node.follow['switch']) if n]
        if len(follows) >= 1:
            follow = min(follows, key=lambda x: x.num)
            node.follow['if'] = follow

    catch_struct(graph, idoms)
