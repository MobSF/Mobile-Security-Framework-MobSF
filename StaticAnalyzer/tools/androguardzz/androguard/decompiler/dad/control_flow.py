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
from androguard.decompiler.dad.basic_blocks import (Condition,
                                                    ShortCircuitBlock,
                                                    LoopBlock)
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
    heads = set([graph.get_entry()])  # set of header nodes
    interv_heads = {}  # interv_heads[i] = interval of header i
    processed = dict([(i, False) for i in graph])
    edges = {}

    while heads:
        head = heads.pop()

        if not processed[head]:
            processed[head] = True
            interv_heads[head] = Interval(head)

            # Check if if there is a node which has all its predecessor in the
            # current interval. If there is, add that node to the interval and
            # repeat until all the possible nodes have been added.
            change = True
            while change:
                change = False
                for node in graph.get_rpo()[1:]:
                    if all(p in interv_heads[head] for p in graph.preds(node)):
                        change |= interv_heads[head].add_node(node)

            # At this stage, a node which is not in the interval, but has one
            # of its predecessor in it, is the header of another interval. So
            # we add all such nodes to the header list.
            for node in graph:
                if node not in interv_heads[head] and node not in heads:
                    if any(p in interv_heads[head] for p in graph.preds(node)):
                        edges.setdefault(interv_heads[head], []).append(node)
                        heads.add(node)

            interval_graph.add_node(interv_heads[head])
            interv_heads[head].compute_end(graph)

    # Edges is a mapping of 'Interval -> [header nodes of interval successors]'
    for interval, heads in edges.items():
        for head in heads:
            interval_graph.add_edge(interval, interv_heads[head])

    interval_graph.set_entry(graph.get_entry().interval)
    graph_exit = graph.get_exit()
    if graph_exit:
        interval_graph.set_exit(graph_exit.interval)

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
        if 0:
            graph.draw(graph.entry.name, 'tmp/dad/intervals/')
        graph.compute_rpo()

    return deriv_seq, deriv_interv


def mark_loop_rec(graph, node, s_num, e_num, interval, nodes_in_loop):
    if node in nodes_in_loop:
        return
    nodes_in_loop.append(node)
    for pred in graph.preds(node):
        if s_num < pred.num <= e_num and pred in interval:
            mark_loop_rec(graph, pred, s_num, e_num, interval, nodes_in_loop)


def mark_loop(graph, start, end, interval):
    logger.debug('MARKLOOP : %s END : %s', start, end)
    head = start.get_head()
    latch = end.get_end()
    nodes_in_loop = [head]
    mark_loop_rec(graph, latch, head.num, latch.num, interval, nodes_in_loop)
    head.set_start_loop()
    latch.set_end_loop()
    head.set_latch_node(latch)
    return nodes_in_loop


def loop_type(start, end, nodes_in_loop):
    start = start.get_head()
    end = end.get_end()
    if end.is_cond():
        if start.is_cond():
            if start.true in nodes_in_loop and start.false in nodes_in_loop:
                start.set_loop_posttest()
            else:
                start.set_loop_pretest()
        else:
            start.set_loop_posttest()
    else:
        if start.is_cond():
            if start.true in nodes_in_loop and start.false in nodes_in_loop:
                start.set_loop_endless()
            else:
                start.set_loop_pretest()
        else:
            start.set_loop_endless()


def loop_follow(start, end, nodes_in_loop):
    head = start.get_head()
    follow = None
    if start.looptype.pretest():
        if head.true in nodes_in_loop:
            follow = head.false
        else:
            follow = head.true
    elif start.looptype.posttest():
        if end.true in nodes_in_loop:
            follow = end.false
        else:
            follow = end.true
    else:
        num_next = NotImplemented  # Hack to do: num_next = infinity
        for node in nodes_in_loop:
            if node.is_cond():
                if (node.true.num < num_next
                        and node.true not in nodes_in_loop):
                    follow = node.true
                    num_next = follow.num
                elif (node.false.num < num_next
                        and node.false not in nodes_in_loop):
                    follow = node.false
                    num_next = follow.num
    head.set_loop_follow(follow)
    for node in nodes_in_loop:
        node.set_loop_follow(follow)
    logger.debug('Start of loop %s', head)
    logger.debug('Follow of loop: %s', head.get_loop_follow())


def loop_struct(graphs_list, intervals_list):
    first_graph = graphs_list[0]
    for i, graph in enumerate(graphs_list):
        interval = intervals_list[i]
        for head in sorted(interval.keys(), key=lambda x: x.num):
            loop_nodes = set()
            for node in graph.preds(head):
                if node.interval is head.interval:
                    lnodes = mark_loop(first_graph, head, node, head.interval)
                    loop_nodes.update(lnodes)
                    head.get_head().set_loop_nodes(loop_nodes)


def if_struct(graph, idoms):
    unresolved = set()
    for node in graph.get_rpo()[::-1]:
        if node.is_cond():
            ldominates = []
            for n, idom in idoms.iteritems():
                if node is idom and len(graph.preds(n)) > 1:
                    ldominates.append(n)
            if len(ldominates) > 0:
                n = max(ldominates, key=lambda x: x.num)
                node.set_if_follow(n)
                for x in unresolved.copy():
                    if node.num < x.num < n.num:
                        x.set_if_follow(n)
                        unresolved.remove(x)
            else:
                unresolved.add(node)
    return unresolved


def switch_struct(graph, idoms):
    unresolved = set()
    for node in graph.post_order():
        if node.is_switch():
            m = node
            for suc in graph.sucs(node):
                if idoms[suc] is not node:
                    m = common_dom(idoms, node, suc)
            ldominates = []
            for n, dom in idoms.iteritems():
                if m is dom and len(graph.preds(n)) > 1:
                    ldominates.append(n)
            if len(ldominates) > 0:
                n = max(ldominates, key=lambda x: x.num)
                node.set_switch_follow(n)
                for x in unresolved:
                    x.set_switch_follow(n)
                unresolved = set()
            else:
                unresolved.add(node)
            node.order_cases()


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

        entry = graph.get_entry() in (node1, node2)

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
            graph.set_entry(new_node)
        return new_node

    change = True
    while change:
        change = False
        done = set()
        for node in graph.post_order():
            if node.is_cond() and node not in done:
                then = node.true
                els = node.false
                if node in (then, els):
                    continue
                if then.is_cond() and len(graph.preds(then)) == 1:
                    if then.false is els:  # node && t
                        change = True
                        merged_node = MergeNodes(node, then, True, False)
                        merged_node.set_true(then.true)
                        merged_node.set_false(els)
                    elif then.true is els:  # !node || t
                        change = True
                        merged_node = MergeNodes(node, then, False, True)
                        merged_node.set_true(els)
                        merged_node.set_false(then.false)
                elif els.is_cond() and len(graph.preds(els)) == 1:
                    if els.false is then:  # !node && e
                        change = True
                        merged_node = MergeNodes(node, els, True, True)
                        merged_node.set_true(els.true)
                        merged_node.set_false(then)
                    elif els.true is then:  # node || e
                        change = True
                        merged_node = MergeNodes(node, els, False, False)
                        merged_node.set_true(then)
                        merged_node.set_false(els.false)
            done.add(node)
        if change:
            graph.reset_rpo()


def while_block_struct(graph, node_map):
    change = False
    for node in graph.get_rpo()[:]:
        if node.is_start_loop():
            change = True
            new_node = LoopBlock(node.name, node)
            node_map[node] = new_node
            new_node.copy_from(node)

            entry = node is graph.get_entry()
            lpreds = graph.preds(node)
            lsuccs = graph.sucs(node)

            for pred in lpreds:
                graph.add_edge(node_map.get(pred, pred), new_node)

            for suc in lsuccs:
                graph.add_edge(new_node, node_map.get(suc, suc))
            if entry:
                graph.set_entry(new_node)

            if node.is_cond():
                new_node.set_true(node.true)
                new_node.set_false(node.false)

            graph.add_node(new_node)
            graph.remove_node(node)

    if change:
        graph.reset_rpo()


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
    for node in graph.get_rpo():
        node.update_attribute_with(node_map)
        if node.is_start_loop():
            loop_starts.append(node)
    for node in loop_starts:
        loop_type(node, node.latch, node.loop_nodes)
        loop_follow(node, node.latch, node.loop_nodes)

    for node in if_unresolved:
        follows = [n for n in (node.loop_follow, node.switch_follow) if n]
        if len(follows) >= 1:
            follow = min(follows, key=lambda x: x.num)
            node.set_if_follow(follow)
