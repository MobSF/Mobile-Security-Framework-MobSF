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
from androguard.decompiler.dad.instruction import (Variable, ThisParam,
                                                   Param)
from androguard.decompiler.dad.util import build_path, common_dom
from androguard.decompiler.dad.node import Node


logger = logging.getLogger('dad.control_flow')


class BasicReachDef(object):
    def __init__(self, graph, params):
        self.g = graph
        self.A = defaultdict(set)
        self.R = defaultdict(set)
        self.DB = defaultdict(set)
        self.defs = defaultdict(lambda: defaultdict(set))
        self.def_to_loc = defaultdict(set)
        # Deal with special entry node
        entry = graph.entry
        self.A[entry] = set(range(-1, -len(params) - 1, -1))
        for loc, param in enumerate(params, 1):
            self.defs[entry][param].add(-loc)
            self.def_to_loc[param].add(-loc)
        # Deal with the other nodes
        for node in graph.rpo:
            for i, ins in node.get_loc_with_ins():
                kill = ins.get_lhs()
                if kill is not None:
                    self.defs[node][kill].add(i)
                    self.def_to_loc[kill].add(i)
            for defs, values in self.defs[node].iteritems():
                self.DB[node].add(max(values))

    def run(self):
        nodes = self.g.rpo[:]
        while nodes:
            node = nodes.pop(0)
            newR = set()
            for pred in self.g.all_preds(node):
                newR.update(self.A[pred])
            if newR and newR != self.R[node]:
                self.R[node] = newR
                for suc in self.g.all_sucs(node):
                    if suc not in nodes:
                        nodes.append(suc)

            killed_locs = set()
            for reg in self.defs[node]:
                killed_locs.update(self.def_to_loc[reg])

            A = set()
            for loc in self.R[node]:
                if loc not in killed_locs:
                    A.add(loc)
            newA = A.union(self.DB[node])
            if newA != self.A[node]:
                self.A[node] = newA
                for suc in self.g.all_sucs(node):
                    if suc not in nodes:
                        nodes.append(suc)


def update_chain(graph, loc, du, ud):
    '''
    Updates the DU chain of the instruction located at loc such that there is
    no more reference to it so that we can remove it.
    When an instruction is found to be dead (i.e it has no side effect, and the
    register defined is not used) we have to update the DU chain of all the
    variables that may me used by the dead instruction.
    '''
    ins = graph.get_ins_from_loc(loc)
    for var in ins.get_used_vars():
        # We get the definition points of the current variable
        for def_loc in set(ud[var, loc]):
            # We remove the use of the variable at loc from the DU chain of
            # the variable definition located at def_loc
            du[var, def_loc].remove(loc)
            ud[var, loc].remove(def_loc)
            if not ud.get((var, loc)):
                ud.pop((var, loc))
            # If the DU chain of the defined variable is now empty, this means
            # that we may have created a new dead instruction, so we check that
            # the instruction has no side effect and we update the DU chain of
            # the new dead instruction, and we delete it.
            # We also make sure that def_loc is not < 0. This is the case when
            # the current variable is a method parameter.
            if def_loc >= 0 and not du[var, def_loc]:
                du.pop((var, def_loc))
                def_ins = graph.get_ins_from_loc(def_loc)
                if def_ins.is_call():
                    def_ins.remove_defined_var()
                elif def_ins.has_side_effect():
                    continue
                else:
                    update_chain(graph, def_loc, du, ud)
                    graph.remove_ins(def_loc)


def dead_code_elimination(graph, du, ud):
    '''
    Run a dead code elimination pass.
    Instructions are checked to be dead. If it is the case, we remove them and
    we update the DU & UD chains of its variables to check for further dead
    instructions.
    '''
    for node in graph.rpo:
        for i, ins in node.get_loc_with_ins()[:]:
            reg = ins.get_lhs()
            if reg is not None:
                # If the definition is not used, we check that the instruction
                # has no side effect. If there is one and this is a call, we
                # remove only the unused defined variable. else, this is
                # something like an array access, so we do nothing.
                # Otherwise (no side effect) we can remove the instruction from
                # the node.
                if (reg, i) not in du:
                    if ins.is_call():
                        ins.remove_defined_var()
                    elif ins.has_side_effect():
                        continue
                    else:
                        # We can delete the instruction. First update the DU
                        # chain of the variables used by the instruction to
                        # `let them know` that they are not used anymore by the
                        # deleted instruction.
                        # Then remove the instruction.
                        update_chain(graph, i, du, ud)
                        graph.remove_ins(i)


def clear_path_node(graph, reg, loc1, loc2):
    for loc in xrange(loc1, loc2):
        ins = graph.get_ins_from_loc(loc)
        logger.debug('  treat loc: %d, ins: %s', loc, ins)
        if ins is None:
            continue
        logger.debug('  LHS: %s, side_effect: %s', ins.get_lhs(),
                                                   ins.has_side_effect())
        if ins.get_lhs() == reg or ins.has_side_effect():
            return False
    return True


def clear_path(graph, reg, loc1, loc2):
    '''
    Check that the path from loc1 to loc2 is clear.
    We have to check that there is no side effect between the two location
    points. We also have to check that the variable `reg` is not redefined
    along one of the possible pathes from loc1 to loc2.
    '''
    logger.debug('clear_path: reg(%s), loc1(%s), loc2(%s)', reg, loc1, loc2)
    node1 = graph.get_node_from_loc(loc1)
    node2 = graph.get_node_from_loc(loc2)
    # If both instructions are in the same node, we only have to check that the
    # path is clear inside the node
    if node1 is node2:
        return clear_path_node(graph, reg, loc1 + 1, loc2)

    # If instructions are in different nodes, we also have to check the nodes
    # in the path between the two locations.
    if not clear_path_node(graph, reg, loc1 + 1, node1.ins_range[1]):
        return False
    path = build_path(graph, node1, node2)
    for node in path:
        locs = node.ins_range
        end_loc = loc2 if (locs[0] <= loc2 <= locs[1]) else locs[1]
        if not clear_path_node(graph, reg, locs[0], end_loc):
            return False
    return True


def register_propagation(graph, du, ud):
    '''
    Propagate the temporary registers between instructions and remove them if
    necessary.
    We process the nodes of the graph in reverse post order. For each
    instruction in the node, we look at the variables that it uses. For each of
    these variables we look where it is defined and if we can replace it with
    its definition.
    We have to be careful to the side effects some instructions may have.
    To do the propagation, we use the computed DU and UD chains.
    '''
    change = True
    while change:
        change = False
        for node in graph.rpo:
            for i, ins in node.get_loc_with_ins()[:]:
                logger.debug('Treating instruction %d: %s', i, ins)
                logger.debug('  Used vars: %s', ins.get_used_vars())
                for var in ins.get_used_vars():
                    # Get the list of locations this variable is defined at.
                    locs = ud[var, i]
                    logger.debug('    var %s defined in lines %s', var, locs)
                    # If the variable is uniquely defined for this instruction
                    # it may be eligible for propagation.
                    if len(locs) != 1:
                        continue

                    loc = locs[0]
                    # Methods parameters are defined with a location < 0.
                    if loc < 0:
                        continue
                    orig_ins = graph.get_ins_from_loc(loc)
                    logger.debug('     -> %s', orig_ins)
                    logger.debug('     -> DU(%s, %s) = %s', var, loc,
                                                    du[var, loc])

                    # We defined some instructions as not propagable.
                    # Actually this is the case only for array creation
                    # (new foo[x])
                    if not orig_ins.is_propagable():
                        logger.debug('    %s not propagable...', orig_ins)
                        continue

                    if not orig_ins.get_rhs().is_const():
                        # We only try to propagate constants and definition
                        # points which are used at only one location.
                        if len(du[var, loc]) > 1:
                            logger.debug('       => variable has multiple uses'
                                         ' and is not const => skip')
                            continue

                        # We check that the propagation is safe for all the
                        # variables that are used in the instruction.
                        # The propagation is not safe if there is a side effect
                        # along the path from the definition of the variable
                        # to its use in the instruction, or if the variable may
                        # be redifined along this path.
                        safe = True
                        orig_ins_used_vars = orig_ins.get_used_vars()
                        logger.debug('    variables used by the original '
                                    'instruction: %s', orig_ins_used_vars)
                        for var2 in orig_ins_used_vars:
                            # loc is the location of the defined variable
                            # i is the location of the current instruction
                            if not clear_path(graph, var2, loc, i):
                                safe = False
                                break
                        if not safe:
                            logger.debug('Propagation NOT SAFE')
                            continue

                    # We also check that the instruction itself is
                    # propagable. If the instruction has a side effect it
                    # cannot be propagated if there is another side effect
                    # along the path
                    if orig_ins.has_side_effect():
                        if not clear_path(graph, None, loc, i):
                            logger.debug('        %s has side effect and the '
                                         'path is not clear !', orig_ins)
                            continue

                    logger.debug('     => Modification of the instruction!')
                    logger.debug('      - BEFORE: %s', ins)
                    ins.replace(var, orig_ins.get_rhs())
                    logger.debug('      -> AFTER: %s', ins)
                    logger.debug('\t UD(%s, %s) : %s', var, i, ud[var, i])
                    ud[var, i].remove(loc)
                    logger.debug('\t    -> %s', ud[var, i])
                    if len(ud[var, i]) == 0:
                        ud.pop((var, i))
                    for var2 in orig_ins.get_used_vars():
                        # We update the UD chain of the variables we
                        # propagate. We also have to take the
                        # definition points of all the variables used
                        # by the instruction and update the DU chain
                        # with this information.
                        old_ud = ud.get((var2, loc))
                        logger.debug('\t  ud(%s, %s) = %s', var2, loc, old_ud)
                        # If the instruction use the same variable
                        # multiple times, the second+ time the ud chain
                        # will be None because already treated.
                        if old_ud is None:
                            continue
                        ud[var2, i].extend(old_ud)
                        logger.debug('\t  - ud(%s, %s) = %s', var2, i,
                                                          ud[var2, i])
                        ud.pop((var2, loc))

                        for def_loc in old_ud:
                            du[var2, def_loc].remove(loc)
                            du[var2, def_loc].append(i)

                    new_du = du[var, loc]
                    logger.debug('\t new_du(%s, %s): %s', var, loc, new_du)
                    new_du.remove(i)
                    logger.debug('\t    -> %s', new_du)
                    if not new_du:
                        logger.debug('\t  REMOVING INS %d', loc)
                        du.pop((var, loc))
                        graph.remove_ins(loc)
                        change = True


class DummyNode(Node):
    def __init__(self, name):
        super(DummyNode, self).__init__(name)

    def get_loc_with_ins(self):
        return []

    def __repr__(self):
        return '%s-dumnode' % self.name

    def __str__(self):
        return '%s-dummynode' % self.name


def group_variables(lvars, DU, UD):
    treated = defaultdict(list)
    variables = defaultdict(list)
    for var, loc in sorted(DU):
        if var not in lvars:
            continue
        if loc in treated[var]:
            continue
        defs = [loc]
        uses = set(DU[var, loc])
        change = True
        while change:
            change = False
            for use in uses:
                ldefs = UD[var, use]
                for ldef in ldefs:
                    if ldef not in defs:
                        defs.append(ldef)
                        change = True
            for ldef in defs[1:]:
                luses = set(DU[var, ldef])
                for use in luses:
                    if use not in uses:
                        uses.add(use)
                        change = True
        treated[var].extend(defs)
        variables[var].append((defs, list(uses)))
    return variables


def split_variables(graph, lvars, DU, UD):
    variables = group_variables(lvars, DU, UD)

    if lvars:
        nb_vars = max(lvars) + 1
    else:
        nb_vars = 0
    for var, versions in variables.iteritems():
        nversions = len(versions)
        if nversions == 1:
            continue
        orig_var = lvars.pop(var)
        for i, (defs, uses) in enumerate(versions):
            if min(defs) < 0:  # Param
                if orig_var.this:
                    new_version = ThisParam(var, orig_var.type)
                else:
                    new_version = Param(var, orig_var.type)
                lvars[var] = new_version
            else:
                new_version = Variable(nb_vars)
                new_version.type = orig_var.type
                lvars[nb_vars] = new_version  # add new version to variables
                nb_vars += 1
            new_version.name = '%d_%d' % (var, i)

            for loc in defs:
                if loc < 0:
                    continue
                ins = graph.get_ins_from_loc(loc)
                ins.replace_lhs(new_version)
                DU[(new_version.value(), loc)] = DU.pop((var, loc))
            for loc in uses:
                ins = graph.get_ins_from_loc(loc)
                ins.replace_var(var, new_version)
                UD[(new_version.value(), loc)] = UD.pop((var, loc))


def reach_def_analysis(graph, lparams):
    # We insert two special nodes : entry & exit, to the graph.
    # This is done to simplify the reaching definition analysis.
    old_entry = graph.entry
    old_exit = graph.exit
    new_entry = DummyNode('entry')
    graph.add_node(new_entry)
    graph.add_edge(new_entry, old_entry)
    graph.entry = new_entry
    if old_exit:
        new_exit = DummyNode('exit')
        graph.add_node(new_exit)
        graph.add_edge(old_exit, new_exit)
        graph.rpo.append(new_exit)

    analysis = BasicReachDef(graph, set(lparams))
    analysis.run()

    # The analysis is done, We can now remove the two special nodes.
    graph.remove_node(new_entry)
    if old_exit:
        graph.remove_node(new_exit)
    graph.entry = old_entry
    return analysis


def build_def_use(graph, lparams):
    '''
    Builds the Def-Use and Use-Def (DU/UD) chains of the variables of the
    method.
    '''
    analysis = reach_def_analysis(graph, lparams)

    UD = defaultdict(list)
    for node in graph.rpo:
        for i, ins in node.get_loc_with_ins():
            for var in ins.get_used_vars():
                # var not in analysis.def_to_loc: test that the register
                # exists. It is possible that it is not the case, when a
                # variable is of a type which is stored on multiple registers
                # e.g: a 'double' stored in v3 is also present in v4, so a call
                # to foo(v3), will in fact call foo(v3, v4).
                if var not in analysis.def_to_loc:
                    continue
                ldefs = analysis.defs[node]
                prior_def = -1
                for v in ldefs.get(var, set()):
                    if prior_def < v < i:
                        prior_def = v
                if prior_def >= 0:
                    UD[var, i].append(prior_def)
                else:
                    intersect = analysis.def_to_loc[var].intersection(
                                                            analysis.R[node])
                    UD[var, i].extend(intersect)
    DU = defaultdict(list)
    for var_loc, defs_loc in UD.items():
        var, loc = var_loc
        for def_loc in defs_loc:
            DU[var, def_loc].append(loc)

    return UD, DU


def place_declarations(graph, dvars, du, ud):
    idom = graph.immediate_dominators()
    for node in graph.post_order():
        for loc, ins in node.get_loc_with_ins():
            for var in ins.get_used_vars():
                if (not isinstance(dvars[var], Variable)
                    or isinstance(dvars[var], Param)):
                    continue
                var_defs_locs = ud[var, loc]
                def_nodes = set()
                for def_loc in var_defs_locs:
                    def_node = graph.get_node_from_loc(def_loc)
                    # TODO: place declarations in catch if needed
                    if def_node.in_catch:
                        continue
                    def_nodes.add(def_node)
                if not def_nodes:
                    continue
                common_dominator = def_nodes.pop()
                for def_node in def_nodes:
                    common_dominator = common_dom(
                                      idom, common_dominator, def_node)
                if any(var in range(*common_dominator.ins_range)
                       for var in ud[var, loc]):
                    continue
                common_dominator.add_variable_declaration(dvars[var])
