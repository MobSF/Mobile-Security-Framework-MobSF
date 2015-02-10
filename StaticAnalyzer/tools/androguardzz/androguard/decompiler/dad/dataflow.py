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

from androguard.decompiler.dad.util import build_path


def dominance_frontier(graph, immdoms):
    '''
    Create the dominance frontier of each nodes of the graph.
    The dominance frontier of a node n is the set of all nodes m such that
    n dominates an immediate predecessor of m but does not strictly dominate m.
    '''
    DF = {}
    for node in graph:
        DF[node] = set()
    for node in graph:
        # Nodes in a DF set must be join points in the graph
        preds = graph.preds(node)
        if len(preds) > 1:
            # We found a join point. Now for each of its predecessor we walk up
            # the dominator tree to find a node that dominates it.
            # The join point belong to the DF of all the nodes which are on the
            # dominator tree walk.
            for pred in preds:
                runner = pred
                while runner != immdoms[node]:
                    DF[runner].add(node)
                    runner = immdoms[runner]
    return DF


class BasicReachDef(object):
    def __init__(self, graph, params):
        self.g = graph
        self.A = {}
        self.R = {}
        self.DB = {}
        self.defs = {}
        self.def_to_loc = {}
        # Deal with special entry node
        entry = graph.get_entry()
        self.defs[entry] = {}
        self.A[entry] = set([-1])
        for param in params:
            self.defs[entry][param] = set([-1])
            self.def_to_loc[param] = set([-1])
        # Deal with the other nodes
        for node in graph.get_rpo():
            self.A[node] = set()
            self.R[node] = set()
            self.DB[node] = set()
            self.defs.setdefault(node, dict())
            for i, ins in node.get_loc_with_ins():
                kill = ins.get_lhs()
                if kill is not None:
                    self.defs[node].setdefault(kill, set()).add(i)
                    self.def_to_loc.setdefault(kill, set()).add(i)
            for defs, values in self.defs[node].items():
                self.DB[node].add(max(values))

    def run(self):
        nodes = self.g.get_rpo()[:]
        while nodes:
            node = nodes.pop(0)
            predA = [self.A[p] for p in self.g.preds(node)]
            newR = reduce(set.union, predA, set())
            if predA and newR != self.R[node]:
                self.R[node] = newR
                for suc in self.g.sucs(node):
                    if suc not in nodes:
                        nodes.append(suc)

            killed_locs = set()
            for reg in self.defs[node]:
                for loc in self.def_to_loc[reg]:
                    killed_locs.add(loc)

            A = set()
            for loc in self.R[node]:
                if loc not in killed_locs:
                    A.add(loc)
            newA = A.union(self.DB[node])
            if newA != self.A[node]:
                self.A[node] = newA
                for suc in self.g.sucs(node):
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
        for def_loc in set(ud.get((var, loc), ())):
            # We remove the use of the variable at loc from the DU chain of
            # the variable definition located at def_loc
            du.get((var, def_loc)).remove(loc)
            # If the DU chain of the defined variable is now empty, this means
            # that we may have created a new dead instruction, so we check that
            # the instruction has no side effect and we update the DU chain of
            # the new dead instruction, and we delete it.
            # We also make sure that def_loc is not -1. This is the case when
            # the current variable is a method parameter.
            if  def_loc >= 0 and len(du.get((var, def_loc))) == 0:
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
    for node in graph.get_rpo():
        for i, ins in node.get_loc_with_ins()[:]:
            reg = ins.get_lhs()
            if reg is not None:
                # If the definition is not used, we check that the instruction
                # has no side effect. If there is one and this is a call, we
                # remove only the unused defined variable. else, this is
                # something like an array access, so we do nothing.
                # Otherwise (no side effect) we can remove the instruction from
                # the node.
                if du.get((reg, i), None) is  None:
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
        if ins is None:
            continue
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
    node1 = graph.get_node_from_loc(loc1)
    node2 = graph.get_node_from_loc(loc2)
    # If both instructions are in the same node, we only have to check that the
    # path is clear inside the node
    if node1 is node2:
        return clear_path_node(graph, reg, loc1, loc2)

    # If instructions are in different nodes, we also have to check the nodes
    # in the path between the two locations.
    if not clear_path_node(graph, reg, loc1, node1.ins_range[1]):
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
        for node in graph.get_rpo():
            for i, ins in node.get_loc_with_ins()[:]:
                # We make sure the ins has not been deleted since the start of
                # the iteration
                if ins not in node.get_ins():
                    continue
                for var in ins.get_used_vars():
                    # Get the list of locations this variable is defined at.
                    locs = ud.get((var, i), ())
                    # If the variable is uniquely defined for this instruction
                    # it may be eligible for propagation.
                    if len(locs) != 1:
                        continue

                    loc = locs[0]
                    # Methods parameters are defined with a location of -1.
                    if loc == -1:
                        continue
                    orig_ins = graph.get_ins_from_loc(loc)

                    # We only try to propagate constants and definition
                    # points which are used at only one location.
                    if len(du.get((var, loc), ())) > 1:
                        if not orig_ins.get_rhs().is_const():
                            continue

                    # We defined some instructions as not propagable.
                    # Actually this is the case only for array creation
                    # (new foo[x])
                    if not orig_ins.is_propagable():
                        continue
                    # We check that the propagation is safe for all the
                    # variables that are used in the instruction.
                    # The propagation is not safe if there is a side effect
                    # along the path from the definition of the variable
                    # to its use in the instruction, or if the variable may
                    # be redifined along this path.
                    safe = True
                    for var2 in orig_ins.get_used_vars():
                        # loc is the location of the defined variable
                        # i is the location of the current instruction
                        if not clear_path(graph, var2, loc + 1, i):
                            safe = False
                            break
                    if not safe:
                        continue

                    # We also check that the instruction itself is
                    # propagable. If the instruction has a side effect it
                    # cannot be propagated if there is another side effect
                    # along the path
                    if orig_ins.has_side_effect():
                        if not clear_path(graph, None, loc + 1, i):
                            continue

                    ins.modify_rhs(var, orig_ins.get_rhs())
                    ud[(var, i)].remove(loc)
                    for var2 in orig_ins.get_used_vars():
                        # We update the UD chain of the variables we
                        # propagate. We also have to take the
                        # definition points of all the variables used
                        # by the instruction and update the DU chain
                        # with this information.
                        old_ud = ud.get((var2, loc))
                        # If the instruction use the same variable
                        # multiple times, the second+ time the ud chain
                        # will be None because already treated.
                        if old_ud is None:
                            continue
                        ud.setdefault((var2, i), []).extend(old_ud)
                        ud.pop((var2, loc))

                        for def_loc in old_ud:
                            du.get((var2, def_loc)).remove(loc)
                            du.get((var2, def_loc)).append(i)

                    new_du = du.get((var, loc))
                    new_du.remove(i)
                    if len(new_du) == 0:
                        graph.remove_ins(loc)
                        change = True


class DummyNode(object):
    def __init__(self, name):
        self.name = name

    def get_loc_with_ins(self):
        return []

    def __repr__(self):
        return '%s-dumnode' % self.name

    def __str__(self):
        return '%s-dummynode' % self.name


def build_def_use(graph, lparams):
    '''
    Builds the Def-Use and Use-Def (DU/UD) chains of the variables of the
    method.
    '''
#    if 0:
#        dom_tree = dominator_tree(graph, immdoms)
#        dom_tree.draw(graph.entry.name, 'dad_graphs/dominators', False)

    # We insert two special nodes : entry & exit, to the graph.
    # This is done to simplify the reaching definition analysis.
    old_entry = graph.get_entry()
    old_exit = graph.get_exit()
    new_entry = DummyNode('entry')
    graph.add_node(new_entry)
    graph.add_edge(new_entry, old_entry)
    graph.set_entry(new_entry)
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
    graph.set_entry(old_entry)

    UD = {}
    for node in graph.get_rpo():
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
                    UD.setdefault((var, i), []).append(prior_def)
                else:
                    intersect = analysis.def_to_loc[var].intersection(
                                                            analysis.R[node])
                    UD.setdefault((var, i), []).extend(intersect)
    DU = {}
    for var_loc, defs_loc in UD.items():
        var, loc = var_loc
        for def_loc in defs_loc:
            DU.setdefault((var, def_loc), []).append(loc)

    return UD, DU
