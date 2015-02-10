#!/usr/bin/env python
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

import sys
sys.path.append('./')

from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis.analysis import uVMAnalysis
from androguard.decompiler.dad.decompile import DvMethod
from androguard.decompiler.dad.instruction import Constant, BinaryCompExpression


class PrintVisitor(object):
    def __init__(self, graph):
        self.graph = graph
        self.visited_nodes = set()
        self.loop_follow = [None]
        self.latch_node = [None]
        self.if_follow = [None]
        self.switch_follow = [None]
        self.next_case = None

    def visit_ins(self, ins):
        return ins.visit(self)

    def visit_node(self, node):
        if node in (self.if_follow[-1], self.switch_follow[-1],
                    self.loop_follow[-1], self.latch_node[-1]):
            return
        if node in self.visited_nodes:
            return
        self.visited_nodes.add(node)
        node.visit(self)

    def visit_loop_node(self, loop):
        print '- Loop node', loop.num
        follow = loop.get_loop_follow()
        if follow is None and not loop.looptype.endless():
            exit('Loop has no follow !', 'error')
        if loop.looptype.pretest():
            if loop.true is follow:
                loop.neg()
                loop.true, loop.false = loop.false, loop.true
            cnd = loop.visit_cond(self)
            print 'while(%s) {' % cnd
        elif loop.looptype.posttest():
            print 'do {'
            self.latch_node.append(loop.latch)
        elif loop.looptype.endless():
            print 'while(true) {'
            pass
        self.loop_follow.append(follow)
        if loop.looptype.pretest():
            self.visit_node(loop.true)
        else:
            self.visit_node(loop.cond)
        self.loop_follow.pop()
        if loop.looptype.pretest():
            print '}'
        elif loop.looptype.posttest():
            print '} while(',
            self.latch_node.pop()
            loop.latch.visit_cond(self)
            print ')'
        else:
            self.visit_node(loop.latch)
        if follow is not None:
            self.visit_node(follow)

    def visit_cond_node(self, cond):
        print '- Cond node', cond.num
        follow = cond.get_if_follow()
        if cond.false is self.loop_follow[-1]:
            cond.neg()
            cond.true, cond.false = cond.false, cond.true
            cond.visit_cond(self)
            self.visit_node(cond.false)
        elif follow is not None:
            is_else = not (follow in (cond.true, cond.false))
            if (cond.true in (follow, self.next_case)
                                                or cond.num > cond.true.num):
                cond.neg()
                cond.true, cond.false = cond.false, cond.true
            self.if_follow.append(follow)
            if not cond.true in self.visited_nodes:
                cnd = cond.visit_cond(self)
                print 'if (%s) {' % cnd
                self.visit_node(cond.true)
            if is_else and not cond.false in self.visited_nodes:
                print '} else {'
                self.visit_node(cond.false)
            print '}'
            self.if_follow.pop()
            self.visit_node(follow)
        else:
            cond.visit_cond(self)
            self.visit_node(cond.true)
            self.visit_node(cond.false)

    def visit_short_circuit_condition(self, nnot, aand, cond1, cond2):
        if nnot:
            cond1.neg()
        cond1.visit_cond(self)
        cond2.visit_cond(self)

    def visit_switch_node(self, switch):
        lins = switch.get_ins()
        for ins in lins[:-1]:
            self.visit_ins(ins)
        switch_ins = switch.get_ins()[-1]
        self.visit_ins(switch_ins)
        follow = switch.switch_follow
        cases = switch.cases
        self.switch_follow.append(follow)
        default = switch.default
        for i, node in enumerate(cases):
            if node in self.visited_nodes:
                continue
            for case in switch.node_to_case[node]:
                pass
            if i + 1 < len(cases):
                self.next_case = cases[i + 1]
            else:
                self.next_case = None
            if node is default:
                default = None
            self.visit_node(node)
        if default not in (None, follow):
            self.visit_node(default)
        self.switch_follow.pop()
        self.visit_node(follow)

    def visit_statement_node(self, stmt):
        print '- Statement node', stmt.num
        sucs = self.graph.sucs(stmt)
        for ins in stmt.get_ins():
            self.visit_ins(ins)
        if len(sucs) == 0:
            return
        follow = sucs[0]
        self.visit_node(follow)

    def visit_return_node(self, ret):
        print '- Return node', ret.num
        for ins in ret.get_ins():
            self.visit_ins(ins)

    def visit_throw_node(self, throw):
        for ins in throw.get_ins():
            self.visit_ins(ins)

    def visit_constant(self, cst):
        return cst

    def visit_base_class(self, cls):
        return cls

    def visit_variable(self, var):
        return 'v%s' % var

    def visit_param(self, param):
        return 'p%s' % param

    def visit_this(self):
        return 'this'

    def visit_assign(self, lhs, rhs):
        if lhs is None:
            rhs.visit(self)
            return
        l = lhs.visit(self)
        r = rhs.visit(self)
        print '%s = %s;' % (l, r)

    def visit_move_result(self, lhs, rhs):
        l = lhs.visit(self)
        r = rhs.visit(self)
        print '%s = %s;' % (l, r)

    def visit_move(self, lhs, rhs):
        if lhs is rhs:
            return
        l = lhs.visit(self)
        r = rhs.visit(self)
        print '%s = %s;' % (l, r)

    def visit_astore(self, array, index, rhs):
        arr = array.visit(self)
        if isinstance(index, Constant):
            idx = index.visit(self, 'I')
        else:
            idx = index.visit(self)
        r = rhs.visit(self)
        print '%s[%s] = %s' % (arr, idx, r)

    def visit_put_static(self, cls, name, rhs):
        r = rhs.visit(self)
        return '%s.%s = %s' % (cls, name, r)

    def visit_put_instance(self, lhs, name, rhs):
        l = lhs.visit(self)
        r = rhs.visit(self)
        return '%s.%s = %s' % (l, name, r)

    def visit_new(self, atype):
        pass

    def visit_invoke(self, name, base, args):
        base.visit(self)
        for arg in args:
            arg.visit(self)

    def visit_return_void(self):
        print 'return;'

    def visit_return(self, arg):
        a = arg.visit(self)
        print 'return %s;' % a

    def visit_nop(self):
        pass

    def visit_switch(self, arg):
        arg.visit(self)

    def visit_check_cast(self, arg, atype):
        arg.visit(self)

    def visit_aload(self, array, index):
        arr = array.visit(self)
        idx = index.visit(self)
        return '%s[%s]' % (arr, idx)

    def visit_alength(self, array):
        res = array.visit(self)
        return '%s.length' % res

    def visit_new_array(self, atype, size):
        size.visit(self)

    def visit_filled_new_array(self, atype, size, args):
        atype.visit(self)
        size.visit(self)
        for arg in args:
            arg.visit(self)

    def visit_fill_array(self, array, value):
        array.visit(self)

    def visit_monitor_enter(self, ref):
        ref.visit(self)

    def visit_monitor_exit(self, ref):
        pass

    def visit_throw(self, ref):
        ref.visit(self)

    def visit_binary_expression(self, op, arg1, arg2):
        val1 = arg1.visit(self)
        val2 = arg2.visit(self)
        return '%s %s %s' % (val1, op, val2)

    def visit_unary_expression(self, op, arg):
        arg.visit(self)

    def visit_cast(self, op, arg):
        a = arg.visit(self)
        return '(%s %s)' % (op, a)

    def visit_cond_expression(self, op, arg1, arg2):
        val1 = arg1.visit(self)
        val2 = arg2.visit(self)
        return '%s %s %s' % (val1, op, val2)

    def visit_condz_expression(self, op, arg):
        if isinstance(arg, BinaryCompExpression):
            arg.op = op
            arg.visit(self)
        else:
            arg.visit(self)

    def visit_get_instance(self, arg, name):
        arg.visit(self)

    def visit_get_static(self, cls, name):
        return '%s.%s' % (cls, name)

TEST = '../DroidDream/magicspiral.apk'

vm = dvm.DalvikVMFormat(apk.APK(TEST).get_dex())
vma = uVMAnalysis(vm)

method = vm.get_method('crypt')[0]
method.show()

amethod = vma.get_method(method)
dvmethod = DvMethod(amethod)

dvmethod.process() # build IR Form / control flow...

graph = dvmethod.graph

print 'Entry block : %s\n' % graph.get_entry()

for block in graph: # graph.get_rpo() to iterate in reverse post order
    print 'Block : %s' % block
    for ins in block.get_ins():
        print '  - %s' % ins
print

visitor = PrintVisitor(graph)
graph.get_entry().visit(visitor)
