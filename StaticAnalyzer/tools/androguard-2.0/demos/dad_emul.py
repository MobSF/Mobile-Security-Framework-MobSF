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
from androguard.decompiler.dad.instruction import (Constant,
                                                   BinaryCompExpression)


class DemoEmulator(object):
    def __init__(self, graph):
        self.graph = graph
        self.loop = []
        self.mem = {}

    def init(self, key, value):
        self.mem[key] = value

    def visit(self, node):
        if node not in self.loop:
            node.visit(self)

    def visit_ins(self, ins):
        return ins.visit(self)

    def visit_loop_node(self, loop):
        self.loop.append(loop)
        follow = loop.get_loop_follow()
        if loop.looptype.pretest():
            if loop.true is follow:
                loop.neg()
                loop.true, loop.false = loop.false, loop.true
            while loop.visit_cond(self):
                loop.true.visit(self)
        self.loop.pop()
        if follow is not None:
            self.visit(follow)

    def visit_cond_node(self, cond):
        follow = cond.get_if_follow()
        if follow is not None:
            has_else = not (follow in (cond.true, cond.false))
            cnd = cond.visit_cond(self)
            if cnd:
                cond.true.visit(self)
            elif has_else:
                    cond.false.visit(self)
            self.visit(follow)

    def visit_statement_node(self, stmt):
        sucs = self.graph.sucs(stmt)
        for ins in stmt.get_ins():
            self.visit_ins(ins)
        if len(sucs):
            self.visit(sucs[0])

    def visit_return_node(self, ret):
        for ins in ret.get_ins():
            self.visit_ins(ins)

    def visit_constant(self, cst):
        return cst

    def visit_variable(self, var):
        return self.mem[var]

    def visit_param(self, param):
        return param

    def visit_assign(self, lhs, rhs):
        if lhs is None:
            rhs.visit(self)
        else:
            self.mem[lhs.v] = rhs.visit(self)

    def visit_astore(self, array, index, rhs):
        array = array.visit(self)
        if isinstance(index, Constant):
            idx = index.visit(self, 'I')
        else:
            idx = index.visit(self)
        self.mem[array][idx] = rhs.visit(self)

    def visit_return_void(self):
        pass

    def visit_aload(self, array, index):
        arr = array.visit(self)
        idx = index.visit(self)
        return self.mem[arr][idx]

    def visit_alength(self, array):
        return len(self.mem[array.visit(self)])

    def visit_binary_expression(self, op, arg1, arg2):
        arg1 = arg1.visit(self)
        if not isinstance(arg1, int):
            arg1 = ord(arg1)
        arg2 = arg2.visit(self)
        if not isinstance(arg2, int):
            arg2 = ord(arg2)
        return eval('%s %s %s' % (arg1, op, arg2))

    def visit_unary_expression(self, op, arg):
        arg.visit(self)

    def visit_cast(self, op, arg):
        return arg.visit(self)

    def visit_cond_expression(self, op, arg1, arg2):
        arg1 = arg1.visit(self)
        if not isinstance(arg1, int):
            arg1 = ord(arg1)
        arg2 = arg2.visit(self)
        if not isinstance(arg2, int):
            arg2 = ord(arg2)
        return eval('%s %s %s' % (arg1, op, arg2))

    def visit_get_static(self, cls, name):
        return self.mem[name]


TEST = './apks/pacsec/magicspiral.apk'

vm = dvm.DalvikVMFormat(apk.APK(TEST).get_dex())
vma = uVMAnalysis(vm)

method = vm.get_method('crypt')[0]

amethod = vma.get_method(method)
dvmethod = DvMethod(amethod)
dvmethod.process()  # build IR Form / control flow...

graph = dvmethod.graph
visitor = DemoEmulator(graph)

l = [94, 42, 93, 88, 3, 2, 95, 2, 13, 85, 11, 2, 19, 1, 125, 19, 0, 102,
     30, 24, 19, 99, 76, 21, 102, 22, 26, 111, 39, 125, 2, 44, 80, 10, 90,
     5, 119, 100, 119, 60, 4, 87, 79, 42, 52]
visitor.init(dvmethod.lparams[0], l)

KEYVALUE = '6^)(9-p35a%3#4S!4S0)$Yt%^&5(j.g^&o(*0)$Yv!#O@6GpG@=+3j.&6^)(0-=1'
visitor.init('KEYVALUE', '[BKEYVALUE')
visitor.init('[BKEYVALUE', KEYVALUE)

visitor.init('keylen', len(KEYVALUE))

method.show()

def show_mem(visitor):
    print 'Memory[4]: %s' % visitor.mem[4]
    print '==> %r' % ''.join(chr(i) for i in visitor.mem[4])

show_mem(visitor)
print '\nStarting visit...',
graph.get_entry().visit(visitor)
print ' done !\n'
show_mem(visitor)

