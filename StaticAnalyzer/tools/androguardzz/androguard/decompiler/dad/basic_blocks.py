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
from androguard.decompiler.dad.opcode_ins import INSTRUCTION_SET
from androguard.decompiler.dad.instruction import Variable
from androguard.decompiler.dad.node import Node


logger = logging.getLogger('dad.basic_blocks')


class BasicBlock(Node):
    def __init__(self, name, block_ins):
        super(BasicBlock, self).__init__(name)
        self.ins = block_ins
        self.ins_range = None
        self.loc_ins = None

    def get_ins(self):
        return self.ins

    def get_loc_with_ins(self):
        if self.loc_ins is None:
            self.loc_ins = zip(range(*self.ins_range), self.ins)
        return self.loc_ins

    def remove_ins(self, loc, ins):
        self.ins.remove(ins)
        self.loc_ins.remove((loc, ins))

    def add_ins(self, new_ins_list):
        for new_ins in new_ins_list:
            self.ins.append(new_ins)
        self.ins_range[1] += len(new_ins_list)

    def number_ins(self, num):
        last_ins_num = num + len(self.ins)
        self.ins_range = [num, last_ins_num]
        self.loc_ins = None
        return last_ins_num


class StatementBlock(BasicBlock):
    def __init__(self, name, block_ins):
        super(StatementBlock, self).__init__(name, block_ins)

    def visit(self, visitor):
        return visitor.visit_statement_node(self)

    def __str__(self):
        return '%d-Statement(%s)' % (self.num, self.name)


class ReturnBlock(BasicBlock):
    def __init__(self, name, block_ins):
        super(ReturnBlock, self).__init__(name, block_ins)

    def visit(self, visitor):
        return visitor.visit_return_node(self)

    def __str__(self):
        return '%d-Return(%s)' % (self.num, self.name)


class ThrowBlock(BasicBlock):
    def __init__(self, name, block_ins):
        super(ThrowBlock, self).__init__(name, block_ins)

    def visit(self, visitor):
        return visitor.visit_throw_node(self)

    def __str__(self):
        return '%d-Throw(%s)' % (self.num, self.name)


class SwitchBlock(BasicBlock):
    def __init__(self, name, switch, block_ins):
        super(SwitchBlock, self).__init__(name, block_ins)
        self.switch = switch
        self.cases = []
        self.default = None
        self.node_to_case = {}

    def add_case(self, case):
        self.cases.append(case)

    def visit(self, visitor):
        return visitor.visit_switch_node(self)

    def copy_from(self, node):
        super(SwitchBlock, self).copy_from(node)
        self.cases = node.cases
        self.switch = node.switch

    def update_attribute_with(self, n_map):
        super(SwitchBlock, self).update_attribute_with(n_map)
        self.cases = [n_map.get(n, n) for n in self.cases]
        for node1, node2 in n_map.iteritems():
            if node1 in self.node_to_case:
                self.node_to_case[node2] = self.node_to_case.pop(node1)

    def order_cases(self):
        values = self.switch.get_values()
        if len(values) < len(self.cases):
            self.default = self.cases.pop(0)
        for case, node in zip(values, self.cases):
            self.node_to_case.setdefault(node, []).append(case)

    def __str__(self):
        return '%d-Switch(%s)' % (self.num, self.name)


class CondBlock(BasicBlock):
    def __init__(self, name, block_ins):
        super(CondBlock, self).__init__(name, block_ins)
        self.true = None
        self.false = None

    def set_true(self, node):
        self.true = node

    def set_false(self, node):
        self.false = node

    def update_attribute_with(self, n_map):
        super(CondBlock, self).update_attribute_with(n_map)
        self.true = n_map.get(self.true, self.true)
        self.false = n_map.get(self.false, self.false)

    def neg(self):
        if len(self.ins) > 1:
            raise ('Condition should have only 1 instruction !')
        self.ins[0].neg()

    def visit(self, visitor):
        return visitor.visit_cond_node(self)

    def visit_cond(self, visitor):
        if len(self.ins) > 1:
            raise ('Condition should have only 1 instruction !')
        return visitor.visit_ins(self.ins[0])

    def __str__(self):
        return '%d-If(%s)' % (self.num, self.name)


class Condition(object):
    def __init__(self, cond1, cond2, isand, isnot):
        self.cond1 = cond1
        self.cond2 = cond2
        self.isand = isand
        self.isnot = isnot

    def neg(self):
        self.isand = not self.isand
        self.cond1.neg()
        self.cond2.neg()

    def get_ins(self):
        lins = []
        lins.extend(self.cond1.get_ins())
        lins.extend(self.cond2.get_ins())
        return lins

    def get_loc_with_ins(self):
        loc_ins = []
        loc_ins.extend(self.cond1.get_loc_with_ins())
        loc_ins.extend(self.cond2.get_loc_with_ins())
        return loc_ins

    def visit(self, visitor):
        return visitor.visit_short_circuit_condition(self.isnot, self.isand,
                                             self.cond1, self.cond2)

    def __str__(self):
        if self.isnot:
            ret = '!%s %s %s'
        else:
            ret = '%s %s %s'
        return ret % (self.cond1, ['||', '&&'][self.isand], self.cond2)


class ShortCircuitBlock(CondBlock):
    def __init__(self, name, cond):
        super(ShortCircuitBlock, self).__init__(name, None)
        self.cond = cond

    def get_ins(self):
        return self.cond.get_ins()

    def get_loc_with_ins(self):
        return self.cond.get_loc_with_ins()

    def neg(self):
        self.cond.neg()

    def visit_cond(self, visitor):
        return self.cond.visit(visitor)

    def __str__(self):
        return '%d-SC(%s)' % (self.num, self.cond)


class LoopBlock(CondBlock):
    def __init__(self, name, cond):
        super(LoopBlock, self).__init__(name, None)
        self.cond = cond

    def get_ins(self):
        return self.cond.get_ins()

    def neg(self):
        self.cond.neg()

    def get_loc_with_ins(self):
        return self.cond.get_loc_with_ins()

    def visit(self, visitor):
        return visitor.visit_loop_node(self)

    def visit_cond(self, visitor):
        return self.cond.visit_cond(visitor)

    def update_attribute_with(self, n_map):
        super(LoopBlock, self).update_attribute_with(n_map)
        self.cond.update_attribute_with(n_map)

    def __str__(self):
        if self.looptype.pretest():
            if self.false in self.loop_nodes:
                return '%d-While(!%s)[%s]' % (self.num, self.name, self.cond)
            else:
                return '%d-While(%s)[%s]' % (self.num, self.name, self.cond)
        elif self.looptype.posttest():
            return '%d-DoWhile(%s)[%s]' % (self.num, self.name, self.cond)
        elif self.looptype.endless():
            return '%d-WhileTrue(%s)[%s]' % (self.num, self.name, self.cond)
        return '%dWhileNoType(%s)' % (self.num, self.name)


class TryBlock(BasicBlock):
    def __init__(self, name, block_ins):
        super(TryBlock, self).__init__(name, block_ins)
        self.catch = []

    def add_catch(self, node):
        self.catch.append(node)

    def __str__(self):
        return 'Try(%s)' % self.name


class CatchBlock(BasicBlock):
    def __init__(self, name, block_ins, typeh):
        super(CatchBlock, self).__init__(name, block_ins)
        self.exception_type = typeh

    def __str__(self):
        return 'Catch(%s)' % self.name


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


def build_node_from_block(block, vmap, gen_ret):
    ins, lins = None, []
    idx = block.get_start()
    for ins in block.get_instructions():
        opcode = ins.get_op_value()
        if opcode == 0x1f:  # check-cast
            idx += ins.get_length()
            continue
        _ins = INSTRUCTION_SET.get(ins.get_name().lower())
        if _ins is None:
            logger.error('Unknown instruction : %s.', _ins.get_name().lower())
        # fill-array-data
        if opcode == 0x26:
            fillaray = block.get_special_ins(idx)
            lins.append(_ins(ins, vmap, fillaray))
        # invoke-kind[/range]
        elif (0x6e <= opcode <= 0x72 or 0x74 <= opcode <= 0x78):
            lins.append(_ins(ins, vmap, gen_ret))
        # filled-new-array[/range]
        elif 0x24 <= opcode <= 0x25:
            lins.append(_ins(ins, vmap, gen_ret.new()))
        # move-result*
        elif 0xa <= opcode <= 0xc:
            lins.append(_ins(ins, vmap, gen_ret.last()))
        else:
            lins.append(_ins(ins, vmap))
        idx += ins.get_length()
    name = block.get_name()
    # return*
    if 0xe <= opcode <= 0x11:
        node = ReturnBlock(name, lins)
        node.set_return()
    # {packed,sparse}-switch
    elif 0x2b <= opcode <= 0x2c:
        idx -= ins.get_length()
        values = block.get_special_ins(idx)
        node = SwitchBlock(name, values, lins)
        node.set_switch()
    # if-test[z]
    elif 0x32 <= opcode <= 0x3d:
        node = CondBlock(name, lins)
        node.set_cond()
        node.off_last_ins = ins.get_ref_off()
    # throw
    elif opcode == 0x27:
        node = ThrowBlock(name, lins)
        node.set_throw()
    else:
        # goto*
        if 0x28 <= opcode <= 0x2a:
            lins.pop()
        node = StatementBlock(name, lins)
        node.set_stmt()
    return node
