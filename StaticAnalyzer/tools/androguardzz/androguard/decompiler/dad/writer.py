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
from androguard.decompiler.dad.util import get_type, ACCESS_FLAGS_METHODS
from androguard.decompiler.dad.opcode_ins import Op
from androguard.decompiler.dad.instruction import (Constant, ThisParam,
                                                   BinaryCompExpression)


logger = logging.getLogger('dad.writer')


class Writer(object):
    def __init__(self, graph, method):
        self.graph = graph
        self.method = method
        self.visited_nodes = set()
        self.ind = 4
        self.buffer = []
        self.loop_follow = [None]
        self.latch_node = [None]
        self.if_follow = [None]
        self.switch_follow = [None]
        self.next_case = None
        self.skip = False
        self.need_break = True

    def __str__(self):
        return ''.join(self.buffer)

    def inc_ind(self, i=1):
        self.ind += (4 * i)

    def dec_ind(self, i=1):
        self.ind -= (4 * i)

    def space(self):
        if self.skip:
            self.skip = False
            return ''
        return ' ' * self.ind

    def write_ind(self):
        if self.skip:
            self.skip = False
        else:
            self.write(self.space())

    def write(self, s):
        self.buffer.append(s)

    def end_ins(self):
        self.write(';\n')

    def visit_ins(self, ins):
        ins.visit(self)

    def write_method(self):
        acc = []
        access = self.method.access
        self.constructor = 0x10000 in access
        for i in self.method.access:
            if i == 0x10000:
                continue
            acc.append(ACCESS_FLAGS_METHODS.get(i))
        if self.constructor:
            name = get_type(self.method.cls_name).split('.')[-1]
            proto = '%s %s(' % (' '.join(acc), name)
        else:
            name = self.method.name
            proto = '%s %s %s(' % (' '.join(acc), self.method.type, name)
        self.write('%s%s' % (self.space(), proto))
        if 0x8 in self.method.access:
            params = self.method.lparams
        else:
            params = self.method.lparams[1:]
        proto = ''
        if self.method.params_type:
            proto = ', '.join(['%s p%s' % (get_type(p_type), param) for
                        p_type, param in zip(self.method.params_type, params)])
        self.write('%s)' % proto)
        if self.graph is None:
            return self.write(';')
        self.write('\n%s{\n' % self.space())
        self.inc_ind()
#        for v, var in self.method.var_to_name.iteritems():
#            var.visit_decl(self)
        self.visit_node(self.graph.get_entry())
        self.dec_ind()
        self.write('%s}\n' % self.space())

    def visit_node(self, node):
        if node in (self.if_follow[-1], self.switch_follow[-1],
                    self.loop_follow[-1], self.latch_node[-1]):
            return
        if node in self.visited_nodes:
            return
        self.visited_nodes.add(node)
        node.visit(self)

    def visit_loop_node(self, loop):
        follow = loop.get_loop_follow()
        if follow is None and not loop.looptype.endless():
            logger.error('Loop has no follow !')
        if loop.looptype.pretest():
            if loop.true is follow:
                loop.neg()
                loop.true, loop.false = loop.false, loop.true
            self.write('%swhile (' % self.space())
            loop.visit_cond(self)
            self.write(') {\n')
        elif loop.looptype.posttest():
            self.write('%sdo {\n' % self.space())
            self.latch_node.append(loop.latch)
        elif loop.looptype.endless():
            self.write('%swhile(true) {\n' % self.space())
        self.inc_ind()
        self.loop_follow.append(follow)
        if loop.looptype.pretest():
            self.visit_node(loop.true)
        else:
            self.visit_node(loop.cond)
        self.loop_follow.pop()
        self.dec_ind()
        if loop.looptype.pretest():
            self.write('%s}\n' % self.space())
        elif loop.looptype.posttest():
            self.latch_node.pop()
            self.write('%s} while(' % self.space())
            loop.latch.visit_cond(self)
            self.write(');\n')
        else:
            self.inc_ind()
            self.visit_node(loop.latch)
            self.dec_ind()
            self.write('%s}\n' % self.space())
        if follow is not None:
            self.visit_node(follow)

    def visit_cond_node(self, cond):
        follow = cond.get_if_follow()
        if cond.false is self.loop_follow[-1]:
            cond.neg()
            cond.true, cond.false = cond.false, cond.true
            self.write('%sif(' % self.space())
            cond.visit_cond(self)
            self.write(') {\n')
            self.inc_ind()
            self.write('%sbreak;\n' % self.space())
            self.dec_ind()
            self.write('%s}\n' % self.space())
            self.visit_node(cond.false)
        elif follow is not None:
            is_else = not (follow in (cond.true, cond.false))
            if (cond.true in (follow, self.next_case)
                                                or cond.num > cond.true.num):
                cond.neg()
                cond.true, cond.false = cond.false, cond.true
            self.if_follow.append(follow)
            if not cond.true in self.visited_nodes:
                self.write('%sif(' % self.space())
                cond.visit_cond(self)
                self.write(') {\n')
                self.inc_ind()
                self.visit_node(cond.true)
                self.dec_ind()
            if is_else and not cond.false in self.visited_nodes:
                self.write('%s} else {\n' % self.space())
                self.inc_ind()
                self.visit_node(cond.false)
                self.dec_ind()
            self.if_follow.pop()
            self.write('%s}\n' % self.space())
            self.visit_node(follow)
        else:
            self.write('%sif (' % self.space())
            cond.visit_cond(self)
            self.write(') {\n')
            self.inc_ind()
            self.visit_node(cond.true)
            self.dec_ind()
            self.write('%s} else {\n' % self.space())
            self.inc_ind()
            self.visit_node(cond.false)
            self.dec_ind()
            self.write('%s}\n' % self.space())

    def visit_short_circuit_condition(self, nnot, aand, cond1, cond2):
        if nnot:
            cond1.neg()
        self.write('(')
        cond1.visit_cond(self)
        self.write(') %s (' % ['||', '&&'][aand])
        cond2.visit_cond(self)
        self.write(')')

    def visit_switch_node(self, switch):
        lins = switch.get_ins()
        for ins in lins[:-1]:
            self.visit_ins(ins)
        switch_ins = switch.get_ins()[-1]
        self.write('%sswitch(' % self.space())
        self.visit_ins(switch_ins)
        self.write(') {\n')
        follow = switch.switch_follow
        cases = switch.cases
        self.switch_follow.append(follow)
        default = switch.default
        for i, node in enumerate(cases):
            if node in self.visited_nodes:
                continue
            self.inc_ind()
            for case in switch.node_to_case[node]:
                self.write('%scase %d:\n' % (self.space(), case))
            if i + 1 < len(cases):
                self.next_case = cases[i + 1]
            else:
                self.next_case = None
            if node is default:
                self.write('%sdefault:\n' % self.space())
                default = None
            self.inc_ind()
            self.visit_node(node)
            if self.need_break:
                self.write('%sbreak;\n' % self.space())
            else:
                self.need_break = True
            self.dec_ind(2)
        if default not in (None, follow):
            self.inc_ind()
            self.write('%sdefault:\n' % self.space())
            self.inc_ind()
            self.visit_node(default)
            self.dec_ind(2)
        self.write('%s}\n' % self.space())
        self.switch_follow.pop()
        self.visit_node(follow)

    def visit_statement_node(self, stmt):
        sucs = self.graph.sucs(stmt)
        for ins in stmt.get_ins():
            self.visit_ins(ins)
        if len(sucs) == 0:
            return
        follow = sucs[0]
        self.visit_node(follow)

    def visit_return_node(self, ret):
        self.need_break = False
        for ins in ret.get_ins():
            self.visit_ins(ins)

    def visit_throw_node(self, throw):
        for ins in throw.get_ins():
            self.visit_ins(ins)

#    def visit_decl(self, var):
#        self.write('%sdecl v%s' % (SPACE * self.ind, var))
#        self.end_ins()

    def visit_constant(self, cst):
        if isinstance(cst, str):
            return self.write(string('%s' % cst))
        self.write('%s' % cst)

    def visit_base_class(self, cls):
        self.write(cls)

    def visit_variable(self, var):
        if isinstance(var, str):
            return self.write(var)
        self.write('v%d' % var)

    def visit_param(self, param):
        self.write('p%s' % param)

    def visit_this(self):
        self.write('this')

    def visit_assign(self, lhs, rhs):
        self.write_ind()
        if lhs is None:
            rhs.visit(self)
            if not self.skip:
                self.end_ins()
            return
        lhs.visit(self)
        self.write(' = ')
        rhs.visit(self)
        self.end_ins()

    def visit_move_result(self, lhs, rhs):
        self.write_ind()
        lhs.visit(self)
        self.write(' = ')
        rhs.visit(self)
        self.end_ins()

    def visit_move(self, lhs, rhs):
        if lhs is rhs:
            return
        self.write_ind()
        lhs.visit(self)
        self.write(' = ')
        rhs.visit(self)
        self.end_ins()

    def visit_astore(self, array, index, rhs):
        self.write_ind()
        array.visit(self)
        self.write('[')
        if isinstance(index, Constant):
            index.visit(self, 'I')
        else:
            index.visit(self)
        self.write('] = ')
        rhs.visit(self)
        self.end_ins()

    def visit_put_static(self, cls, name, rhs):
        self.write_ind()
        self.write('%s.%s = ' % (cls, name))
        rhs.visit(self)
        self.end_ins()

    def visit_put_instance(self, lhs, name, rhs):
        self.write_ind()
        lhs.visit(self)
        self.write('.%s = ' % name)
        rhs.visit(self)
        self.end_ins()

    def visit_new(self, atype):
        self.write('new %s' % get_type(atype))

    def visit_invoke(self, name, base, ptype, rtype, args):
        if isinstance(base, ThisParam):
            if name == '<init>' and self.constructor and len(args) == 0:
                self.skip = True
                return
        base.visit(self)
        if name != '<init>':
            self.write('.%s' % name)
        self.write('(')
        comma = False
        for arg in args:
            if comma:
                self.write(', ')
            comma = True
            arg.visit(self)
        self.write(')')

    def visit_return_void(self):
        self.write_ind()
        self.write('return')
        self.end_ins()

    def visit_return(self, arg):
        self.write_ind()
        self.write('return ')
        arg.visit(self)
        self.end_ins()

    def visit_nop(self):
        pass

    def visit_switch(self, arg):
        arg.visit(self)

    def visit_check_cast(self, arg, atype):
        self.write('(checkcast)(')
        arg.visit(self)
        self.write(', %s)' % atype)

    def visit_aload(self, array, index):
        array.visit(self)
        self.write('[')
        index.visit(self)
        self.write(']')

    def visit_alength(self, array):
        array.visit(self)
        self.write('.length')

    def visit_new_array(self, atype, size):
        self.write('new %s[' % get_type(atype[1:]))
        size.visit(self)
        self.write(']')

    def visit_filled_new_array(self, atype, size, args):
        self.write('filled-new-array(type=')
        atype.visit(self)
        self.write(', size=')
        size.visit(self)
        for arg in args:
            self.write(', arg=')
            arg.visit(self)
        self.write(')')

    def visit_fill_array(self, array, value):
        self.write_ind()
        array.visit(self)
        self.write(' = {')
        data = value.get_data()
        self.write(', '.join(['%d' % ord(c) for c in data[:-1]]))
        self.write('}')
        self.end_ins()

    def visit_monitor_enter(self, ref):
        self.write_ind()
        self.write('synchronized(')
        ref.visit(self)
        self.write(') {\n')
        self.inc_ind()

    def visit_monitor_exit(self, ref):
        self.dec_ind()
        self.write_ind()
        self.write('}\n')

    def visit_throw(self, ref):
        self.write_ind()
        self.write('throw ')
        ref.visit(self)
        self.end_ins()

    def visit_binary_expression(self, op, arg1, arg2):
        self.write('(')
        arg1.visit(self)
        self.write(' %s ' % op)
        arg2.visit(self)
        self.write(')')

    def visit_unary_expression(self, op, arg):
        self.write('(%s ' % op)
        arg.visit(self)
        self.write(')')

    def visit_cast(self, op, arg):
        self.write('(%s ' % op)
        arg.visit(self)
        self.write(')')

    def visit_cond_expression(self, op, arg1, arg2):
        arg1.visit(self)
        self.write(' %s ' % op)
        arg2.visit(self)

    def visit_condz_expression(self, op, arg):
        if isinstance(arg, BinaryCompExpression):
            arg.op = op
            return arg.visit(self)
        atype = arg.get_type()
        if atype == 'Z':
            if op is Op.EQUAL:
                self.write('!')
                arg.visit(self)
            else:
                arg.visit(self)
        else:
            arg.visit(self)
            self.write(' %s 0' % op)

    def visit_get_instance(self, arg, name):
        arg.visit(self)
        self.write('.%s' % name)

    def visit_get_static(self, cls, name):
        self.write('%s.%s' % (cls, name))


def string(s):
    # Based on http://stackoverflow.com/a/1676407
    ret = ['"']
    for c in s:
        if ord(c) < 32 or 0x80 <= ord(c) <= 0xff:
            to_add = '\\x%02x' % ord(c)
        elif c in '\\"':
            to_add = '%c' % c
        else:
            to_add = c
        ret.append(to_add)
    ret.append('"')
    return ''.join(ret)
