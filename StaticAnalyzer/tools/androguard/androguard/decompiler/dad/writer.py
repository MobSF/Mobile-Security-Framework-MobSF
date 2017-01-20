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
from struct import unpack
from androguard.decompiler.dad.util import get_type
from androguard.decompiler.dad.opcode_ins import Op
from androguard.decompiler.dad.instruction import (Constant, ThisParam,
                                                   BinaryExpression,
                                                   BaseClass,
                                                   InstanceExpression,
                                                   NewInstance,
                                                   Variable,
                                                   BinaryCompExpression)


logger = logging.getLogger('dad.writer')


class Writer(object):
    def __init__(self, graph, method):
        self.graph = graph
        self.method = method
        self.visited_nodes = set()
        self.ind = 4
        self.buffer = []
        self.buffer2 = []
        self.loop_follow = [None]
        self.if_follow = [None]
        self.switch_follow = [None]
        self.latch_node = [None]
        self.try_follow = [None]
        self.next_case = None
        self.skip = False
        self.need_break = True

    def __str__(self):
        return ''.join(self.buffer)

    def str_ext(self):
        return self.buffer2

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
            self.write_ext(('INDENTATION', self.space()))

    def write(self, s, data=None):
        self.buffer.append(s)
        # old method, still used
        # TODO: clean?
        if data:
            self.buffer2.append((data, s))

    # at minimum, we have t as a tuple of the form:
    # (TYPE_STR, MY_STR) such as ('THIS', 'this')
    # where the 2nd field is the actual generated source code
    # We can have more fields, for example:
    # ('METHOD', 'sendToServer', 'this -> sendToServer', <androguard.decompiler.dad.instruction.ThisParam>)
    def write_ext(self, t):
        if not isinstance(t, tuple):
            raise "Error in write_ext: %s not a tuple" % str(t)
        self.buffer2.append(t)

    def end_ins(self):
        self.write(';\n')
        self.write_ext(('END_INSTRUCTION', ';\n'))

    def write_ind_visit_end(self, lhs, s, rhs=None, data=None):
        self.write_ind()
        lhs.visit(self)
        self.write(s)
        self.write_ext(('TODO_4343', s, data))
        if rhs is not None:
            rhs.visit(self)
        self.end_ins()

    #TODO: prefer this class as write_ind_visit_end that should be deprecated
    # at the end
    def write_ind_visit_end_ext(self, lhs, before, s, after, rhs=None,
                                data=None, subsection='UNKNOWN_SUBSECTION'):
        self.write_ind()
        lhs.visit(self)
        self.write(before + s + after)
        self.write_ext(('BEFORE', before))
        self.write_ext((subsection, s, data))
        self.write_ext(('AFTER', after))
        if rhs is not None:
            rhs.visit(self)
        self.end_ins()

    def write_inplace_if_possible(self, lhs, rhs):
        if isinstance(rhs, BinaryExpression) and lhs == rhs.var_map[rhs.arg1]:
            exp_rhs = rhs.var_map[rhs.arg2]
            if rhs.op in '+-' and isinstance(exp_rhs, Constant) and\
                                  exp_rhs.get_int_value() == 1:
                return self.write_ind_visit_end(lhs, rhs.op * 2, data=rhs)
            return self.write_ind_visit_end(
                lhs, ' %s= ' % rhs.op, exp_rhs, data=rhs)
        return self.write_ind_visit_end(lhs, ' = ', rhs, data=rhs)

    def visit_ins(self, ins):
        ins.visit(self)

    def write_method(self):
        acc = []
        access = self.method.access
        self.constructor = False
        for modifier in access:
            if modifier == 'constructor':
                self.constructor = True
                continue
            acc.append(modifier)
        self.write('\n%s' % self.space())
        self.write_ext(('NEWLINE', '\n%s' % (self.space())))
        if acc:
            self.write('%s ' % ' '.join(acc))
            self.write_ext(('PROTOTYPE_ACCESS', '%s ' % ' '.join(acc)))
        if self.constructor:
            name = get_type(self.method.cls_name).split('.')[-1]
            self.write(name)
            self.write_ext(('NAME_METHOD_PROTOTYPE', '%s' % name, self.method))
        else:
            self.write(
                '%s %s' % (get_type(self.method.type), self.method.name))
            self.write_ext(
                ('PROTOTYPE_TYPE', '%s' % get_type(self.method.type)))
            self.write_ext(('SPACE', ' '))
            self.write_ext(
                ('NAME_METHOD_PROTOTYPE',
                '%s' % self.method.name, self.method))
        params = self.method.lparams
        if 'static' not in access:
            params = params[1:]
        proto = ''
        self.write_ext(('PARENTHESIS_START', '('))
        if self.method.params_type:
            proto = ', '.join(['%s p%s' % (get_type(p_type), param) for
                        p_type, param in zip(self.method.params_type, params)])
            first = True
            for p_type, param in zip(self.method.params_type, params):
                if not first:
                    self.write_ext(('COMMA', ', '))
                else:
                    first = False
                self.write_ext(('ARG_TYPE', '%s' % get_type(p_type)))
                self.write_ext(('SPACE', ' '))
                self.write_ext(
                    ('NAME_ARG', 'p%s' % param, p_type, self.method))
        self.write_ext(('PARENTHESIS_END', ')'))
        self.write('(%s)' % proto)
        if self.graph is None:
            self.write(';\n')
            self.write_ext(('METHOD_END_NO_CONTENT', ';\n'))
            return
        self.write('\n%s{\n' % self.space())
        self.write_ext(('METHOD_START', '\n%s{\n' % self.space()))
        self.inc_ind()
        self.visit_node(self.graph.entry)
        self.dec_ind()
        self.write('%s}\n' % self.space())
        self.write_ext(('METHOD_END', '%s}\n' % self.space()))

    def visit_node(self, node):
        if node in (self.if_follow[-1], self.switch_follow[-1],
                    self.loop_follow[-1], self.latch_node[-1],
                    self.try_follow[-1]):
            return
        if not node.type.is_return and node in self.visited_nodes:
            return
        self.visited_nodes.add(node)
        for var in node.var_to_declare:
            var.visit_decl(self)
            var.declared = True
        node.visit(self)

    def visit_loop_node(self, loop):
        follow = loop.follow['loop']
        if follow is None and not loop.looptype.is_endless:
            logger.error('Loop has no follow !')
        if loop.looptype.is_pretest:
            if loop.true is follow:
                loop.neg()
                loop.true, loop.false = loop.false, loop.true
            self.write('%swhile (' % self.space())
            self.write_ext(('WHILE', '%swhile (' % self.space()))
            loop.visit_cond(self)
            self.write(') {\n')
            self.write_ext(('WHILE_START', ') {\n'))
        elif loop.looptype.is_posttest:
            self.write('%sdo {\n' % self.space())
            self.write_ext(('DO', '%sdo {\n' % self.space()))
            self.latch_node.append(loop.latch)
        elif loop.looptype.is_endless:
            self.write('%swhile(true) {\n' % self.space())
            self.write_ext(('WHILE_TRUE', '%swhile(true) {\n' % self.space()))
        self.inc_ind()
        self.loop_follow.append(follow)
        if loop.looptype.is_pretest:
            self.visit_node(loop.true)
        else:
            self.visit_node(loop.cond)
        self.loop_follow.pop()
        self.dec_ind()
        if loop.looptype.is_pretest:
            self.write('%s}\n' % self.space())
            self.write_ext(('END_PRETEST', '%s}\n' % self.space()))
        elif loop.looptype.is_posttest:
            self.latch_node.pop()
            self.write('%s} while(' % self.space())
            self.write_ext(('WHILE_POSTTEST', '%s} while(' % self.space()))
            loop.latch.visit_cond(self)
            self.write(');\n')
            self.write_ext(('POSTTEST_END', ');\n'))
        else:
            self.inc_ind()
            self.visit_node(loop.latch)
            self.dec_ind()
            self.write('%s}\n' % self.space())
            self.write_ext(('END_LOOP', '%s}\n' % self.space()))
        if follow is not None:
            self.visit_node(follow)

    def visit_cond_node(self, cond):
        follow = cond.follow['if']
        if cond.false is cond.true:
            self.write('%s// Both branches of the condition point to the same'
                       ' code.\n' % self.space())
            self.write_ext(
                ('COMMENT_ERROR_MSG',
                 '%s// Both branches of the condition point to the same'
                 ' code.\n' % self.space()))
            self.write('%s// if (' % self.space())
            self.write_ext(('COMMENT_IF', '%s// if (' % self.space()))
            cond.visit_cond(self)
            self.write(') {\n')
            self.write_ext(('COMMENT_COND_END', ') {\n'))
            self.inc_ind()
            self.visit_node(cond.true)
            self.dec_ind()
            self.write('%s// }\n' % self.space(), data="COMMENT_IF_COND_END")
            return
        if cond.false is self.loop_follow[-1]:
            cond.neg()
            cond.true, cond.false = cond.false, cond.true
        if self.loop_follow[-1] in (cond.true, cond.false):
            self.write('%sif (' % self.space(), data="IF_2")
            cond.visit_cond(self)
            self.write(') {\n', data="IF_TRUE_2")
            self.inc_ind()
            self.write('%sbreak;\n' % self.space(), data="BREAK")
            self.dec_ind()
            self.write('%s}\n' % self.space(), data="IF_END_2")
            self.visit_node(cond.false)
        elif follow is not None:
            if cond.true in (follow, self.next_case) or\
                                                cond.num > cond.true.num:
                             # or cond.true.num > cond.false.num:
                cond.neg()
                cond.true, cond.false = cond.false, cond.true
            self.if_follow.append(follow)
            if cond.true:  # in self.visited_nodes:
                self.write('%sif (' % self.space(), data="IF")
                cond.visit_cond(self)
                self.write(') {\n', data="IF_TRUE")
                self.inc_ind()
                self.visit_node(cond.true)
                self.dec_ind()
            is_else = not (follow in (cond.true, cond.false))
            if is_else and not cond.false in self.visited_nodes:
                self.write('%s} else {\n' % self.space(), data="IF_FALSE")
                self.inc_ind()
                self.visit_node(cond.false)
                self.dec_ind()
            self.if_follow.pop()
            self.write('%s}\n' % self.space(), data="IF_END")
            self.visit_node(follow)
        else:
            self.write('%sif (' % self.space(), data="IF_3")
            cond.visit_cond(self)
            self.write(') {\n', data="IF_COND_3")
            self.inc_ind()
            self.visit_node(cond.true)
            self.dec_ind()
            self.write('%s} else {\n' % self.space(), data="ELSE_3")
            self.inc_ind()
            self.visit_node(cond.false)
            self.dec_ind()
            self.write('%s}\n' % self.space(), data="IF_END_3")

    def visit_short_circuit_condition(self, nnot, aand, cond1, cond2):
        if nnot:
            cond1.neg()
        self.write('(', data="TODO24")
        cond1.visit_cond(self)
        self.write(') %s (' % ['||', '&&'][aand], data="TODO25")
        cond2.visit_cond(self)
        self.write(')', data="TODO26")

    def visit_switch_node(self, switch):
        lins = switch.get_ins()
        for ins in lins[:-1]:
            self.visit_ins(ins)
        switch_ins = switch.get_ins()[-1]
        self.write('%sswitch (' % self.space(), data="SWITCH")
        self.visit_ins(switch_ins)
        self.write(') {\n', data="SWITCH_END")
        follow = switch.follow['switch']
        cases = switch.cases
        self.switch_follow.append(follow)
        default = switch.default
        for i, node in enumerate(cases):
            if node in self.visited_nodes:
                continue
            self.inc_ind()
            for case in switch.node_to_case[node]:
                self.write(
                    '%scase %d:\n' % (self.space(), case), data="CASE_XX")
            if i + 1 < len(cases):
                self.next_case = cases[i + 1]
            else:
                self.next_case = None
            if node is default:
                self.write('%sdefault:\n' % self.space(), data="CASE_DEFAULT")
                default = None
            self.inc_ind()
            self.visit_node(node)
            if self.need_break:
                self.write('%sbreak;\n' % self.space(), data="CASE_BREAK")
            else:
                self.need_break = True
            self.dec_ind(2)
        if default not in (None, follow):
            self.inc_ind()
            self.write('%sdefault:\n' % self.space(), data="CASE_DEFAULT_2")
            self.inc_ind()
            self.visit_node(default)
            self.dec_ind(2)
        self.write('%s}\n' % self.space(), data="CASE_END")
        self.switch_follow.pop()
        self.visit_node(follow)

    def visit_statement_node(self, stmt):
        sucs = self.graph.sucs(stmt)
        for ins in stmt.get_ins():
            self.visit_ins(ins)
        if len(sucs) == 1:
            if sucs[0] is self.loop_follow[-1]:
                self.write('%sbreak;\n' % self.space(), data="BREAK_2")
            elif sucs[0] is self.next_case:
                self.need_break = False
            else:
                self.visit_node(sucs[0])

    def visit_try_node(self, try_node):
        self.write('%stry {\n' % self.space(), data="TRY_START")
        self.inc_ind()
        self.try_follow.append(try_node.follow)
        self.visit_node(try_node.try_start)
        self.dec_ind()
        self.write('%s}' % self.space(), data="TRY_START_END")
        for catch in try_node.catch:
            self.visit_node(catch)
        self.write('\n', data="NEWLINE_END_TRY")
        self.visit_node(self.try_follow.pop())

    def visit_catch_node(self, catch_node):
        self.write(' catch (', data="CATCH")
        catch_node.visit_exception(self)
        self.write(') {\n', data="CATCH_START")
        self.inc_ind()
        self.visit_node(catch_node.catch_start)
        self.dec_ind()
        self.write('%s}' % self.space(), data="CATCH_END")

    def visit_return_node(self, ret):
        self.need_break = False
        for ins in ret.get_ins():
            self.visit_ins(ins)

    def visit_throw_node(self, throw):
        for ins in throw.get_ins():
            self.visit_ins(ins)

    def visit_decl(self, var):
        if not var.declared:
            var_type = var.get_type() or 'unknownType'
            self.write('%s%s v%s' % (
                self.space(), get_type(var_type),
                var.name), data="DECLARATION")
            self.end_ins()

    def visit_constant(self, cst):
        if isinstance(cst, basestring):
            return self.write(string(cst), data="CONSTANT_STRING")
        self.write('%r' % cst, data="CONSTANT_INTEGER")  # INTEGER or also others?

    def visit_base_class(self, cls, data=None):
        self.write(cls)
        self.write_ext(('NAME_BASE_CLASS', cls, data))

    def visit_variable(self, var):
        var_type = var.get_type() or 'unknownType'
        if not var.declared:
            self.write('%s ' % get_type(var_type))
            self.write_ext(
                ('VARIABLE_TYPE', '%s' % get_type(var_type), var_type))
            self.write_ext(('SPACE', ' '))
            var.declared = True
        self.write('v%s' % var.name)
        self.write_ext(('NAME_VARIABLE', 'v%s' % var.name, var, var_type))

    def visit_param(self, param, data=None):
        self.write('p%s' % param)
        self.write_ext(('NAME_PARAM', 'p%s' % param, data))

    def visit_this(self):
        self.write('this', data="THIS")

    def visit_assign(self, lhs, rhs):
        if lhs is not None:
            return self.write_inplace_if_possible(lhs, rhs)
        self.write_ind()
        rhs.visit(self)
        if not self.skip:
            self.end_ins()

    def visit_move_result(self, lhs, rhs):
        self.write_ind_visit_end(lhs, ' = ', rhs)

    def visit_move(self, lhs, rhs):
        if lhs is not rhs:
            self.write_inplace_if_possible(lhs, rhs)

    def visit_astore(self, array, index, rhs, data=None):
        self.write_ind()
        array.visit(self)
        self.write('[', data=("ASTORE_START", data))
        index.visit(self)
        self.write('] = ', data="ASTORE_END")
        rhs.visit(self)
        self.end_ins()

    def visit_put_static(self, cls, name, rhs):
        self.write_ind()
        self.write('%s.%s = ' % (cls, name), data="STATIC_PUT")
        rhs.visit(self)
        self.end_ins()

    def visit_put_instance(self, lhs, name, rhs, data=None):
        self.write_ind_visit_end_ext(
            lhs, '.', '%s' % name, ' = ', rhs,
            data=data, subsection='NAME_CLASS_ASSIGNMENT')

    def visit_new(self, atype, data=None):
        self.write('new %s' % get_type(atype))
        self.write_ext(('NEW', 'new '))
        self.write_ext(
            ('NAME_CLASS_NEW', '%s' % get_type(atype), data.type, data))

    def visit_invoke(self, name, base, ptype, rtype, args, invokeInstr=None):
        if isinstance(base, ThisParam):
            if name == '<init>' and self.constructor and len(args) == 0:
                self.skip = True
                return
        base.visit(self)
        if name != '<init>':
            if isinstance(base, BaseClass):
                call_name = "%s -> %s" % (base.cls, name)
            elif isinstance(base, InstanceExpression):
                call_name = "%s -> %s" % (base.ftype, name)
            elif hasattr(base, "base") and hasattr(base, "var_map"):
                base2base = base
                while True:
                    base2base = base2base.var_map[base2base.base]
                    if isinstance(base2base, NewInstance):
                        call_name = "%s -> %s" % (base2base.type, name)
                        break
                    elif (hasattr(base2base, "base") and
                          hasattr(base2base, "var_map")):
                        continue
                    else:
                        call_name = "UNKNOWN_TODO"
                        break
            elif isinstance(base, ThisParam):
                call_name = "this -> %s" % name
            elif isinstance(base, Variable):
                call_name = "%s -> %s" % (base.type, name)
            else:
                call_name = "UNKNOWN_TODO2"
            self.write('.%s' % name)
            self.write_ext(('INVOKE', '.'))
            self.write_ext(
                ('NAME_METHOD_INVOKE',
                 '%s' % name, call_name, ptype, rtype, base, invokeInstr))
        self.write('(', data="PARAM_START")
        comma = False
        for arg in args:
            if comma:
                self.write(', ', data="PARAM_SEPARATOR")
            comma = True
            arg.visit(self)
        self.write(')', data="PARAM_END")

    def visit_return_void(self):
        self.write_ind()
        self.write('return', data="RETURN")
        self.end_ins()

    def visit_return(self, arg):
        self.write_ind()
        self.write('return ', data="RETURN")
        arg.visit(self)
        self.end_ins()

    def visit_nop(self):
        pass

    def visit_switch(self, arg):
        arg.visit(self)

    def visit_check_cast(self, arg, atype):
        self.write('((%s) ' % atype, data="CHECKCAST")
        arg.visit(self)
        self.write(')')

    def visit_aload(self, array, index):
        array.visit(self)
        self.write('[', data="ALOAD_START")
        index.visit(self)
        self.write(']', data="ALOAD_END")

    def visit_alength(self, array):
        array.visit(self)
        self.write('.length', data="ARRAY_LENGTH")

    def visit_new_array(self, atype, size):
        self.write('new %s[' % get_type(atype[1:]), data="NEW_ARRAY")
        size.visit(self)
        self.write(']', data="NEW_ARRAY_END")

    def visit_filled_new_array(self, atype, size, args):
        self.write('new %s {' % get_type(atype), data="NEW_ARRAY_FILLED")
        for idx, arg in enumerate(args):
            arg.visit(self)
            if idx + 1 < len(args):
                self.write(', ', data="COMMA")
        self.write('})', data="NEW_ARRAY_FILLED_END")

    def visit_fill_array(self, array, value):
        self.write_ind()
        array.visit(self)
        self.write(' = {', data="ARRAY_FILLED")
        data = value.get_data()
        tab = []
        elem_size = value.element_width
        if elem_size == 4:
            for i in range(0, value.size * 4, 4):
                tab.append('%s' % unpack('i', data[i:i + 4])[0])
        else:  # FIXME: other cases
            for i in range(value.size):
                tab.append('%s' % unpack('b', data[i])[0])
        self.write(', '.join(tab), data="COMMA")
        self.write('}', data="ARRAY_FILLED_END")
        self.end_ins()

    def visit_move_exception(self, var, data=None):
        var.declared = True
        var_type = var.get_type() or 'unknownType'
        self.write('%s v%s' % (get_type(var_type), var.name))
        self.write_ext(
            ('EXCEPTION_TYPE', '%s' % get_type(var_type), data.type))
        self.write_ext(('SPACE', ' '))
        self.write_ext(
            ('NAME_CLASS_EXCEPTION', 'v%s' % var.value(), data.type, data))

    def visit_monitor_enter(self, ref):
        self.write_ind()
        self.write('synchronized(', data="SYNCHRONIZED")
        ref.visit(self)
        self.write(') {\n', data="SYNCHRONIZED_END")
        self.inc_ind()

    def visit_monitor_exit(self, ref):
        self.dec_ind()
        self.write_ind()
        self.write('}\n', data="MONITOR_EXIT")

    def visit_throw(self, ref):
        self.write_ind()
        self.write('throw ', data="THROW")
        ref.visit(self)
        self.end_ins()

    def visit_binary_expression(self, op, arg1, arg2):
        self.write('(', data="BINARY_EXPRESSION_START")
        arg1.visit(self)
        self.write(' %s ' % op, data="TODO58")
        arg2.visit(self)
        self.write(')', data="BINARY_EXPRESSION_END")

    def visit_unary_expression(self, op, arg):
        self.write('(%s ' % op, data="UNARY_EXPRESSION_START")
        arg.visit(self)
        self.write(')', data="UNARY_EXPRESSION_END")

    def visit_cast(self, op, arg):
        self.write('(%s ' % op, data="CAST_START")
        arg.visit(self)
        self.write(')', data="CAST_END")

    def visit_cond_expression(self, op, arg1, arg2):
        arg1.visit(self)
        self.write(' %s ' % op, data="COND_EXPRESSION")
        arg2.visit(self)

    def visit_condz_expression(self, op, arg):
        if isinstance(arg, BinaryCompExpression):
            arg.op = op
            return arg.visit(self)
        atype = arg.get_type()
        if atype == 'Z':
            if op == Op.EQUAL:
                self.write('!', data="NEGATE")
            arg.visit(self)
        else:
            arg.visit(self)
            if atype in 'VBSCIJFD':
                self.write(' %s 0' % op, data="TODO64")
            else:
                self.write(' %s null' % op, data="TODO65")

    def visit_get_instance(self, arg, name, data=None):
        arg.visit(self)
        self.write('.%s' % name)
        self.write_ext(('GET_INSTANCE', '.'))
        self.write_ext(('NAME_CLASS_INSTANCE', '%s' % name, data))

    def visit_get_static(self, cls, name):
        self.write('%s.%s' % (cls, name), data="GET_STATIC")


def string(s):
    ret = ['"']
    for c in s.decode('utf8'):
        if c >= ' ' and c < '\x7f':
            if c == "'" or c == '"' or c == '\\':
                ret.append('\\')
            ret.append(c)
            continue
        elif c <= '\x7f':
            if c in ('\r', '\n', '\t'):
                ret.append(c.encode('unicode-escape'))
                continue
        i = ord(c)
        ret.append('\\u')
        ret.append('%x' % (i >> 12))
        ret.append('%x' % ((i >> 8) & 0x0f))
        ret.append('%x' % ((i >> 4) & 0x0f))
        ret.append('%x' % (i & 0x0f))
    ret.append('"')
    return ''.join(ret).encode('utf8')
