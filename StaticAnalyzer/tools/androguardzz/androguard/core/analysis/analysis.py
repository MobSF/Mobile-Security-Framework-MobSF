# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
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

import re, random, string, cPickle

from androguard.core.androconf import error, warning
from androguard.core.bytecodes import jvm, dvm
from androguard.core.bytecodes.api_permissions import DVM_PERMISSIONS_BY_PERMISSION, DVM_PERMISSIONS_BY_ELEMENT

class ContextField :
    def __init__(self, mode) :
        self.mode = mode
        self.details = []

    def set_details(self, details) :
        for i in details :
            self.details.append( i )

class ContextMethod :
    def __init__(self) :
        self.details = []

    def set_details(self, details) :
        for i in details :
            self.details.append( i )

class ExternalFM :
    def __init__(self, class_name, name, descriptor) :
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor

    def get_class_name(self) :
        return self.class_name

    def get_name(self) :
        return self.name

    def get_descriptor(self) :
        return self.descriptor

class ToString :
    def __init__(self, tab) :
        self.__tab = tab
        self.__re_tab = {}

        for i in self.__tab :
            self.__re_tab[i] = []
            for j in self.__tab[i] :
                self.__re_tab[i].append( re.compile( j ) )

        self.__string = ""

    def push(self, name) :
        for i in self.__tab :
            for j in self.__re_tab[i] :
                if j.match(name) != None :
                    if len(self.__string) > 0 :
                        if i == 'O' and self.__string[-1] == 'O' :
                            continue
                    self.__string += i

    def get_string(self) :
        return self.__string

class BreakBlock(object) :
    def __init__(self, _vm, idx) :
        self._vm = _vm
        self._start = idx
        self._end = self._start

        self._ins = []

        self._ops = []

        self._fields = {}
        self._methods = {}


    def get_ops(self) :
        return self._ops

    def get_fields(self) :
        return self._fields

    def get_methods(self) :
        return self._methods

    def push(self, ins) :
        self._ins.append(ins)
        self._end += ins.get_length()

    def get_start(self) :
        return self._start

    def get_end(self) :
        return self._end

    def show(self) :
        for i in self._ins :
            print "\t\t",
            i.show(0)

##### JVM ######
FIELDS = {
            "getfield" : "R",
            "getstatic" : "R",
            "putfield" : "W",
            "putstatic" : "W",
         }

METHODS = [ "invokestatic", "invokevirtual", "invokespecial" ]

JVM_TOSTRING = { "O" : jvm.MATH_JVM_OPCODES.keys(),
                 "I" : jvm.INVOKE_JVM_OPCODES,
                 "G" : jvm.FIELD_READ_JVM_OPCODES,
                 "P" : jvm.FIELD_WRITE_JVM_OPCODES,
               }

BREAK_JVM_OPCODES_RE = []
for i in jvm.BREAK_JVM_OPCODES :
    BREAK_JVM_OPCODES_RE.append( re.compile( i ) )

class Stack :
    def __init__(self) :
        self.__elems = []

    def gets(self) :
        return self.__elems

    def push(self, elem) :
        self.__elems.append( elem )

    def get(self) :
        return self.__elems[-1]

    def pop(self) :
        return self.__elems.pop(-1)

    def nil(self) :
        return len(self.__elems) == 0

    def insert_stack(self, idx, elems) :
        if elems != self.__elems :
            for i in elems :
                self.__elems.insert(idx, i)
                idx += 1

    def show(self) :
        nb = 0

        if len(self.__elems) == 0 :
            print "\t--> nil"

        for i in self.__elems :
            print "\t-->", nb, ": ", i
            nb += 1

class StackTraces :
    def __init__(self) :
        self.__elems = []

    def save(self, idx, i_idx, ins, stack_pickle, msg_pickle) :
        self.__elems.append( (idx, i_idx, ins, stack_pickle, msg_pickle) )

    def get(self) :
        for i in self.__elems :
            yield (i[0], i[1], i[2], cPickle.loads( i[3] ), cPickle.loads( i[4] ) )

    def show(self) :
        for i in self.__elems :
            print i[0], i[1], i[2].get_name()

            cPickle.loads( i[3] ).show()
            print "\t", cPickle.loads( i[4] )

def push_objectref(_vm, ins, special, stack, res, ret_v) :
    value = "OBJ_REF_@_%s" % str(special)
    stack.push( value )

def push_objectref_l(_vm, ins, special, stack, res, ret_v) :
    stack.push( "VARIABLE_LOCAL_%d" % special )

def push_objectref_l_i(_vm, ins, special, stack, res, ret_v) :
    stack.push( "VARIABLE_LOCAL_%d" % ins.get_operands() )

def pop_objectref(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_return( stack.pop() )

def multi_pop_objectref_i(_vm, ins, special, stack, res, ret_v) :
    for i in range(0, ins.get_operands()[1]) :
        stack.pop()

def push_objectres(_vm, ins, special, stack, res, ret_v) :
    value = ""

    if special[0] == 1 :
        value += special[1] + "(" + str( res.pop() ) + ") "
    else :
        for i in range(0, special[0]) :
            value += str( res.pop() ) + special[1]

    value = value[:-1]

    stack.push( value )

def push_integer_i(_vm, ins, special, stack, res, ret_v) :
    value = ins.get_operands()
    stack.push( value )

def push_integer_d(_vm, ins, special, stack, res, ret_v) :
    stack.push( special )

def push_float_d(_vm, ins, special, stack, res, ret_v) :
    stack.push( special )

def putfield(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_return( stack.pop() )

def putstatic(_vm, ins, special, stack, res, ret_v) :
    stack.pop()

def getfield(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_return( stack.pop() )
    stack.push( "FIELD" )

def getstatic(_vm, ins, special, stack, res, ret_v) :
    stack.push( "FIELD_STATIC" )

def new(_vm, ins, special, stack, res, ret_v) :
    stack.push( "NEW_OBJ" )

def dup(_vm, ins, special, stack, res, ret_v) :
    l = []

    for i in range(0, special+1) :
        l.append( stack.pop() )
    l.reverse()

    l.insert( 0, l[-1] )
    for i in l :
        stack.push( i )

def dup2(_vm, ins, special, stack, res, ret_v) :
    l = []

    for i in range(0, special+1) :
        l.append( stack.pop() )
    l.reverse()

    l.insert( 0, l[-1] )
    l.insert( 1, l[-2] )
    for i in l :
        stack.push( i )

#FIXME
def ldc(_vm, ins, special, stack, res, ret_v) :
    #print ins.get_name(), ins.get_operands(), special
    stack.push( "STRING" )

def invoke(_vm, ins, special, stack, res, ret_v) :
    desc = ins.get_operands()[-1]
    param = desc[1:desc.find(")")]
    ret = desc[desc.find(")")+1:]

#   print "DESC --->", param, calc_nb( param ), ret, calc_nb( ret )

    for i in range(0, calc_nb( param )) :
        stack.pop()

    # objectref : static or not
    for i in range(0, special) :
        stack.pop()

    for i in range(0, calc_nb( ret )):
        stack.push( "E" )

def set_arrayref(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_msg( "SET VALUE %s %s @ ARRAY REF %s %s" % (special, str(stack.pop()), str(stack.pop()), str(stack.pop())) )

def set_objectref(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_msg( "SET OBJECT REF %d --> %s" % (special, str(stack.pop())) )

def set_objectref_i(_vm, ins, special, stack, res, ret_v) :
    ret_v.add_msg( "SET OBJECT REF %d --> %s" % (ins.get_operands(), str(stack.pop())) )

def swap(_vm, ins, special, stack, res, ret_v) :
    l = stack.pop()
    l2 = stack.pop()

    stack.push(l2)
    stack.push(l)

def calc_nb(info) :
    if info == "" or info == "V" :
        return 0

    if ";" in info :
        n = 0
        for i in info.split(";") :
            if i != "" :
                n += 1
        return n
    else :
        return len(info) - info.count('[')

INSTRUCTIONS_ACTIONS = {
         "aaload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "aastore" : [ { set_arrayref : None } ],
         "aconst_null" : [ { push_objectref : "null" } ],
         "aload" : [ { push_objectref_l_i : None } ],
         "aload_0" : [ { push_objectref_l : 0 } ],
         "aload_1" : [ { push_objectref_l : 1 } ],
         "aload_2" : [ { push_objectref_l : 2 } ],
         "aload_3" : [ { push_objectref_l : 3 } ],
         "anewarray" : [ { pop_objectref : None }, { push_objectref : [ 1, "ANEWARRAY" ] } ],
         "areturn" : [ { pop_objectref : None } ],
         "arraylength" : [ { pop_objectref : None }, { push_objectres : [ 1, 'LENGTH' ] } ],
         "astore" : [ { set_objectref_i : None } ],
         "astore_0" : [ { set_objectref : 0 } ],
         "astore_1" : [ { set_objectref : 1 } ],
         "astore_2" : [ { set_objectref : 2 } ],
         "astore_3" : [ { set_objectref : 3 } ],
         "athrow" : [ { pop_objectref : None }, { push_objectres : [ 1, "throw" ] } ],
         "baload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "bastore" : [ { set_arrayref : "byte" } ],
         "bipush" :  [ { push_integer_i : None } ],
         "caload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "castore" : [ { set_arrayref : "char" } ],
         "checkcast" : [ { pop_objectref : None }, { push_objectres : [ 1, "checkcast" ] } ],
         "d2f" : [ { pop_objectref : None }, { push_objectres : [ 1, 'float' ] } ],
         "d2i" : [ { pop_objectref : None }, { push_objectres : [ 1, 'integer' ] } ],
         "d2l" : [  { pop_objectref : None }, { push_objectres : [ 1, 'long' ] } ],
         "dadd" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '+' ] } ],
         "daload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "dastore" : [ { set_arrayref : "double" } ],
         "dcmpg" : [  { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "dcmpl" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "dconst_0" : [ { push_float_d : 0.0 } ],
         "dconst_1" : [ { push_float_d : 1.0 } ],
         "ddiv" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '&' ] } ],
         "dload" : [ { push_objectref_l_i : None } ],
         "dload_0" : [ { push_objectref_l : 0 } ],
         "dload_1" : [  { push_objectref_l : 1 } ],
         "dload_2" : [  { push_objectref_l : 2 } ],
         "dload_3" : [  { push_objectref_l : 3 } ],
         "dmul" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '*' ] } ],
         "dneg" : [ { pop_objectref : None }, { push_objectres : [ 1, '-' ] } ],
         "drem" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, 'rem' ] } ],
         "dreturn" : [ { pop_objectref : None } ],
         "dstore" : [ { set_objectref_i : None } ],
         "dstore_0" : [ { set_objectref : 0 } ],
         "dstore_1" : [ { set_objectref : 1 } ],
         "dstore_2" : [ { set_objectref : 2 } ],
         "dstore_3" : [ { set_objectref : 3 } ],
         "dsub" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '-' ] } ],
         "dup" : [ { dup : 0 } ],
         "dup_x1" : [ { dup : 1 } ],
         "dup_x2" : [ { dup : 2 } ],
         "dup2" : [ { dup2 : 0 } ],
         "dup2_x1" : [ { dup2 : 1 } ],
         "dup2_x2" : [ { dup2 : 2 } ],
         "f2d" : [ { pop_objectref : None }, { push_objectres : [ 1, 'double' ] }  ],
         "f2i" : [ { pop_objectref : None }, { push_objectres : [ 1, 'integer' ] } ],
         "f2l" : [ { pop_objectref : None }, { push_objectres : [ 1, 'long' ] } ],
         "fadd" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '+' ] } ],
         "faload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "fastore" : [ { set_arrayref : "float" } ],
         "fcmpg" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "fcmpl" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "fconst_0" : [ { push_float_d : 0.0 } ],
         "fconst_1" : [ { push_float_d : 1.0 } ],
         "fconst_2" : [ { push_float_d : 2.0 } ],
         "fdiv" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '&' ] } ],
         "fload" : [ { push_objectref_l_i : None } ],
         "fload_0" : [ { push_objectref_l : 0 } ],
         "fload_1" : [ { push_objectref_l : 1 } ],
         "fload_2" : [ { push_objectref_l : 2 } ],
         "fload_3" : [ { push_objectref_l : 3 } ],
         "fmul" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '*' ] } ],
         "fneg" : [ { pop_objectref : None }, { push_objectres : [ 1, '-' ] } ],
         "freturn" : [ { pop_objectref : None } ],
         "fstore" : [ { set_objectref_i : None } ],
         "fstore_0" : [ { set_objectref : 0 } ],
         "fstore_1" : [ { set_objectref : 1 } ],
         "fstore_2" : [ { set_objectref : 2 } ],
         "fstore_3" : [ { set_objectref : 3 } ],
         "fsub" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '-' ] } ],
         "getfield" : [ { getfield : None } ],
         "getstatic" : [ { getstatic : None } ],
         "goto" : [ {} ],
         "goto_w" : [ {} ],
         "i2b" : [ { pop_objectref : None }, { push_objectres : [ 1, 'byte' ] } ],
         "i2c" : [ { pop_objectref : None }, { push_objectres : [ 1, 'char' ] }  ],
         "i2d" : [ { pop_objectref : None }, { push_objectres : [ 1, 'double' ] } ],
         "i2f" : [ { pop_objectref : None }, { push_objectres : [ 1, 'float' ] } ],
         "i2l" : [ { pop_objectref : None }, { push_objectres : [ 1, 'long' ] } ],
         "i2s" : [ { pop_objectref : None }, { push_objectres : [ 1, 'string' ] } ],
         "iadd" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '+' ] } ],
         "iaload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "iand" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '&' ] } ],
         "iastore" : [ { set_arrayref : "int" } ],
         "iconst_m1" : [ { push_integer_d : -1 } ],
         "iconst_0" : [ { push_integer_d : 0 } ],
         "iconst_1" : [ { push_integer_d : 1 } ],
         "iconst_2" : [ { push_integer_d : 2 } ],
         "iconst_3" : [ { push_integer_d : 3 } ],
         "iconst_4" : [ { push_integer_d : 4 } ],
         "iconst_5" : [ { push_integer_d : 5 } ],
         "idiv" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '/' ] } ],
         "if_acmpeq" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_acmpne" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmpeq" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmpne" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmplt" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmpge" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmpgt" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "if_icmple" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "ifeq" : [ { pop_objectref : None } ],
         "ifne" : [ { pop_objectref : None } ],
         "iflt" : [ { pop_objectref : None } ],
         "ifge" : [ { pop_objectref : None } ],
         "ifgt" : [ { pop_objectref : None } ],
         "ifle" : [ { pop_objectref : None } ],
         "ifnonnull" : [ { pop_objectref : None } ],
         "ifnull" : [ { pop_objectref : None } ],
         "iinc" : [ {} ],
         "iload" : [ { push_objectref_l_i : None } ],
         "iload_1" : [ { push_objectref_l : 1 } ],
         "iload_2" : [ { push_objectref_l : 2 } ],
         "iload_3" : [ { push_objectref_l : 3 } ],
         "imul" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '*' ] } ],
         "ineg" : [ { pop_objectref : None }, { push_objectres : [ 1, '-' ] } ],
         "instanceof" : [ { pop_objectref : None }, { push_objectres : [ 1, 'instanceof' ] } ],
         "invokeinterface" : [ { invoke : 1 } ],
         "invokespecial" : [ { invoke : 1 } ],
         "invokestatic" : [ { invoke : 0 } ],
         "invokevirtual": [ { invoke : 1 } ],
         "ior" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '|' ] } ],
         "irem" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, 'REM' ] } ],
         "ireturn" : [ { pop_objectref : None } ],
         "ishl" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '<<' ] } ],
         "ishr" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '>>' ] } ],
         "istore" : [ { set_objectref_i : None } ],
         "istore_0" : [ { set_objectref : 0 } ],
         "istore_1" : [ { set_objectref : 1 } ],
         "istore_2" : [ { set_objectref : 2 } ],
         "istore_3" : [ { set_objectref : 3 } ],
         "isub" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '-' ] } ],
         "iushr" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '>>' ] } ],
         "ixor" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '^' ] } ],
         "jsr" : [ { push_integer_i : None } ],
         "jsr_w" : [ { push_integer_i : None } ],
         "l2d" : [ { pop_objectref : None }, { push_objectres : [ 1, 'double' ] } ],
         "l2f" : [ { pop_objectref : None }, { push_objectres : [ 1, 'float' ] } ],
         "l2i" : [ { pop_objectref : None }, { push_objectres : [ 1, 'integer' ] } ],
         "ladd" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '+' ] } ],
         "laload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "land" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '&' ] } ],
         "lastore" : [ { set_arrayref : "long" } ],
         "lcmp" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "lconst_0" : [ { push_float_d : 0.0 } ],
         "lconst_1" : [ { push_float_d : 1.0 } ],
         "ldc" : [ { ldc : None } ],
         "ldc_w" : [ { ldc : None } ],
         "ldc2_w" : [ { ldc : None } ],
         "ldiv" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '/' ] } ],
         "lload" : [ { push_objectref_l_i : None } ],
         "lload_0" : [ { push_objectref_l : 0 } ],
         "lload_1" : [ { push_objectref_l : 1 } ],
         "lload_2" : [ { push_objectref_l : 2 } ],
         "lload_3" : [ { push_objectref_l : 3 } ],
         "lmul" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '*' ] } ],
         "lneg" : [ { pop_objectref : None }, { push_objectres : [ 1, '-' ] } ],
         "lookupswitch" : [ { pop_objectref : None } ],
         "lor" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '|' ] } ],
         "lrem" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, 'REM' ] } ],
         "lreturn" : [ { pop_objectref : None } ],
         "lshl" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '<<' ] } ],
         "lshr" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '>>' ] } ],
         "lstore" : [ { set_objectref_i : None } ],
         "lstore_0" : [ { set_objectref : 0 } ],
         "lstore_1" : [ { set_objectref : 1 } ],
         "lstore_2" : [ { set_objectref : 2 } ],
         "lstore_3" : [ { set_objectref : 3 } ],
         "lsub" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '-' ] } ],
         "lushr" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '>>' ] } ],
         "lxor" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectres : [ 2, '^' ] } ],
         "monitorenter" : [ { pop_objectref : None } ],
         "monitorexit" : [ { pop_objectref : None } ],
         "multianewarray" : [ { multi_pop_objectref_i : None }, { push_objectref : 0 } ],
         "new" : [ { new : None } ],
         "newarray" : [ { pop_objectref : None }, { push_objectref : [ 1, "NEWARRAY" ] } ],
         "nop" : [ {} ],
         "pop" : [ { pop_objectref : None } ],
         "pop2" : [ { pop_objectref : None }, { pop_objectref : None } ],
         "putfield" : [ { putfield : None }, { pop_objectref : None } ],
         "putstatic" : [ { putstatic : None } ],
         "ret" : [ {} ],
         "return" : [ {} ],
         "saload" : [ { pop_objectref : None }, { pop_objectref : None }, { push_objectref : 0 } ],
         "sastore" : [ { set_arrayref : "short" } ],
         "sipush" :  [ { push_integer_i : None } ],
         "swap" : [ { swap : None } ],
         "tableswitch" : [ { pop_objectref : None } ],
         "wide" : [ {} ],
}


class ReturnValues :
    def __init__(self) :
        self.__elems = []
        self.__msgs = []

    def add_msg(self, e) :
        self.__msgs.append( e )

    def add_return(self, e) :
        self.__elems.append( e )

    def get_msg(self) :
        return self.__msgs

    def get_return(self) :
        return self.__elems

class ExternalMethod :
    def __init__(self, class_name, name, descriptor) :
        self.__class_name = class_name
        self.__name = name
        self.__descriptor = descriptor

    def get_name(self) :
        return "M@[%s][%s]-[%s]" % (self.__class_name, self.__name, self.__descriptor)

    def set_fathers(self, f) :
        pass

class JVMBasicBlock :
    def __init__(self, start, vm, method, context) :
        self.__vm = vm
        self.method = method
        self.context = context

        self.__stack = Stack()
        self.stack_traces = StackTraces()

        self.ins = []

        self.fathers = []
        self.childs = []

        self.start = start
        self.end = self.start

        self.break_blocks = []

        self.free_blocks_offsets = []

        self.name = "%s-BB@0x%x" % (self.method.get_name(), self.start)

    def get_stack(self) :
        return self.__stack.gets()

    def get_method(self) :
        return self.method

    def get_name(self) :
        return self.name

    def get_start(self) :
        return self.start

    def get_end(self) :
        return self.end

    def get_last(self) :
        return self.ins[-1]

    def push(self, i) :
        self.ins.append( i )
        self.end += i.get_length()

    def set_fathers(self, f) :
        self.fathers.append( f )

    def set_childs(self, values) :
#      print self, self.start, self.end, values, self.ins[-1].get_name()
        if values == [] :
            next_block = self.context.get_basic_block( self.end + 1 )
            if next_block != None :
                self.childs.append( ( self.end - self.ins[-1].get_length(), self.end, next_block ) )
        else :
            for i in values :
                #print i, self.context.get_basic_block( i )
                if i != -1 :
                    self.childs.append( ( self.end - self.ins[-1].get_length(), i, self.context.get_basic_block( i ) ) )

        for c in self.childs :
            if c[2] != None :
                c[2].set_fathers( ( c[1], c[0], self ) )

    def prev_free_block_offset(self, idx=0) :
        last = -1

        #print "IDX", idx, self.free_blocks_offsets

        if self.free_blocks_offsets == [] :
            return -1

        for i in self.free_blocks_offsets :
            if i <= idx :
                last = i
            else :
                return last

        return last

    def random_free_block_offset(self) :
        return self.free_blocks_offsets[ random.randint(0, len(self.free_blocks_offsets) - 1) ]

    def next_free_block_offset(self, idx=0) :
        #print idx, self.__free_blocks_offsets
        for i in self.free_blocks_offsets :
            if i > idx :
                return i
        return -1

    def get_random_free_block_offset(self) :
        return self.free_blocks_offsets[ random.randint(0, len(self.free_blocks_offsets) - 1) ]

    def get_random_break_block(self) :
        return self.break_blocks[ random.randint(0, len(self.break_blocks) - 1) ]

    def get_break_block(self, idx) :
        for i in self.break_blocks :
            if idx >= i.get_start() and idx <= i.get_end() :
                return i
        return None

    def analyze_break_blocks(self) :
        idx = self.get_start()

        current_break = JVMBreakBlock( self.__vm, idx )
        self.break_blocks.append(current_break)
        for i in self.ins :
            name = i.get_name()

            ##################### Break Block ########################
            match = False
            for j in BREAK_JVM_OPCODES_RE :
                if j.match(name) != None :
                    match = True
                    break

            current_break.push( i )
            if match == True :
                current_break.analyze()
                current_break = JVMBreakBlock( self.__vm, current_break.get_end() )

                self.break_blocks.append( current_break )
            #########################################################

            idx += i.get_length()

    def analyze(self) :
        idx = 0
        for i in self.ins :
            ################### TAINTED LOCAL VARIABLES ###################
            if "load" in i.get_name() or "store" in i.get_name() :
                action = i.get_name()

                access_flag = [ "R", "load" ]
                if "store" in action :
                    access_flag = [ "W", "store" ]

                if "_" in action :
                    name = i.get_name().split(access_flag[1])
                    value = name[1][-1]
                else :
                    value = i.get_operands()

                variable_name = "%s-%s" % (i.get_name()[0], value)

                self.context.get_tainted_variables().add( variable_name, TAINTED_LOCAL_VARIABLE, self.method )
                self.context.get_tainted_variables().push_info( TAINTED_LOCAL_VARIABLE, variable_name, (access_flag[0], idx, self, self.method) )
            #########################################################

            ################### TAINTED FIELDS ###################
            elif i.get_name() in FIELDS :
                o = i.get_operands()
                desc = getattr(self.__vm, "get_field_descriptor")(o[0], o[1], o[2])

                # It's an external
                #if desc == None :
                #    desc = ExternalFM( o[0], o[1], o[2] )

#               print "RES", res, "-->", desc.get_name()
                self.context.get_tainted_variables().push_info( TAINTED_FIELD, [o[0], o[1], o[2]], (FIELDS[ i.get_name() ][0], idx, self, self.method) )
            #########################################################

            ################### TAINTED PACKAGES ###################
            elif "new" in i.get_name() or "invoke" in i.get_name() or "getstatic" in i.get_name() :
                if "new" in i.get_name() :
                    self.context.get_tainted_packages().push_info( i.get_operands(), (TAINTED_PACKAGE_CREATE, idx, self, self.method) )
                else :
                    self.context.get_tainted_packages().push_info( i.get_operands()[0], (TAINTED_PACKAGE_CALL, idx, self, self.method, i.get_operands()[1], i.get_operands()[2]) )
            #########################################################

            ################### TAINTED INTEGERS ###################
            if "ldc" == i.get_name() :
                o = i.get_operands()

                if o[0] == "CONSTANT_Integer" :
                    self.context.get_tainted_integers().push_info( i, (o[1], idx, self, self.method) )

            elif "sipush" in i.get_name() :
                self.context.get_tainted_integers().push_info( i, (i.get_operands(), idx, self, self.method) )

            elif "bipush" in i.get_name() :
                self.context.get_tainted_integers().push_info( i, (i.get_operands(), idx, self, self.method) )

            #########################################################

            idx += i.get_length()
    
    def set_exception(self, exception_analysis) :
        pass

    # FIXME : create a recursive function to follow the cfg, because it does not work with obfuscator
    def analyze_code(self) :
        self.analyze_break_blocks()

        #print "ANALYZE CODE -->", self.name
        d = {}
        for i in self.fathers :
        #   print "\t FATHER ->", i[2].get_name(), i[2].get_stack(), i[0], i[1]
            d[ i[0] ] = i[2]

        self.free_blocks_offsets.append( self.get_start() )

        idx = 0
        for i in self.ins :
#         print i.get_name(), self.start + idx, idx
#         i.show(idx)

            if self.start + idx in d :
                self.__stack.insert_stack( 0, d[ self.start + idx ].get_stack() )

            ret_v = ReturnValues()

            res = []
            try :
                #print i.get_name(), i.get_name() in INSTRUCTIONS_ACTIONS

                if INSTRUCTIONS_ACTIONS[ i.get_name() ] == [] :
                    print "[[[[ %s is not yet implemented ]]]]" % i.get_name()
                    raise("ooops")

                i_idx = 0
                for actions in INSTRUCTIONS_ACTIONS[ i.get_name() ] :
                    for action in actions :
                        action( self.__vm, i, actions[action], self.__stack, res, ret_v )
                        for val in ret_v.get_return() :
                            res.append( val )

                    #self.__stack.show()
                    self.stack_traces.save( idx, i_idx, i, cPickle.dumps( self.__stack ), cPickle.dumps( ret_v.get_msg() ) )
                    i_idx += 1

            except KeyError :
                print "[[[[ %s is not in INSTRUCTIONS_ACTIONS ]]]]" % i.get_name()
            except IndexError :
                print "[[[[ Analysis failed in %s-%s-%s ]]]]" % (self.method.get_class_name(), self.method.get_name(), self.method.get_descriptor())

            idx += i.get_length()

            if self.__stack.nil() == True and i != self.ins[-1] :
                self.free_blocks_offsets.append( idx + self.get_start() )

    def show(self) :
        print "\t@", self.name

        idx = 0
        nb = 0
        for i in self.ins :
            print "\t\t", nb, idx,
            i.show(nb)
            nb += 1
            idx += i.get_length()

        print ""
        print "\t\tFree blocks offsets --->", self.free_blocks_offsets
        print "\t\tBreakBlocks --->", len(self.break_blocks)

        print "\t\tF --->", ', '.join( i[2].get_name() for i in self.fathers )
        print "\t\tC --->", ', '.join( i[2].get_name() for i in self.childs )

        self.stack_traces.show()

    def get_ins(self) :
        return self.ins

class JVMBreakBlock(BreakBlock) :
    def __init__(self, _vm, idx) :
        super(JVMBreakBlock, self).__init__(_vm, idx)

        self.__info = {
                          "F" : [ "get_field_descriptor", self._fields, ContextField ],
                          "M" : [ "get_method_descriptor", self._methods, ContextMethod ],
                      }


    def get_free(self) :
        if self._ins == [] :
            return False

        if "store" in self._ins[-1].get_name() :
            return True
        elif "putfield" in self._ins[-1].get_name() :
            return True

        return False

    def analyze(self) :
        ctt = []

        stack = Stack()
        for i in self._ins :
            v = self.trans(i)
            if v != None :
                ctt.append( v )

            t = ""

            for mre in jvm.MATH_JVM_RE :
                if mre[0].match( i.get_name() ) :
                    self._ops.append( mre[1] )
                    break

            # Woot it's a field !
            if i.get_name() in FIELDS :
                t = "F"
            elif i.get_name() in METHODS :
                t = "M"

            if t != "" :
                o = i.get_operands()
                desc = getattr(self._vm, self.__info[t][0])(o[0], o[1], o[2])

                # It's an external
                if desc == None :
                    desc = ExternalFM( o[0], o[1], o[2] )

                if desc not in self.__info[t][1] :
                    self.__info[t][1][desc] = []

                if t == "F" :
                    self.__info[t][1][desc].append( self.__info[t][2]( FIELDS[ i.get_name() ][0] ) )

#               print "RES", res, "-->", desc.get_name()
#               self.__tf.push_info( desc, [ FIELDS[ i.get_name() ][0], res ] )
                elif t == "M" :
                    self.__info[t][1][desc].append( self.__info[t][2]() )

        for i in self._fields :
            for k in self._fields[i] :
                k.set_details( ctt )

        for i in self._methods :
            for k in self._methods[i] :
                k.set_details( ctt )

    def trans(self, i) :
        v = i.get_name()[0:2]
        if v == "il" or v == "ic" or v == "ia" or v == "si" or v == "bi" :
            return "I"

        if v == "ba" :
            return "B"

        if v == "if" :
            return "IF"

        if v == "ir" :
            return "RET"

        if "and" in i.get_name() :
            return "&"

        if "add" in i.get_name() :
            return "+"

        if "sub" in i.get_name() :
            return "-"

        if "xor" in i.get_name() :
            return "^"

        if "ldc" in i.get_name() :
            return "I"

        if "invokevirtual" in i.get_name() :
            return "M" + i.get_operands()[2]

        if "getfield" in i.get_name() :
            return "F" + i.get_operands()[2]


DVM_FIELDS_ACCESS = {
      "iget" : "R",
      "iget-wide" : "R",
      "iget-object" : "R",
      "iget-boolean" : "R",
      "iget-byte" : "R",
      "iget-char" : "R",
      "iget-short" : "R",

      "iput" : "W",
      "iput-wide" : "W",
      "iput-object" : "W",
      "iput-boolean" : "W",
      "iput-byte" : "W",
      "iput-char" : "W",
      "iput-short" : "W",

      "sget" : "R",
      "sget-wide" : "R",
      "sget-object" : "R",
      "sget-boolean" : "R",
      "sget-byte" : "R",
      "sget-char" : "R",
      "sget-short" : "R",

      "sput" : "W",
      "sput-wide" : "W",
      "sput-object" : "W",
      "sput-boolean" : "W",
      "sput-byte" : "W",
      "sput-char" : "W",
      "sput-short" : "W",
   }

class DVMBasicBlock:
    """
        A simple basic block of a dalvik method
    """
    def __init__(self, start, vm, method, context):
        self.__vm = vm
        self.method = method
        self.context = context

        self.last_length = 0
        self.nb_instructions = 0

        self.fathers = []
        self.childs = []

        self.start = start
        self.end = self.start

        self.special_ins = {}

        self.name = "%s-BB@0x%x" % (self.method.get_name(), self.start)
        self.exception_analysis = None

        self.tainted_variables = self.context.get_tainted_variables()
        self.tainted_packages = self.context.get_tainted_packages()

    def get_instructions(self):
      """
        Get all instructions from a basic block.

        :rtype: Return all instructions in the current basic block
      """
      tmp_ins = []
      idx = 0
      for i in self.method.get_instructions():
        if idx >= self.start and idx < self.end:
          tmp_ins.append(i)

        idx += i.get_length()
      return tmp_ins

    def get_nb_instructions(self):
        return self.nb_instructions

    def get_method(self):
        return self.method

    def get_name(self):
        return self.name

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_last(self):
        return self.get_instructions()[-1]

    def get_next(self):
        """
            Get next basic blocks

            :rtype: a list of the next basic blocks
        """
        return self.childs

    def get_prev(self):
        """
            Get previous basic blocks

            :rtype: a list of the previous basic blocks
        """
        return self.fathers

    def set_fathers(self, f):
        self.fathers.append(f)

    def get_last_length(self):
      return self.last_length

    def set_childs(self, values):
        #print self, self.start, self.end, values
        if values == [] :
            next_block = self.context.get_basic_block( self.end + 1 )
            if next_block != None :
                self.childs.append( ( self.end - self.get_last_length(), self.end, next_block ) )
        else :
            for i in values :
                if i != -1 :
                    next_block = self.context.get_basic_block( i )
                    if next_block != None :
                        self.childs.append( ( self.end - self.get_last_length(), i, next_block) )

        for c in self.childs :
            if c[2] != None :
                c[2].set_fathers( ( c[1], c[0], self ) )

    def push(self, i):
      try :
            self.nb_instructions += 1
            idx = self.end
            self.last_length = i.get_length()
            self.end += self.last_length

            op_value = i.get_op_value()

            #if i.get_name() in DVM_FIELDS_ACCESS :
            if (op_value >= 0x52 and op_value <= 0x6d) :
                desc = self.__vm.get_cm_field( i.get_ref_kind() )
                if self.tainted_variables != None :
                    self.tainted_variables.push_info( TAINTED_FIELD, desc, DVM_FIELDS_ACCESS[ i.get_name() ][0], idx, self.method )

            #elif "invoke" in i.get_name() :
            elif (op_value >= 0x6e and op_value <= 0x72) or (op_value >= 0x74 and op_value <= 0x78) :
                idx_meth = i.get_ref_kind()
                method_info = self.__vm.get_cm_method( idx_meth )
                if self.tainted_packages != None :
                    self.tainted_packages.push_info( method_info[0], TAINTED_PACKAGE_CALL, idx, self.method, idx_meth )

            #elif "new-instance" in i.get_name() :
            elif op_value == 0x22 :
                idx_type = i.get_ref_kind()
                type_info = self.__vm.get_cm_type( idx_type )
                if self.tainted_packages != None :
                    self.tainted_packages.push_info( type_info, TAINTED_PACKAGE_CREATE, idx, self.method, None )

            #elif "const-string" in i.get_name() :
            elif (op_value >= 0x1a and op_value <= 0x1b) :
                string_name = self.__vm.get_cm_string( i.get_ref_kind() )
                if self.tainted_variables != None :
                    self.tainted_variables.push_info( TAINTED_STRING, string_name, "R", idx, self.method )

            elif op_value == 0x26 or (op_value >= 0x2b and op_value <= 0x2c) :
                code = self.method.get_code().get_bc()
                self.special_ins[ idx ] = code.get_ins_off( idx + i.get_ref_off() * 2 )
      except :
        pass

    def get_special_ins(self, idx):
        """
            Return the associated instruction to a specific instruction (for example a packed/sparse switch)

            :param idx: the index of the instruction

            :rtype: None or an Instruction
        """
        try:
            return self.special_ins[idx]
        except:
            return None

    def get_exception_analysis(self):
        return self.exception_analysis

    def set_exception_analysis(self, exception_analysis):
        self.exception_analysis = exception_analysis

TAINTED_LOCAL_VARIABLE = 0
TAINTED_FIELD = 1
TAINTED_STRING = 2

class PathVar :
  def __init__(self, access, idx, dst_idx, info_obj) :
    self.access_flag = access
    self.idx = idx
    self.dst_idx = dst_idx
    self.info_obj = info_obj

  def get_var_info(self) :
    return self.info_obj.get_info()

  def get_access_flag(self) :
    return self.access_flag

  def get_dst(self, cm) :
    method = cm.get_method_ref( self.dst_idx )
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_idx(self) :
    return self.idx

class TaintedVariable :
    def __init__(self, var, _type) :
        self.var = var
        self.type = _type

        self.paths = {}
        self.__cache = []

    def get_type(self) :
        return self.type

    def get_info(self) :
        if self.type == TAINTED_FIELD :
            return [ self.var[0], self.var[2], self.var[1] ]
        return self.var

    def push(self, access, idx, ref) :
        m_idx = ref.get_method_idx()

        if m_idx not in self.paths :
          self.paths[ m_idx ] = []

        self.paths[ m_idx ].append( (access, idx) )

    def get_paths_access(self, mode) :
        for i in self.paths :
          for j in self.paths[ i ] :
            for k, v in self.paths[ i ][ j ] :
              if k in mode :
                yield i, j, k, v

    def get_paths(self) :
        if self.__cache != [] :
            return self.__cache

        for i in self.paths :
          for j in self.paths[ i ] :
              self.__cache.append( [j, i] )
              #yield j, i
        return self.__cache

    def get_paths_length(self) :
        return len(self.paths)

    def show_paths(self, vm) :
        show_PathVariable( vm, self.get_paths() )

class TaintedVariables :
    def __init__(self, _vm) :
        self.__vm = _vm
        self.__vars = {
           TAINTED_LOCAL_VARIABLE : {},
           TAINTED_FIELD : {},
           TAINTED_STRING : {},
        }

        self.__cache_field_by_method = {}
        self.__cache_string_by_method = {}

    # functions to get particulars elements
    def get_string(self, s) :
        try :
            return self.__vars[ TAINTED_STRING ][ s ]
        except KeyError :
            return None

    def get_field(self, class_name, name, descriptor) :
        key = class_name + descriptor + name

        try :
            return self.__vars[ TAINTED_FIELD ] [ key ]
        except KeyError :
            return None

    def toPathVariable(self, obj) :
      z = []
      for i in obj.get_paths() :
        access, idx = i[0]
        m_idx = i[1]

        z.append( PathVar(access, idx, m_idx, obj ) )
      return z

    # permission functions 
    def get_permissions_method(self, method) :
        permissions = []

        for f, f1 in self.get_fields() :
            data = "%s-%s-%s" % (f1[0], f1[1], f1[2])
            if data in DVM_PERMISSIONS_BY_ELEMENT :
                for path in f.get_paths() :
                    access, idx = path[0]
                    m_idx = path[1]
                    if m_idx == method.get_idx() :
                        if DVM_PERMISSIONS_BY_ELEMENT[ data ] not in permissions :
                            permissions.append( DVM_PERMISSIONS_BY_ELEMENT[ data ] )

        return permissions

    def get_permissions(self, permissions_needed) :
        """
            @param permissions_needed : a list of restricted permissions to get ([] returns all permissions)

            @rtype : a dictionnary of permissions' paths
        """
        permissions = {}

        pn = permissions_needed
        if permissions_needed == [] :
            pn = DVM_PERMISSIONS_BY_PERMISSION.keys()

        for f, f1 in self.get_fields() :
            data = "%s-%s-%s" % (f.var[0], f.var[2], f.var[1])

            if data in DVM_PERMISSIONS_BY_ELEMENT :
                if DVM_PERMISSIONS_BY_ELEMENT[ data ] in pn :
                    try :
                        permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ].extend( self.toPathVariable( f ) )
                    except KeyError :
                        permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ] = []
                        permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ].extend( self.toPathVariable( f ) )

        return permissions

    # global functions

    def get_strings(self) :
        for i in self.__vars[ TAINTED_STRING ] :
            yield self.__vars[ TAINTED_STRING ][ i ], i

    def get_fields(self) :
        for i in self.__vars[ TAINTED_FIELD ] :
            yield self.__vars[ TAINTED_FIELD ][ i ], i

    # specifics functions
    def get_strings_by_method(self, method) :
        z = {}

        try :
            for i in self.__cache_string_by_method[ method.get_method_idx() ] :
                z[ i ] = []
                for j in i.get_paths() :
                    if method.get_method_idx() == j[1] :
                        z[i].append( j[0] )

            return z
        except :
            return z


    def get_fields_by_method(self, method) :
        z = {}

        try :
            for i in self.__cache_field_by_method[ method.get_method_idx() ] :
                z[ i ] = []
                for j in i.get_paths() :
                    if method.get_method_idx() == j[1] :
                        z[i].append( j[0] )
            return z
        except :
            return z

    def add(self, var, _type, _method=None) :
        if _type == TAINTED_FIELD :
            key = var[0] + var[1] + var[2]
            if key not in self.__vars[ TAINTED_FIELD ] :
                self.__vars[ TAINTED_FIELD ][ key ] = TaintedVariable( var, _type )
        elif _type == TAINTED_STRING :
            if var not in self.__vars[ TAINTED_STRING ] :
                self.__vars[ TAINTED_STRING ][ var ] = TaintedVariable( var, _type )
        elif _type == TAINTED_LOCAL_VARIABLE :
            if _method not in self.__vars[ TAINTED_LOCAL_VARIABLE ] :
                self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ] = {}

            if var not in self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ] :
                self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ][ var ] = TaintedVariable( var, _type )

    def push_info(self, _type, var, access, idx, ref) :
        if _type == TAINTED_FIELD :
            self.add( var, _type )
            key = var[0] + var[1] + var[2]
            self.__vars[ _type ][ key ].push( access, idx, ref )

            method_idx = ref.get_method_idx()
            if method_idx not in self.__cache_field_by_method :
                self.__cache_field_by_method[ method_idx ] = set()

            self.__cache_field_by_method[ method_idx ].add( self.__vars[ TAINTED_FIELD ][ key ] )


        elif _type == TAINTED_STRING :
            self.add( var, _type )
            self.__vars[ _type ][ var ].push( access, idx, ref )

            method_idx = ref.get_method_idx()

            if method_idx not in self.__cache_string_by_method :
                self.__cache_string_by_method[ method_idx ] = set()

            self.__cache_string_by_method[ method_idx ].add( self.__vars[ TAINTED_STRING ][ var ] )

TAINTED_PACKAGE_CREATE = 0
TAINTED_PACKAGE_CALL = 1

TAINTED_PACKAGE = {
   TAINTED_PACKAGE_CREATE : "C",
   TAINTED_PACKAGE_CALL : "M"
}
def show_Path(vm, path) :
  cm = vm.get_class_manager()

  if isinstance(path, PathVar) :
    dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
    info_var = path.get_var_info()
    print "%s %s (0x%x) ---> %s->%s%s" % (path.get_access_flag(),
                                          info_var,
                                          path.get_idx(),
                                          dst_class_name,
                                          dst_method_name,
                                          dst_descriptor)
  else :
    if path.get_access_flag() == TAINTED_PACKAGE_CALL :
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

      print "%d %s->%s%s (0x%x) ---> %s->%s%s" % (path.get_access_flag(), 
                                                  src_class_name,
                                                  src_method_name,
                                                  src_descriptor,
                                                  path.get_idx(),
                                                  dst_class_name,
                                                  dst_method_name,
                                                  dst_descriptor)
    else :
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      print "%d %s->%s%s (0x%x)" % (path.get_access_flag(), 
                                    src_class_name,
                                    src_method_name,
                                    src_descriptor,
                                    path.get_idx() )

def show_Paths(vm, paths) :
    """
        Show paths of packages
        :param paths: a list of :class:`PathP` objects
    """
    for path in paths :
        show_Path( vm, path )

def show_PathVariable(vm, paths) :
    for path in paths :
      access, idx = path[0]
      m_idx = path[1]
      method = vm.get_cm_method( m_idx )
      print "%s %x %s->%s %s" % (access, idx, method[0], method[1], method[2][0] + method[2][1])

class PathP :
  def __init__(self, access, idx, src_idx, dst_idx) :
    self.access_flag = access
    self.idx = idx
    self.src_idx = src_idx
    self.dst_idx = dst_idx

  def get_access_flag(self) :
    return self.access_flag

  def get_dst(self, cm) :
    method = cm.get_method_ref( self.dst_idx )
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_src(self, cm) :
    method = cm.get_method_ref( self.src_idx )
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_idx(self) :
    return self.idx

  def get_src_idx(self):
    return self.src_idx

  def get_dst_idx(self):
    return self.dst_idx

class TaintedPackage:
    def __init__(self, vm, name):
        self.vm = vm
        self.name = name
        self.paths = {TAINTED_PACKAGE_CREATE : [], TAINTED_PACKAGE_CALL : []}

    def get_name(self) :
        return self.name

    def gets(self) :
        return self.paths

    def push(self, access, idx, src_idx, dst_idx) :
        p = PathP( access, idx, src_idx, dst_idx )
        self.paths[ access ].append( p )
        return p

    def get_objects_paths(self) :
        return self.paths[ TAINTED_PACKAGE_CREATE ]

    def search_method(self, name, descriptor) :
        """
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method

            @rtype : a list of called paths
        """
        l = []
        m_name = re.compile(name)
        m_descriptor = re.compile(descriptor)

        for path in self.paths[ TAINTED_PACKAGE_CALL ] :
            _, dst_name, dst_descriptor = path.get_dst(self.vm.get_class_manager())

            if m_name.match( dst_name ) != None and m_descriptor.match( dst_descriptor ) != None :
                l.append( path )
        return l

    def get_method(self, name, descriptor) :
        l = []
        for path in self.paths[ TAINTED_PACKAGE_CALL ] :
            if path.get_name() == name and path.get_descriptor() == descriptor :
                l.append( path )
        return l

    def get_paths(self) :
        for i in self.paths :
            for j in self.paths[ i ] :
                yield j

    def get_paths_length(self) :
        x = 0
        for i in self.paths :
            x += len(self.paths[ i ])
        return x

    def get_methods(self):
        return [path for path in self.paths[TAINTED_PACKAGE_CALL]]

    def get_new(self):
        return [path for path in self.paths[TAINTED_PACKAGE_CREATE]]

    def show(self) :
        cm = self.vm.get_class_manager()
        print self.get_name()
        for _type in self.paths:
            print "\t -->", _type
            if _type == TAINTED_PACKAGE_CALL:
                for path in self.paths[_type]:
                    print "\t\t => %s <-- %x in %s" % (path.get_dst(cm), path.get_idx(), path.get_src(cm))
            else:
                for path in self.paths[_type]:
                    print "\t\t => %x in %s" % (path.get_idx(), path.get_src(cm))

def show_Permissions(dx) :
    """
        Show where permissions are used in a specific application
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    p = dx.get_permissions( [] )

    for i in p :
        print i, ":"
        for j in p[i] :
            show_Path( dx.get_vm(), j )

def show_DynCode(dx) :
    """
        Show where dynamic code is used
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    paths = dx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
    show_Paths( dx.get_vm(), paths )

def show_NativeMethods(dx) :
    """
        Show the native methods
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    d = dx.get_vm()
    for i in d.get_methods() :
        if i.get_access_flags() & 0x100 :
            print i.get_class_name(), i.get_name(), i.get_descriptor()

def show_ReflectionCode(dx) :
    """
        Show the reflection code 
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
    show_Paths( dx.get_vm(), paths )

def is_crypto_code(dx) :
    """
        Crypto code is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    paths = dx.get_tainted_packages().search_methods( "Ljavax/crypto/.", ".", ".")
    if paths != [] :
        return True

    return False

def is_dyn_code(dx) :
    """
        Dynamic code loading is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    paths = dx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
    if paths != [] :
        return True

    return False

def is_reflection_code(dx) :
    """
        Reflection is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/reflect/Method;", ".", ".")
    if paths != [] :
        return True

    return False

def is_native_code(dx) :
    """
        Native code is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    paths = dx.get_tainted_packages().search_methods( "Ljava/lang/System;", "loadLibrary", ".")
    if paths != [] :
        return True

    return False

class TaintedPackages :
    def __init__(self, _vm) :
        self.__vm = _vm
        self.__packages = {}
        self.__methods = {}

    def _add_pkg(self, name) :
        if name not in self.__packages :
            self.__packages[ name ] = TaintedPackage( self.__vm, name )

    #self.context.get_tainted_packages().push_info( method_info[0], TAINTED_PACKAGE_CALL, idx, self, self.method, method_info[1], method_info[2][0] + method_info[2][1] )
    def push_info(self, class_name, access, idx, method, idx_method) :
        self._add_pkg( class_name )
        p = self.__packages[ class_name ].push( access, idx, method.get_method_idx(), idx_method )

        try :
            self.__methods[ method ][ class_name ].append( p )
        except :
            try :
                self.__methods[ method ][ class_name ] = []
            except :
                self.__methods[ method ] = {}
                self.__methods[ method ][ class_name ] = []

            self.__methods[ method ][ class_name ].append( p )

    def get_packages_by_method(self, method):
        try:
            return self.__methods[method]
        except KeyError:
            return {}

    def get_package(self, name):
        return self.__packages[name]

    def get_packages_by_bb(self, bb):
        """
            :rtype: return a list of packaged used in a basic block
        """
        l = []
        for i in self.__packages :
            paths = self.__packages[i].gets()
            for j in paths :
                for k in paths[j] :
                    if k.get_bb() == bb :
                        l.append( (i, k.get_access_flag(), k.get_idx(), k.get_method()) )

        return l

    def get_packages(self):
        for i in self.__packages:
            yield self.__packages[i], i

    def get_internal_packages_from_package(self, package):
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())

                if src_class_name == package and dst_class_name in classes:
                    l.append(j)
        return l

    def get_internal_packages(self):
        """
            :rtype: return a list of the internal packages called in the application
        """
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                  dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())
                  if dst_class_name in classes and m.get_name() in classes:
                    l.append(j)
        return l

    def get_internal_new_packages(self):
        """
            :rtype: return a list of the internal packages created in the application
        """
        classes = self.__vm.get_classes_names()
        l = {}
        for m, _ in self.get_packages():
            paths = m.get_new()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                if src_class_name in classes and m.get_name() in classes:
                    if j.get_access_flag() == TAINTED_PACKAGE_CREATE:
                        try:
                            l[m.get_name()].append(j)
                        except:
                            l[m.get_name()] = []
                            l[m.get_name()].append(j)
        return l

    def get_external_packages(self):
        """
            :rtype: return a list of the external packages called in the application
        """
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())
                if src_class_name in classes and dst_class_name not in classes:
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                        l.append(j)
        return l

    def search_packages(self, package_name):
        """
            :param package_name: a regexp for the name of the package

            :rtype: a list of called packages' paths
        """
        ex = re.compile(package_name)   

        l = []
        for m, _ in self.get_packages():
            if ex.search(m.get_name()) != None:
                l.extend(m.get_methods())
        return l

    def search_unique_packages(self, package_name) :
        """
            :param package_name: a regexp for the name of the package
        """
        ex = re.compile( package_name )

        l = []
        d = {} 
        for m, _ in self.get_packages() :
            if ex.match( m.get_info() ) != None :
                for path in m.get_methods() :
                    try :
                        d[ path.get_class_name() + path.get_name() + path.get_descriptor() ] += 1
                    except KeyError :
                        d[ path.get_class_name() + path.get_name() + path.get_descriptor() ] = 0
                        l.append( [ path.get_class_name(), path.get_name(), path.get_descriptor() ] )
        return l, d

    def search_methods(self, class_name, name, descriptor, re_expr=True) :
        """
            @param class_name : a regexp for the class name of the method (the package)
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method

            @rtype : a list of called methods' paths
        """
        l = []
        if re_expr == True :
            ex = re.compile( class_name )

            for m, _ in self.get_packages() :
                if ex.search( m.get_name() ) != None :
                    l.extend( m.search_method( name, descriptor ) )

        return l
    
    def search_objects(self, class_name) :
        """
            @param class_name : a regexp for the class name

            @rtype : a list of created objects' paths
        """
        ex = re.compile( class_name )
        l = []

        for m, _ in self.get_packages() :
            if ex.search( m.get_name() ) != None :
                l.extend( m.get_objects_paths() )
    
        return l

    def search_crypto_packages(self) :
        """
            @rtype : a list of called crypto packages
        """
        return self.search_packages( "Ljavax/crypto/" )

    def search_telephony_packages(self) :
        """
            @rtype : a list of called telephony packages
        """
        return self.search_packages( "Landroid/telephony/" )

    def search_net_packages(self) :
        """
            @rtype : a list of called net packages 
        """
        return self.search_packages( "Landroid/net/" )

    def get_method(self, class_name, name, descriptor) :
        try :
            return self.__packages[ class_name ].get_method( name, descriptor )
        except KeyError :
            return []

    def get_permissions_method(self, method) :
        permissions = []

        for m, _ in self.get_packages() :
            paths = m.get_methods()
            for j in paths :
                if j.get_method() == method :
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL :
                        tmp = j.get_descriptor()
                        tmp = tmp[ : tmp.rfind(")") + 1 ]
                        data = "%s-%s-%s" % (m.get_info(), j.get_name(), tmp)
                        if data in DVM_PERMISSIONS_BY_ELEMENT :
                            if DVM_PERMISSIONS_BY_ELEMENT[ data ] not in permissions :
                                permissions.append( DVM_PERMISSIONS_BY_ELEMENT[ data ] )
        return permissions

    def get_permissions(self, permissions_needed) :
        """
            @param permissions_needed : a list of restricted permissions to get ([] returns all permissions)
            @rtype : a dictionnary of permissions' paths
        """
        permissions = {}

        pn = permissions_needed
        if permissions_needed == [] :
            pn = DVM_PERMISSIONS_BY_PERMISSION.keys()

        classes = self.__vm.get_classes_names()

        for m, _ in self.get_packages() :
            paths = m.get_methods()
            for j in paths :
                src_class_name, src_method_name, src_descriptor = j.get_src( self.__vm.get_class_manager() )
                dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.__vm.get_class_manager() )
                if src_class_name in classes and m.get_name() not in classes :
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL :
                        tmp = dst_descriptor
                        tmp = tmp[ : tmp.rfind(")") + 1 ]

                        #data = "%s-%s-%s" % (m.get_info(), j.get_name(), j.get_descriptor())
                        data = "%s-%s-%s" % (m.get_name(), dst_method_name, tmp)

                        if data in DVM_PERMISSIONS_BY_ELEMENT :
                            if DVM_PERMISSIONS_BY_ELEMENT[ data ] in pn :
                                try :
                                    permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ].append( j )
                                except KeyError :
                                    permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ] = []
                                    permissions[ DVM_PERMISSIONS_BY_ELEMENT[ data ] ].append( j )

        return permissions

class Enum(object):
  def __init__(self, names):
    self.names = names
    for value, name in enumerate(self.names):
      setattr(self, name.upper(), value)
  
  def tuples(self):
    return tuple(enumerate(self.names))

TAG_ANDROID = Enum([ 'ANDROID', 'TELEPHONY', 'ACCESSIBILITYSERVICE', 'ACCOUNTS',
    'ANIMATION', 'APP', 'BLUETOOTH', 'CONTENT', 'DATABASE', 'DRM', 'GESTURE',
    'GRAPHICS', 'HARDWARE', 'INPUTMETHODSERVICE', 'LOCATION', 'MEDIA', 'MTP',
    'NET', 'NFC', 'OPENGL', 'OS', 'PREFERENCE', 'PROVIDER', 'RENDERSCRIPT',
    'SAX', 'SECURITY', 'SERVICE', 'SPEECH', 'SUPPORT', 'TEST', 'TEXT', 'UTIL',
    'VIEW', 'WEBKIT', 'WIDGET', 'DALVIK_BYTECODE', 'DALVIK_SYSTEM'])

TAG_REVERSE_ANDROID = dict((i[0], i[1]) for i in TAG_ANDROID.tuples())

TAGS_ANDROID = { TAG_ANDROID.ANDROID :                  [ 0, "Landroid" ],
                 TAG_ANDROID.TELEPHONY :                [ 0, "Landroid/telephony"],
                 TAG_ANDROID.ACCESSIBILITYSERVICE :     [ 0, "Landroid/accessibilityservice" ],
                 TAG_ANDROID.ACCOUNTS :                 [ 0, "Landroid/accounts" ],
                 TAG_ANDROID.ANIMATION :                [ 0, "Landroid/animation" ],
                 TAG_ANDROID.APP :                      [ 0, "Landroid/app" ],
                 TAG_ANDROID.BLUETOOTH :                [ 0, "Landroid/bluetooth" ],
                 TAG_ANDROID.CONTENT :                  [ 0, "Landroid/content" ],
                 TAG_ANDROID.DATABASE :                 [ 0, "Landroid/database" ],
                 TAG_ANDROID.DRM :                      [ 0, "Landroid/drm" ],
                 TAG_ANDROID.GESTURE :                  [ 0, "Landroid/gesture" ],
                 TAG_ANDROID.GRAPHICS :                 [ 0, "Landroid/graphics" ],
                 TAG_ANDROID.HARDWARE :                 [ 0, "Landroid/hardware" ],
                 TAG_ANDROID.INPUTMETHODSERVICE :       [ 0, "Landroid/inputmethodservice" ],
                 TAG_ANDROID.LOCATION :                 [ 0, "Landroid/location" ],
                 TAG_ANDROID.MEDIA :                    [ 0, "Landroid/media" ],
                 TAG_ANDROID.MTP :                      [ 0, "Landroid/mtp" ],
                 TAG_ANDROID.NET :                      [ 0, "Landroid/net" ],
                 TAG_ANDROID.NFC :                      [ 0, "Landroid/nfc" ],
                 TAG_ANDROID.OPENGL :                   [ 0, "Landroid/opengl" ],
                 TAG_ANDROID.OS :                       [ 0, "Landroid/os" ],
                 TAG_ANDROID.PREFERENCE :               [ 0, "Landroid/preference" ],
                 TAG_ANDROID.PROVIDER :                 [ 0, "Landroid/provider" ],
                 TAG_ANDROID.RENDERSCRIPT :             [ 0, "Landroid/renderscript" ],
                 TAG_ANDROID.SAX :                      [ 0, "Landroid/sax" ],
                 TAG_ANDROID.SECURITY :                 [ 0, "Landroid/security" ],
                 TAG_ANDROID.SERVICE :                  [ 0, "Landroid/service" ],
                 TAG_ANDROID.SPEECH :                   [ 0, "Landroid/speech" ],
                 TAG_ANDROID.SUPPORT :                  [ 0, "Landroid/support" ],
                 TAG_ANDROID.TEST :                     [ 0, "Landroid/test" ],
                 TAG_ANDROID.TEXT :                     [ 0, "Landroid/text" ],
                 TAG_ANDROID.UTIL :                     [ 0, "Landroid/util" ],
                 TAG_ANDROID.VIEW :                     [ 0, "Landroid/view" ],
                 TAG_ANDROID.WEBKIT :                   [ 0, "Landroid/webkit" ],
                 TAG_ANDROID.WIDGET :                   [ 0, "Landroid/widget" ],
                 TAG_ANDROID.DALVIK_BYTECODE :          [ 0, "Ldalvik/bytecode" ],
                 TAG_ANDROID.DALVIK_SYSTEM :            [ 0, "Ldalvik/system" ],
}

class Tags :
  """
      Handle specific tags
      
      :param patterns:
      :params reverse:
  """
  def __init__(self, patterns=TAGS_ANDROID, reverse=TAG_REVERSE_ANDROID) :
    self.tags = set()
   
    self.patterns = patterns
    self.reverse = TAG_REVERSE_ANDROID

    for i in self.patterns :
      self.patterns[i][1] = re.compile(self.patterns[i][1])

  def emit(self, method) :
    for i in self.patterns :
      if self.patterns[i][0] == 0 :
        if self.patterns[i][1].search( method.get_class() ) != None :
          self.tags.add( i )
  
  def emit_by_classname(self, classname) :
    for i in self.patterns :
      if self.patterns[i][0] == 0 :
        if self.patterns[i][1].search( classname ) != None :
          self.tags.add( i )

  def __contains__(self, key) :
    return key in self.tags

  def __str__(self) :
    return str([ self.reverse[ i ] for i in self.tags ])

  def empty(self) :
    return self.tags == set()


class BasicBlocks:
    """
        This class represents all basic blocks of a method
    """
    def __init__(self, _vm, tv):
        self.__vm = _vm
        self.tainted = tv

        self.bb = []

    def push(self, bb):
        self.bb.append(bb)

    def pop(self, idx):
        return self.bb.pop(idx)

    def get_basic_block(self, idx):
        for i in self.bb:
            if idx >= i.get_start() and idx < i.get_end():
                return i
        return None

    def get_tainted_integers(self):
        try:
          return self.tainted.get_tainted_integers()
        except:
          return None

    def get_tainted_packages(self):
        try:
          return self.tainted.get_tainted_packages()
        except:
          return None

    def get_tainted_variables(self):
        try:
          return self.tainted.get_tainted_variables()
        except:
          return None

    def get(self):
        """
            :rtype: return each basic block (:class:`DVMBasicBlock` object)
        """
        for i in self.bb:
            yield i

    def gets(self):
        """
            :rtype: a list of basic blocks (:class:`DVMBasicBlock` objects)
        """
        return self.bb

    def get_basic_block_pos(self, idx):
        return self.bb[idx]

class ExceptionAnalysis :
    def __init__(self, exception, bb) :
        self.start = exception[0]
        self.end = exception[1]

        self.exceptions = exception[2:]

        for i in self.exceptions :
            i.append( bb.get_basic_block( i[1] ) )

    def show_buff(self) :
        buff = "%x:%x\n" % (self.start, self.end)

        for i in self.exceptions :
            if i[2] == None :
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2])
            else :
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2].get_name())

        return buff[:-1]

class Exceptions :
    def __init__(self, _vm) :
        self.__vm = _vm
        self.exceptions = []

    def add(self, exceptions, basic_blocks) :
        for i in exceptions :
            self.exceptions.append( ExceptionAnalysis( i, basic_blocks ) )

    def get_exception(self, addr_start, addr_end) :
        for i in self.exceptions :
#            print hex(i.start), hex(i.end), hex(addr_start), hex(addr_end), i.start >= addr_start and i.end <= addr_end, addr_end <= i.end and addr_start >= i.start
            if i.start >= addr_start and i.end <= addr_end :
                return i

            elif addr_end <= i.end and addr_start >= i.start :
                return i

        return None

    def gets(self) :
        return self.exceptions

    def get(self) :
        for i in self.exceptions :
            yield i

#BO = { "BasicOPCODES" : jvm.BRANCH2_JVM_OPCODES, "BasicClass" : JVMBasicBlock, "Dnext" : jvm.determineNext, "Dexception" : jvm.determineException }
BO = { "BasicOPCODES" : dvm.BRANCH_DVM_OPCODES, "BasicClass" : DVMBasicBlock, "Dnext" : dvm.determineNext, "Dexception" : dvm.determineException }

BO["BasicOPCODES_H"] = []
for i in BO["BasicOPCODES"] :
  BO["BasicOPCODES_H"].append( re.compile( i ) )

class MethodAnalysis :
    """
        This class analyses in details a method of a class/dex file

        :param vm: the object which represent the dex file
        :param method: the original method
        :param tv: a virtual object to get access to tainted information
        :type vm: a :class:`DalvikVMFormat` object
        :type method: a :class:`EncodedMethod` object
    """
    def __init__(self, vm, method, tv):
        self.__vm = vm
        self.method = method

        self.tainted = tv

        self.basic_blocks = BasicBlocks( self.__vm, self.tainted )
        self.exceptions = Exceptions( self.__vm )

        code = self.method.get_code()
        if code == None :
            return

        current_basic = BO["BasicClass"]( 0, self.__vm, self.method, self.basic_blocks )
        self.basic_blocks.push( current_basic )

        ##########################################################

        bc = code.get_bc()
        l = []
        h = {}
        idx = 0

        instructions = [ i for i in bc.get_instructions() ]
        for i in instructions :
            for j in BO["BasicOPCODES_H"] :
                if j.match(i.get_name()) != None :
                    v = BO["Dnext"]( i, idx, self.method )
                    h[ idx ] = v
                    l.extend( v )
                    break

            idx += i.get_length()

        excepts = BO["Dexception"]( self.__vm, self.method )
        for i in excepts:
            l.extend( [i[0]] )
            for handler in i[2:] :
                l.append( handler[1] )

        idx = 0
        for i in instructions :
            # index is a destination
            if idx in l :
                if current_basic.get_nb_instructions() != 0 :
                    current_basic = BO["BasicClass"]( current_basic.get_end(), self.__vm, self.method, self.basic_blocks )
                    self.basic_blocks.push( current_basic )

            current_basic.push( i )

            # index is a branch instruction
            if idx in h :
                current_basic = BO["BasicClass"]( current_basic.get_end(), self.__vm, self.method, self.basic_blocks )
                self.basic_blocks.push( current_basic )

            idx += i.get_length()

        if current_basic.get_nb_instructions() == 0 :
            self.basic_blocks.pop( -1 )

        for i in self.basic_blocks.get() :
            try :
                i.set_childs( h[ i.end - i.get_last_length() ] )
            except KeyError :
                i.set_childs( [] )

        # Create exceptions
        self.exceptions.add(excepts, self.basic_blocks)

        for i in self.basic_blocks.get() :
            # setup exception by basic block
            i.set_exception_analysis( self.exceptions.get_exception( i.start, i.end - 1 ) )

        del instructions
        del h, l

    def get_basic_blocks(self):
        """
            :rtype: a :class:`BasicBlocks` object
        """
        return self.basic_blocks
    def get_length(self) :
        """
            :rtype: an integer which is the length of the code
        """
        return self.get_code().get_length()

    def get_vm(self) :
        return self.__vm

    def get_method(self) :
        return self.method

    def get_local_variables(self) :
        return self.tainted.get_tainted_variables().get_local_variables( self.method )

    def show(self) :
        print "METHOD", self.method.get_class_name(), self.method.get_name(), self.method.get_descriptor()

        for i in self.basic_blocks.get() :
            print "\t", i
            i.show()
            print ""

    def show_methods(self) :
        print "\t #METHODS :"
        for i in self.__bb :
            methods = i.get_methods()
            for method in methods :
                print "\t\t-->", method.get_class_name(), method.get_name(), method.get_descriptor()
                for context in methods[method] :
                    print "\t\t\t |---|", context.details

    def create_tags(self) :
      """
          Create the tags for the method
      """
      self.tags = Tags()
      for i in self.tainted.get_tainted_packages().get_packages_by_method( self.method ) :
        self.tags.emit_by_classname( i )

    def get_tags(self) :
      """
          Return the tags of the method

          :rtype: a :class:`Tags` object
      """
      return self.tags

SIGNATURE_L0_0 = "L0_0"
SIGNATURE_L0_1 = "L0_1"
SIGNATURE_L0_2 = "L0_2"
SIGNATURE_L0_3 = "L0_3"
SIGNATURE_L0_4 = "L0_4" 
SIGNATURE_L0_5 = "L0_5"
SIGNATURE_L0_6 = "L0_6"
SIGNATURE_L0_0_L1 = "L0_0:L1"
SIGNATURE_L0_1_L1 = "L0_1:L1"
SIGNATURE_L0_2_L1 = "L0_2:L1"
SIGNATURE_L0_3_L1 = "L0_3:L1"
SIGNATURE_L0_4_L1 = "L0_4:L1"
SIGNATURE_L0_5_L1 = "L0_5:L1"
SIGNATURE_L0_0_L2 = "L0_0:L2"
SIGNATURE_L0_0_L3 = "L0_0:L3"
SIGNATURE_HEX = "hex"
SIGNATURE_SEQUENCE_BB = "sequencebb"

SIGNATURES = {
                SIGNATURE_L0_0 : { "type" : 0 },
                SIGNATURE_L0_1 : { "type" : 1 },
                SIGNATURE_L0_2 : { "type" : 2, "arguments" : ["Landroid"] },
                SIGNATURE_L0_3 : { "type" : 2, "arguments" : ["Ljava"] },
                SIGNATURE_L0_4 : { "type" : 2, "arguments" : ["Landroid", "Ljava"] },
                SIGNATURE_L0_5 : { "type" : 3, "arguments" : ["Landroid"] },
                SIGNATURE_L0_6 : { "type" : 3, "arguments" : ["Ljava"] },
                SIGNATURE_SEQUENCE_BB : {},
                SIGNATURE_HEX : {},
            }

from sign import Signature

class VMAnalysis :
    """
       This class analyses a dex file

       :param _vm: the object which represent the dex file
       :type _vm: a :class:`DalvikVMFormat` object

       :Example:
            VMAnalysis( DalvikVMFormat( open("toto.dex", "r").read() ) )
    """
    def __init__(self, _vm) :
        self.__vm = _vm

        self.tainted_variables = TaintedVariables( self.__vm )
        self.tainted_packages = TaintedPackages( self.__vm )

        self.tainted = { "variables" : self.tainted_variables,
                         "packages" : self.tainted_packages,
                       }

        self.signature = None

        for i in self.__vm.get_all_fields() :
            self.tainted_variables.add( [ i.get_class_name(), i.get_descriptor(), i.get_name() ], TAINTED_FIELD )

        self.methods = []
        self.hmethods = {}
        self.__nmethods = {}
        for i in self.__vm.get_methods() :
            x = MethodAnalysis( self.__vm, i, self )
            self.methods.append( x )
            self.hmethods[ i ] = x
            self.__nmethods[ i.get_name() ] = x

    def get_vm(self) :
        return self.__vm

    def get_method(self, method) :
        """
            Return an analysis method

            :param method: a classical method object
            :type method: an :class:`EncodedMethod` object

            :rtype: a :class:`MethodAnalysis` object
        """
        return self.hmethods[ method ]

    def get_methods(self) :
        """
           Return each analysis method

           :rtype: a :class:`MethodAnalysis` object
        """
        for i in self.hmethods :
            yield self.hmethods[i]

    def get_method_signature(self, method, grammar_type="", options={}, predef_sign="") :
        """
            Return a specific signature for a specific method

            :param method: a reference to method from a vm class
            :type method: a :class:`EncodedMethod` object

            :param grammar_type: the type of the signature (optional)
            :type grammar_type: string

            :param options: the options of the signature (optional)
            :param options: dict

            :param predef_sign: used a predefined signature (optional)
            :type predef_sign: string

            :rtype: a :class:`Sign` object
        """        
        if self.signature == None :
          self.signature = Signature( self )

        if predef_sign != "" :
            g = ""
            o = {} 

            for i in predef_sign.split(":") :
                if "_" in i :
                    g += "L0:"
                    o[ "L0" ] = SIGNATURES[ i ]
                else :
                    g += i
                    g += ":" 

            return self.signature.get_method( self.get_method( method ), g[:-1], o )
        else : 
            return self.signature.get_method( self.get_method( method ), grammar_type, options )

    def get_permissions(self, permissions_needed) :
        """
            Return the permissions used

            :param permissions_needed: a list of restricted permissions to get ([] returns all permissions)
            :type permissions_needed: list
            
            :rtype: a dictionnary of permissions paths
        """
        permissions = {}

        permissions.update( self.get_tainted_packages().get_permissions( permissions_needed ) )
        permissions.update( self.get_tainted_variables().get_permissions( permissions_needed ) )

        return permissions

    def get_permissions_method(self, method) :
        permissions_f = self.get_tainted_packages().get_permissions_method( method )
        permissions_v = self.get_tainted_variables().get_permissions_method( method )

        return list( set( permissions_f + permissions_v ) )
 
    def get_tainted_variables(self) :
        """
           Return the tainted variables

           :rtype: a :class:`TaintedVariables` object
        """
        return self.tainted_variables

    def get_tainted_packages(self) :
        """
           Return the tainted packages

           :rtype: a :class:`TaintedPackages` object
        """
        return self.tainted_packages

    def get_tainted_fields(self) :
        return self.get_tainted_variables().get_fields()

    def get_tainted_field(self, class_name, name, descriptor) :
        """
           Return a specific tainted field

           :param class_name: the name of the class
           :param name: the name of the field
           :param descriptor: the descriptor of the field
           :type class_name: string
           :type name: string
           :type descriptor: string

           :rtype: a :class:`TaintedVariable` object
        """
        return self.get_tainted_variables().get_field( class_name, name, descriptor )

class uVMAnalysis(VMAnalysis) :
  """
     This class analyses a dex file but on the fly (quicker !)

     :param _vm: the object which represent the dex file
     :type _vm: a :class:`DalvikVMFormat` object

     :Example:
          uVMAnalysis( DalvikVMFormat( open("toto.dex", "r").read() ) )
  """
  def __init__(self, vm) :
    self.vm = vm
    self.tainted_variables = TaintedVariables( self.vm )
    self.tainted_packages = TaintedPackages( self.vm )

    self.tainted = { "variables" : self.tainted_variables,
                     "packages" : self.tainted_packages,
    }

    self.signature = None
    self.resolve = False

  def get_methods(self) :
    self.resolve = True
    for i in self.vm.get_methods() :
      yield MethodAnalysis( self.vm, i, self )

  def get_method(self, method) :
    return MethodAnalysis( self.vm, method, None )

  def get_vm(self) :
    return self.vm

  def _resolve(self) :
    if self.resolve == False :
      for i in self.get_methods() :
        pass

  def get_tainted_packages(self) :
    self._resolve()
    return self.tainted_packages

  def get_tainted_variables(self) :
        self._resolve()
        return self.tainted_variables
