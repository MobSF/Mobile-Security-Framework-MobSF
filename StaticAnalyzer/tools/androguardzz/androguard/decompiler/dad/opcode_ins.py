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
from struct import pack, unpack
import androguard.decompiler.dad.util as util
from androguard.decompiler.dad.instruction import (ArrayLengthExpression,
                            ArrayLoadExpression, ArrayStoreInstruction,
                            AssignExpression, BaseClass, BinaryCompExpression,
                            BinaryExpression, BinaryExpression2Addr,
                            BinaryExpressionLit, CastExpression,
                            CheckCastExpression, ConditionalExpression,
                            ConditionalZExpression, Constant,
                            FillArrayExpression, FilledArrayExpression,
                            InstanceExpression, InstanceInstruction,
                            InvokeInstruction, InvokeDirectInstruction,
                            InvokeRangeInstruction, InvokeStaticInstruction,
                            MonitorEnterExpression, MonitorExitExpression,
                            MoveExpression, MoveResultExpression,
                            NewArrayExpression, NewInstance, NopExpression,
                            RefExpression, ThrowExpression, Variable,
                            ReturnInstruction, StaticExpression,
                            StaticInstruction, SwitchExpression,
                            UnaryExpression)


logger = logging.getLogger('dad.opcode_ins')


EXPR = 0
INST = 1
COND = 2


class Op(object):
    CMP = 'cmp'
    ADD = '+'
    SUB = '-'
    MUL = '*'
    DIV = '/'
    MOD = '%'
    AND = '&'
    OR = '|'
    XOR = '^'
    EQUAL = '=='
    NEQUAL = '!='
    GREATER = '>'
    LOWER = '<'
    GEQUAL = '>='
    LEQUAL = '<='
    NEG = '-'
    NOT = '~'
    INTSHL = '<<'  # '(%s << ( %s & 0x1f ))'
    INTSHR = '>>'  # '(%s >> ( %s & 0x1f ))'
    LONGSHL = '<<'  # '(%s << ( %s & 0x3f ))'
    LONGSHR = '>>'  # '(%s >> ( %s & 0x3f ))'


def get_variables(vmap, *variables):
    res = []
    for variable in variables:
        res.append(vmap.setdefault(variable, Variable(variable)))
    if len(res) == 1:
        return res[0]
    return res


def assign_const(dest_reg, cst, vmap):
    return AssignExpression(get_variables(vmap, dest_reg), cst)


def assign_cmp(val_a, val_b, val_c, cmp_type, vmap):
    reg_a, reg_b, reg_c = get_variables(vmap, val_a, val_b, val_c)
    exp = BinaryCompExpression(Op.CMP, reg_b, reg_c, cmp_type)
    return AssignExpression(reg_a, exp)


def load_array_exp(val_a, val_b, val_c, ar_type, vmap):
    reg_a, reg_b, reg_c = get_variables(vmap, val_a, val_b, val_c)
    return AssignExpression(reg_a, ArrayLoadExpression(reg_b, reg_c, ar_type))


def store_array_inst(val_a, val_b, val_c, ar_type, vmap):
    reg_a, reg_b, reg_c = get_variables(vmap, val_a, val_b, val_c)
    return ArrayStoreInstruction(reg_a, reg_b, reg_c, ar_type)


def assign_cast_exp(val_a, val_b, val_op, op_type, vmap):
    reg_a, reg_b = get_variables(vmap, val_a, val_b)
    return AssignExpression(reg_a, CastExpression(val_op, op_type, reg_b))


def assign_binary_exp(ins, val_op, op_type, vmap):
    reg_a, reg_b, reg_c = get_variables(vmap, ins.AA, ins.BB, ins.CC)
    return AssignExpression(reg_a, BinaryExpression(val_op, reg_b,
                                                    reg_c, op_type))


def assign_binary_2addr_exp(ins, val_op, op_type, vmap):
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    return AssignExpression(reg_a, BinaryExpression2Addr(val_op, reg_a,
                                                         reg_b, op_type))


def assign_lit(op_type, val_cst, val_a, val_b, vmap):
    cst = Constant(val_cst, 'I')
    var_a, var_b = get_variables(vmap, val_a, val_b)
    return AssignExpression(var_a, BinaryExpressionLit(op_type, var_b, cst))


# nop
def nop(ins, vmap):
    return NopExpression()


# move vA, vB ( 4b, 4b )
def move(ins, vmap):
    logger.debug('Move %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    return MoveExpression(reg_a, reg_b)


# move/from16 vAA, vBBBB ( 8b, 16b )
def movefrom16(ins, vmap):
    logger.debug('MoveFrom16 %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move/16 vAAAA, vBBBB ( 16b, 16b )
def move16(ins, vmap):
    logger.debug('Move16 %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AAAA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move-wide vA, vB ( 4b, 4b )
def movewide(ins, vmap):
    logger.debug('MoveWide %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    return MoveExpression(reg_a, reg_b)


# move-wide/from16 vAA, vBBBB ( 8b, 16b )
def movewidefrom16(ins, vmap):
    logger.debug('MoveWideFrom16 : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move-wide/16 vAAAA, vBBBB ( 16b, 16b )
def movewide16(ins, vmap):
    logger.debug('MoveWide16 %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AAAA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move-object vA, vB ( 4b, 4b )
def moveobject(ins, vmap):
    logger.debug('MoveObject %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    return MoveExpression(reg_a, reg_b)


# move-object/from16 vAA, vBBBB ( 8b, 16b )
def moveobjectfrom16(ins, vmap):
    logger.debug('MoveObjectFrom16 : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move-object/16 vAAAA, vBBBB ( 16b, 16b )
def moveobject16(ins, vmap):
    logger.debug('MoveObject16 : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AAAA, ins.BBBB)
    return MoveExpression(reg_a, reg_b)


# move-result vAA ( 8b )
def moveresult(ins, vmap, ret):
    logger.debug('MoveResult : %s', ins.get_output())
    return MoveResultExpression(get_variables(vmap, ins.AA), ret, None)


# move-result-wide vAA ( 8b )
def moveresultwide(ins, vmap, ret):
    logger.debug('MoveResultWide : %s', ins.get_output())
    return MoveResultExpression(get_variables(vmap, ins.AA), ret, 'W')


# move-result-object vAA ( 8b )
def moveresultobject(ins, vmap, ret):
    logger.debug('MoveResultObject : %s', ins.get_output())
    return MoveResultExpression(get_variables(vmap, ins.AA), ret, 'O')


# move-exception vAA ( 8b )
def moveexception(ins, vmap):
    logger.debug('MoveException : %s', ins.get_output())
    return RefExpression(get_variables(vmap, ins.AA))


# return-void
def returnvoid(ins, vmap):
    logger.debug('ReturnVoid')
    return ReturnInstruction(None)


# return vAA ( 8b )
def return_reg(ins, vmap):
    logger.debug('Return : %s', ins.get_output())
    return ReturnInstruction(get_variables(vmap, ins.AA))


# return-wide vAA ( 8b )
def returnwide(ins, vmap):
    logger.debug('ReturnWide : %s', ins.get_output())
    return ReturnInstruction(get_variables(vmap, ins.AA))


# return-object vAA ( 8b )
def returnobject(ins, vmap):
    logger.debug('ReturnObject : %s', ins.get_output())
    return ReturnInstruction(get_variables(vmap, ins.AA))


# const/4 vA, #+B ( 4b, 4b )
def const4(ins, vmap):
    logger.debug('Const4 : %s', ins.get_output())
    cst = Constant(ins.B, 'I')
    return assign_const(ins.A, cst, vmap)


# const/16 vAA, #+BBBB ( 8b, 16b )
def const16(ins, vmap):
    logger.debug('Const16 : %s', ins.get_output())
    cst = Constant(ins.BBBB, 'I')
    return assign_const(ins.AA, cst, vmap)


# const vAA, #+BBBBBBBB ( 8b, 32b )
def const(ins, vmap):
    logger.debug('Const : %s', ins.get_output())
    value = unpack("=f", pack("=i", ins.BBBBBBBB))[0]
    cst = Constant(value, 'F', ins.BBBBBBBB)
    return assign_const(ins.AA, cst, vmap)


# const/high16 vAA, #+BBBB0000 ( 8b, 16b )
def consthigh16(ins, vmap):
    logger.debug('ConstHigh16 : %s', ins.get_output())
    value = unpack('=f', '\x00\x00' + pack('=h', ins.BBBB))[0]
    cst = Constant(value, 'F', ins.BBBB)
    return assign_const(ins.AA, cst, vmap)


# const-wide/16 vAA, #+BBBB ( 8b, 16b )
def constwide16(ins, vmap):
    logger.debug('ConstWide16 : %s', ins.get_output())
    value = unpack('=d', pack('=d', ins.BBBB))[0]
    cst = Constant(value, 'J', ins.BBBB)
    return assign_const(ins.AA, cst, vmap)


# const-wide/32 vAA, #+BBBBBBBB ( 8b, 32b )
def constwide32(ins, vmap):
    logger.debug('ConstWide32 : %s', ins.get_output())
    value = unpack('=d', pack('=d', ins.BBBBBBBB))[0]
    cst = Constant(value, 'J', ins.BBBBBBBB)
    return assign_const(ins.AA, cst, vmap)


# const-wide vAA, #+BBBBBBBBBBBBBBBB ( 8b, 64b )
def constwide(ins, vmap):
    logger.debug('ConstWide : %s', ins.get_output())
    value = unpack('=d', pack('=q', ins.BBBBBBBBBBBBBBBB))[0]
    cst = Constant(value, 'D', ins.BBBBBBBBBBBBBBBB)
    return assign_const(ins.AA, cst, vmap)


# const-wide/high16 vAA, #+BBBB000000000000 ( 8b, 16b )
def constwidehigh16(ins, vmap):
    logger.debug('ConstWideHigh16 : %s', ins.get_output())
    value = unpack('=d',
                    '\x00\x00\x00\x00\x00\x00' + pack('=h', ins.BBBB))[0]
    cst = Constant(value, 'D', ins.BBBB)
    return assign_const(ins.AA, cst, vmap)


# const-string vAA ( 8b )
def conststring(ins, vmap):
    logger.debug('ConstString : %s', ins.get_output())
    cst = Constant(ins.get_raw_string(), 'STR')
    return assign_const(ins.AA, cst, vmap)


# const-string/jumbo vAA ( 8b )
def conststringjumbo(ins, vmap):
    logger.debug('ConstStringJumbo %s', ins.get_output())
    cst = Constant(ins.get_raw_string(), 'STR')
    return assign_const(ins.AA, cst, vmap)


# const-class vAA, type@BBBB ( 8b )
def constclass(ins, vmap):
    logger.debug('ConstClass : %s', ins.get_output())
    cst = Constant(util.get_type(ins.get_string()), 'class')
    return assign_const(ins.AA, cst, vmap)


# monitor-enter vAA ( 8b )
def monitorenter(ins, vmap):
    logger.debug('MonitorEnter : %s', ins.get_output())
    return MonitorEnterExpression(get_variables(vmap, ins.AA))


# monitor-exit vAA ( 8b )
def monitorexit(ins, vmap):
    logger.debug('MonitorExit : %s', ins.get_output())
    a = get_variables(vmap, ins.AA)
    return MonitorExitExpression(a)


# check-cast vAA ( 8b )
def checkcast(ins, vmap):
    logger.debug('CheckCast: %s', ins.get_output())
    cast_type = util.get_type(ins.get_translated_kind())
    return CheckCastExpression(get_variables(vmap, ins.AA), cast_type)


# instance-of vA, vB ( 4b, 4b )
def instanceof(ins, vmap):
    logger.debug('InstanceOf : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    reg_c = BaseClass(util.get_type(ins.get_translated_kind()))
    exp = BinaryExpression('instanceof', reg_b, reg_c, None)
    return AssignExpression(reg_a, exp)


# array-length vA, vB ( 4b, 4b )
def arraylength(ins, vmap):
    logger.debug('ArrayLength: %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.A, ins.B)
    return AssignExpression(reg_a, ArrayLengthExpression(reg_b))


# new-instance vAA ( 8b )
def newinstance(ins, vmap):
    logger.debug('NewInstance : %s', ins.get_output())
    reg_a = get_variables(vmap, ins.AA)
    ins_type = ins.cm.get_type(ins.BBBB)
    return AssignExpression(reg_a, NewInstance(ins_type))


# new-array vA, vB ( 8b, size )
def newarray(ins, vmap):
    logger.debug('NewArray : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = NewArrayExpression(b, ins.cm.get_type(ins.CCCC))
    return AssignExpression(a, exp)


# filled-new-array {vD, vE, vF, vG, vA} ( 4b each )
def fillednewarray(ins, vmap, ret):
    logger.debug('FilledNewArray : %s', ins.get_output())
    a, b, c, d, e, f, g = get_variables(vmap, ins.A, ins.BBBB, ins.C, ins.D,
                                                    ins.E, ins.F, ins.G)
    exp = FilledArrayExpression(a, c, [d, e, f, g, a])
    return AssignExpression(ret, exp)


# filled-new-array/range {vCCCC..vNNNN} ( 16b )
def fillednewarrayrange(ins, vmap, ret):
    logger.debug('FilledNewArrayRange : %s', ins.get_output())
    a, b, c, n = get_variables(vmap, ins.AA, ins.BBBB, ins.CCCC, ins.NNNN)
    exp = FilledArrayExpression(a, b, [c, n])
    return AssignExpression(ret, exp)


# fill-array-data vAA, +BBBBBBBB ( 8b, 32b )
def fillarraydata(ins, vmap, value):
    logger.debug('FillArrayData : %s', ins.get_output())
    return FillArrayExpression(get_variables(vmap, ins.AA), value)


# fill-array-data-payload vAA, +BBBBBBBB ( 8b, 32b )
def fillarraydatapayload(ins, vmap):
    logger.debug('FillArrayDataPayload : %s', ins.get_output())
    return FillArrayExpression(None)


# throw vAA ( 8b )
def throw(ins, vmap):
    logger.debug('Throw : %s', ins.get_output())
    return ThrowExpression(get_variables(vmap, ins.AA))


# goto +AA ( 8b )
def goto(ins, vmap):
    return NopExpression()


# goto/16 +AAAA ( 16b )
def goto16(ins, vmap):
    return NopExpression()


# goto/32 +AAAAAAAA ( 32b )
def goto32(ins, vmap):
    return NopExpression()


# packed-switch vAA, +BBBBBBBB ( reg to test, 32b )
def packedswitch(ins, vmap):
    logger.debug('PackedSwitch : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AA, ins.BBBBBBBB)
    return SwitchExpression(reg_a, reg_b)


# sparse-switch vAA, +BBBBBBBB ( reg to test, 32b )
def sparseswitch(ins, vmap):
    logger.debug('SparseSwitch : %s', ins.get_output())
    reg_a, reg_b = get_variables(vmap, ins.AA, ins.BBBBBBBB)
    return SwitchExpression(reg_a, reg_b)


# cmpl-float vAA, vBB, vCC ( 8b, 8b, 8b )
def cmplfloat(ins, vmap):
    logger.debug('CmpglFloat : %s', ins.get_output())
    return assign_cmp(ins.AA, ins.BB, ins.CC, 'F', vmap)


# cmpg-float vAA, vBB, vCC ( 8b, 8b, 8b )
def cmpgfloat(ins, vmap):
    logger.debug('CmpgFloat : %s', ins.get_output())
    return assign_cmp(ins.AA, ins.BB, ins.CC, 'F', vmap)


# cmpl-double vAA, vBB, vCC ( 8b, 8b, 8b )
def cmpldouble(ins, vmap):
    logger.debug('CmplDouble : %s', ins.get_output())
    return assign_cmp(ins.AA, ins.BB, ins.CC, 'D', vmap)


# cmpg-double vAA, vBB, vCC ( 8b, 8b, 8b )
def cmpgdouble(ins, vmap):
    logger.debug('CmpgDouble : %s', ins.get_output())
    return assign_cmp(ins.AA, ins.BB, ins.CC, 'D', vmap)


# cmp-long vAA, vBB, vCC ( 8b, 8b, 8b )
def cmplong(ins, vmap):
    logger.debug('CmpLong : %s', ins.get_output())
    return assign_cmp(ins.AA, ins.BB, ins.CC, 'J', vmap)


# if-eq vA, vB, +CCCC ( 4b, 4b, 16b )
def ifeq(ins, vmap):
    logger.debug('IfEq : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.EQUAL, a, b)


# if-ne vA, vB, +CCCC ( 4b, 4b, 16b )
def ifne(ins, vmap):
    logger.debug('IfNe : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.NEQUAL, a, b)


# if-lt vA, vB, +CCCC ( 4b, 4b, 16b )
def iflt(ins, vmap):
    logger.debug('IfLt : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.LOWER, a, b)


# if-ge vA, vB, +CCCC ( 4b, 4b, 16b )
def ifge(ins, vmap):
    logger.debug('IfGe : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.GEQUAL, a, b)


# if-gt vA, vB, +CCCC ( 4b, 4b, 16b )
def ifgt(ins, vmap):
    logger.debug('IfGt : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.GREATER, a, b)


# if-le vA, vB, +CCCC ( 4b, 4b, 16b )
def ifle(ins, vmap):
    logger.debug('IfLe : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    return ConditionalExpression(Op.LEQUAL, a, b)


# if-eqz vAA, +BBBB ( 8b, 16b )
def ifeqz(ins, vmap):
    logger.debug('IfEqz : %s', ins.get_output())
    return ConditionalZExpression(Op.EQUAL, get_variables(vmap, ins.AA))


# if-nez vAA, +BBBB ( 8b, 16b )
def ifnez(ins, vmap):
    logger.debug('IfNez : %s', ins.get_output())
    return ConditionalZExpression(Op.NEQUAL, get_variables(vmap, ins.AA))


# if-ltz vAA, +BBBB ( 8b, 16b )
def ifltz(ins, vmap):
    logger.debug('IfLtz : %s', ins.get_output())
    return ConditionalZExpression(Op.LOWER, get_variables(vmap, ins.AA))


# if-gez vAA, +BBBB ( 8b, 16b )
def ifgez(ins, vmap):
    logger.debug('IfGez : %s', ins.get_output())
    return ConditionalZExpression(Op.GEQUAL, get_variables(vmap, ins.AA))


# if-gtz vAA, +BBBB ( 8b, 16b )
def ifgtz(ins, vmap):
    logger.debug('IfGtz : %s', ins.get_output())
    return ConditionalZExpression(Op.GREATER, get_variables(vmap, ins.AA))


# if-lez vAA, +BBBB (8b, 16b )
def iflez(ins, vmap):
    logger.debug('IfLez : %s', ins.get_output())
    return ConditionalZExpression(Op.LEQUAL, get_variables(vmap, ins.AA))


#TODO: check type for all aget
# aget vAA, vBB, vCC ( 8b, 8b, 8b )
def aget(ins, vmap):
    logger.debug('AGet : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, None, vmap)


# aget-wide vAA, vBB, vCC ( 8b, 8b, 8b )
def agetwide(ins, vmap):
    logger.debug('AGetWide : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'W', vmap)


# aget-object vAA, vBB, vCC ( 8b, 8b, 8b )
def agetobject(ins, vmap):
    logger.debug('AGetObject : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'O', vmap)


# aget-boolean vAA, vBB, vCC ( 8b, 8b, 8b )
def agetboolean(ins, vmap):
    logger.debug('AGetBoolean : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'Z', vmap)


# aget-byte vAA, vBB, vCC ( 8b, 8b, 8b )
def agetbyte(ins, vmap):
    logger.debug('AGetByte : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'B', vmap)


# aget-char vAA, vBB, vCC ( 8b, 8b, 8b )
def agetchar(ins, vmap):
    logger.debug('AGetChar : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'C', vmap)


# aget-short vAA, vBB, vCC ( 8b, 8b, 8b )
def agetshort(ins, vmap):
    logger.debug('AGetShort : %s', ins.get_output())
    return load_array_exp(ins.AA, ins.BB, ins.CC, 'S', vmap)


# aput vAA, vBB, vCC
def aput(ins, vmap):
    logger.debug('APut : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, None, vmap)


# aput-wide vAA, vBB, vCC ( 8b, 8b, 8b )
def aputwide(ins, vmap):
    logger.debug('APutWide : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'W', vmap)


# aput-object vAA, vBB, vCC ( 8b, 8b, 8b )
def aputobject(ins, vmap):
    logger.debug('APutObject : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'O', vmap)


# aput-boolean vAA, vBB, vCC ( 8b, 8b, 8b )
def aputboolean(ins, vmap):
    logger.debug('APutBoolean : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'Z', vmap)


# aput-byte vAA, vBB, vCC ( 8b, 8b, 8b )
def aputbyte(ins, vmap):
    logger.debug('APutByte : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'B', vmap)


# aput-char vAA, vBB, vCC ( 8b, 8b, 8b )
def aputchar(ins, vmap):
    logger.debug('APutChar : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'C', vmap)


# aput-short vAA, vBB, vCC ( 8b, 8b, 8b )
def aputshort(ins, vmap):
    logger.debug('APutShort : %s', ins.get_output())
    return store_array_inst(ins.AA, ins.BB, ins.CC, 'S', vmap)


# iget vA, vB ( 4b, 4b )
def iget(ins, vmap):
    logger.debug('IGet : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-wide vA, vB ( 4b, 4b )
def igetwide(ins, vmap):
    logger.debug('IGetWide : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-object vA, vB ( 4b, 4b )
def igetobject(ins, vmap):
    logger.debug('IGetObject : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-boolean vA, vB ( 4b, 4b )
def igetboolean(ins, vmap):
    logger.debug('IGetBoolean : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-byte vA, vB ( 4b, 4b )
def igetbyte(ins, vmap):
    logger.debug('IGetByte : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-char vA, vB ( 4b, 4b )
def igetchar(ins, vmap):
    logger.debug('IGetChar : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iget-short vA, vB ( 4b, 4b )
def igetshort(ins, vmap):
    logger.debug('IGetShort : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = InstanceExpression(b, klass, ftype, name)
    return AssignExpression(a, exp)


# iput vA, vB ( 4b, 4b )
def iput(ins, vmap):
    logger.debug('IPut %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-wide vA, vB ( 4b, 4b )
def iputwide(ins, vmap):
    logger.debug('IPutWide %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-object vA, vB ( 4b, 4b )
def iputobject(ins, vmap):
    logger.debug('IPutObject %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-boolean vA, vB ( 4b, 4b )
def iputboolean(ins, vmap):
    logger.debug('IPutBoolean %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-byte vA, vB ( 4b, 4b )
def iputbyte(ins, vmap):
    logger.debug('IPutByte %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-char vA, vB ( 4b, 4b )
def iputchar(ins, vmap):
    logger.debug('IPutChar %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# iput-short vA, vB ( 4b, 4b )
def iputshort(ins, vmap):
    logger.debug('IPutShort %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.CCCC)
    klass = util.get_type(klass)
    a, b = get_variables(vmap, ins.A, ins.B)
    return InstanceInstruction(a, b, klass, atype, name)


# sget vAA ( 8b )
def sget(ins, vmap):
    logger.debug('SGet : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-wide vAA ( 8b )
def sgetwide(ins, vmap):
    logger.debug('SGetWide : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-object vAA ( 8b )
def sgetobject(ins, vmap):
    logger.debug('SGetObject : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-boolean vAA ( 8b )
def sgetboolean(ins, vmap):
    logger.debug('SGetBoolean : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-byte vAA ( 8b )
def sgetbyte(ins, vmap):
    logger.debug('SGetByte : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-char vAA ( 8b )
def sgetchar(ins, vmap):
    logger.debug('SGetChar : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sget-short vAA ( 8b )
def sgetshort(ins, vmap):
    logger.debug('SGetShort : %s', ins.get_output())
    klass, atype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    exp = StaticExpression(klass, atype, name)
    a = get_variables(vmap, ins.AA)
    return AssignExpression(a, exp)


# sput vAA ( 8b )
def sput(ins, vmap):
    logger.debug('SPut : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-wide vAA ( 8b )
def sputwide(ins, vmap):
    logger.debug('SPutWide : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-object vAA ( 8b )
def sputobject(ins, vmap):
    logger.debug('SPutObject : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-boolean vAA ( 8b )
def sputboolean(ins, vmap):
    logger.debug('SPutBoolean : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-wide vAA ( 8b )
def sputbyte(ins, vmap):
    logger.debug('SPutByte : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-char vAA ( 8b )
def sputchar(ins, vmap):
    logger.debug('SPutChar : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


# sput-short vAA ( 8b )
def sputshort(ins, vmap):
    logger.debug('SPutShort : %s', ins.get_output())
    klass, ftype, name = ins.cm.get_field(ins.BBBB)
    klass = util.get_type(klass)
    a = get_variables(vmap, ins.AA)
    return StaticInstruction(a, klass, ftype, name)


def get_args(vmap, param_type, largs):
    num_param = 0
    args = []
    for type_ in param_type:
        param = largs[num_param]
        args.append(param)
        num_param += util.get_type_size(type_)

    if len(param_type) == 1:
        return [get_variables(vmap, *args)]
    return get_variables(vmap, *args)


# invoke-virtual {vD, vE, vF, vG, vA} ( 4b each )
def invokevirtual(ins, vmap, ret):
    logger.debug('InvokeVirtual : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = [ins.D, ins.E, ins.F, ins.G]
    args = get_args(vmap, param_type, largs)
    c = get_variables(vmap, ins.C)
    exp = InvokeInstruction(cls_name, name, c, ret_type,
                            param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-super {vD, vE, vF, vG, vA} ( 4b each )
def invokesuper(ins, vmap, ret):
    logger.debug('InvokeSuper : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    nbargs = ins.A - 1
    largs = [ins.D, ins.E, ins.F, ins.G]
    args = get_variables(vmap, *largs)[:nbargs]
    superclass = BaseClass('super')
    exp = InvokeInstruction(cls_name, name, superclass, ret_type,
                            param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-direct {vD, vE, vF, vG, vA} ( 4b each )
def invokedirect(ins, vmap, ret):
    logger.debug('InvokeDirect : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = [ins.D, ins.E, ins.F, ins.G]
    args = get_args(vmap, param_type, largs)
    c = get_variables(vmap, ins.C)
    ret.set_to(c)
    exp = InvokeDirectInstruction(cls_name, name, c, ret_type,
                            param_type, args)
    return AssignExpression(c, exp)


# invoke-static {vD, vE, vF, vG, vA} ( 4b each )
def invokestatic(ins, vmap, ret):
    logger.debug('InvokeStatic : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    #nbargs = len(param_type)
    largs = [ins.C, ins.D, ins.E, ins.F, ins.G]
    #args = get_variables(vmap, *largs)[:nbargs]
    args = get_args(vmap, param_type, largs)
    base = BaseClass(cls_name)
    exp = InvokeStaticInstruction(cls_name, name, base, ret_type,
                                    param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-interface {vD, vE, vF, vG, vA} ( 4b each )
def invokeinterface(ins, vmap, ret):
    logger.debug('InvokeInterface : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    nbargs = ins.A - 1
    largs = [ins.D, ins.E, ins.F, ins.G]
    args = get_variables(vmap, *largs)[:nbargs]
    c = get_variables(vmap, ins.C)
    exp = InvokeInstruction(cls_name, name, c, ret_type,
                            param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-virtual/range {vCCCC..vNNNN} ( 16b each )
def invokevirtualrange(ins, vmap, ret):
    logger.debug('InvokeVirtualRange : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = range(ins.CCCC, ins.NNNN + 1)
    args = get_variables(vmap, *largs)
    if len(largs) == 1:
        args = [args]
    exp = InvokeRangeInstruction(cls_name, name, ret_type,
                                 param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-super/range {vCCCC..vNNNN} ( 16b each )
def invokesuperrange(ins, vmap, ret):
    logger.debug('InvokeSuperRange : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = range(ins.CCCC, ins.NNNN + 1)
    args = get_variables(vmap, *largs)
    if len(largs) == 1:
        args = [args]
    exp = InvokeRangeInstruction(cls_name, name, ret_type,
                                param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-direct/range {vCCCC..vNNNN} ( 16b each )
def invokedirectrange(ins, vmap, ret):
    logger.debug('InvokeDirectRange : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = range(ins.CCCC, ins.NNNN + 1)
    args = get_variables(vmap, *largs)
    if len(largs) == 1:
        args = [args]
    c = get_variables(vmap, ins.CCCC)
    ret.set_to(c)
    exp = InvokeRangeInstruction(cls_name, name, ret_type,
                                param_type, args)
    return AssignExpression(c, exp)


# invoke-static/range {vCCCC..vNNNN} ( 16b each )
def invokestaticrange(ins, vmap, ret):
    logger.debug('InvokeStaticRange : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = range(ins.CCCC, ins.NNNN + 1)
    args = get_variables(vmap, *largs)
    if len(largs) == 1:
        args = [args]
    base = BaseClass(cls_name)
    exp = InvokeStaticInstruction(cls_name, name, base, ret_type,
                                param_type, args)
    return AssignExpression(ret.new(), exp)


# invoke-interface/range {vCCCC..vNNNN} ( 16b each )
def invokeinterfacerange(ins, vmap, ret):
    logger.debug('InvokeInterfaceRange : %s', ins.get_output())
    method = ins.cm.get_method_ref(ins.BBBB)
    cls_name = util.get_type(method.get_class_name())
    name = method.get_name()
    param_type, ret_type = method.get_proto()
    ret_type = util.get_type(ret_type)
    param_type = util.get_params_type(param_type)
    largs = range(ins.CCCC, ins.NNNN + 1)
    args = get_variables(vmap, *largs)
    if len(largs) == 1:
        args = [args]
    exp = InvokeRangeInstruction(cls_name, name, ret_type,
                                param_type, args)
    return AssignExpression(ret.new(), exp)


# neg-int vA, vB ( 4b, 4b )
def negint(ins, vmap):
    logger.debug('NegInt : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NEG, b)
    exp.type = 'I'
    return AssignExpression(a, exp)


# not-int vA, vB ( 4b, 4b )
def notint(ins, vmap):
    logger.debug('NotInt : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NOT, b)
    exp.type = 'I'
    return AssignExpression(a, exp)


# neg-long vA, vB ( 4b, 4b )
def neglong(ins, vmap):
    logger.debug('NegLong : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NEG, b)
    exp.type = 'J'
    return AssignExpression(a, exp)


# not-long vA, vB ( 4b, 4b )
def notlong(ins, vmap):
    logger.debug('NotLong : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NOT, b)
    exp.type = 'J'
    return AssignExpression(a, exp)


# neg-float vA, vB ( 4b, 4b )
def negfloat(ins, vmap):
    logger.debug('NegFloat : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NEG, b)
    exp.type = 'F'
    return AssignExpression(a, exp)


# neg-double vA, vB ( 4b, 4b )
def negdouble(ins, vmap):
    logger.debug('NegDouble : %s', ins.get_output())
    a, b = get_variables(vmap, ins.A, ins.B)
    exp = UnaryExpression(Op.NEG, b)
    exp.type = 'D'
    return AssignExpression(a, exp)


# int-to-long vA, vB ( 4b, 4b )
def inttolong(ins, vmap):
    logger.debug('IntToLong : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(long)', 'J', vmap)


# int-to-float vA, vB ( 4b, 4b )
def inttofloat(ins, vmap):
    logger.debug('IntToFloat : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(float)', 'F', vmap)


# int-to-double vA, vB ( 4b, 4b )
def inttodouble(ins, vmap):
    logger.debug('IntToDouble : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(double)', 'D', vmap)


# long-to-int vA, vB ( 4b, 4b )
def longtoint(ins, vmap):
    logger.debug('LongToInt : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(int)', 'I', vmap)


# long-to-float vA, vB ( 4b, 4b )
def longtofloat(ins, vmap):
    logger.debug('LongToFloat : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(float)', 'F', vmap)


# long-to-double vA, vB ( 4b, 4b )
def longtodouble(ins, vmap):
    logger.debug('LongToDouble : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(double)', 'D', vmap)


# float-to-int vA, vB ( 4b, 4b )
def floattoint(ins, vmap):
    logger.debug('FloatToInt : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(int)', 'I', vmap)


# float-to-long vA, vB ( 4b, 4b )
def floattolong(ins, vmap):
    logger.debug('FloatToLong : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(long)', 'J', vmap)


# float-to-double vA, vB ( 4b, 4b )
def floattodouble(ins, vmap):
    logger.debug('FloatToDouble : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(double)', 'D', vmap)


# double-to-int vA, vB ( 4b, 4b )
def doubletoint(ins, vmap):
    logger.debug('DoubleToInt : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(int)', 'I', vmap)


# double-to-long vA, vB ( 4b, 4b )
def doubletolong(ins, vmap):
    logger.debug('DoubleToLong : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(long)', 'J', vmap)


# double-to-float vA, vB ( 4b, 4b )
def doubletofloat(ins, vmap):
    logger.debug('DoubleToFloat : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(float)', 'F', vmap)


# int-to-byte vA, vB ( 4b, 4b )
def inttobyte(ins, vmap):
    logger.debug('IntToByte : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(byte)', 'B', vmap)


# int-to-char vA, vB ( 4b, 4b )
def inttochar(ins, vmap):
    logger.debug('IntToChar : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(char)', 'C', vmap)


# int-to-short vA, vB ( 4b, 4b )
def inttoshort(ins, vmap):
    logger.debug('IntToShort : %s', ins.get_output())
    return assign_cast_exp(ins.A, ins.B, '(short)', 'S', vmap)


# add-int vAA, vBB, vCC ( 8b, 8b, 8b )
def addint(ins, vmap):
    logger.debug('AddInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.ADD, 'I', vmap)


# sub-int vAA, vBB, vCC ( 8b, 8b, 8b )
def subint(ins, vmap):
    logger.debug('SubInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.SUB, 'I', vmap)


# mul-int vAA, vBB, vCC ( 8b, 8b, 8b )
def mulint(ins, vmap):
    logger.debug('MulInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MUL, 'I', vmap)


# div-int vAA, vBB, vCC ( 8b, 8b, 8b )
def divint(ins, vmap):
    logger.debug('DivInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.DIV, 'I', vmap)


# rem-int vAA, vBB, vCC ( 8b, 8b, 8b )
def remint(ins, vmap):
    logger.debug('RemInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MOD, 'I', vmap)


# and-int vAA, vBB, vCC ( 8b, 8b, 8b )
def andint(ins, vmap):
    logger.debug('AndInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.AND, 'I', vmap)


# or-int vAA, vBB, vCC ( 8b, 8b, 8b )
def orint(ins, vmap):
    logger.debug('OrInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.OR, 'I', vmap)


# xor-int vAA, vBB, vCC ( 8b, 8b, 8b )
def xorint(ins, vmap):
    logger.debug('XorInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.XOR, 'I', vmap)


# shl-int vAA, vBB, vCC ( 8b, 8b, 8b )
def shlint(ins, vmap):
    logger.debug('ShlInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.INTSHL, 'I', vmap)


# shr-int vAA, vBB, vCC ( 8b, 8b, 8b )
def shrint(ins, vmap):
    logger.debug('ShrInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.INTSHR, 'I', vmap)


# ushr-int vAA, vBB, vCC ( 8b, 8b, 8b )
def ushrint(ins, vmap):
    logger.debug('UShrInt : %s', ins.get_output())
    return assign_binary_exp(ins, Op.INTSHR, 'I', vmap)


# add-long vAA, vBB, vCC ( 8b, 8b, 8b )
def addlong(ins, vmap):
    logger.debug('AddLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.ADD, 'J', vmap)


# sub-long vAA, vBB, vCC ( 8b, 8b, 8b )
def sublong(ins, vmap):
    logger.debug('SubLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.SUB, 'J', vmap)


# mul-long vAA, vBB, vCC ( 8b, 8b, 8b )
def mullong(ins, vmap):
    logger.debug('MulLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MUL, 'J', vmap)


# div-long vAA, vBB, vCC ( 8b, 8b, 8b )
def divlong(ins, vmap):
    logger.debug('DivLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.DIV, 'J', vmap)


# rem-long vAA, vBB, vCC ( 8b, 8b, 8b )
def remlong(ins, vmap):
    logger.debug('RemLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MOD, 'J', vmap)


# and-long vAA, vBB, vCC ( 8b, 8b, 8b )
def andlong(ins, vmap):
    logger.debug('AndLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.AND, 'J', vmap)


# or-long vAA, vBB, vCC ( 8b, 8b, 8b )
def orlong(ins, vmap):
    logger.debug('OrLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.OR, 'J', vmap)


# xor-long vAA, vBB, vCC ( 8b, 8b, 8b )
def xorlong(ins, vmap):
    logger.debug('XorLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.XOR, 'J', vmap)


# shl-long vAA, vBB, vCC ( 8b, 8b, 8b )
def shllong(ins, vmap):
    logger.debug('ShlLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.LONGSHL, 'J', vmap)


# shr-long vAA, vBB, vCC ( 8b, 8b, 8b )
def shrlong(ins, vmap):
    logger.debug('ShrLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.LONGSHR, 'J', vmap)


# ushr-long vAA, vBB, vCC ( 8b, 8b, 8b )
def ushrlong(ins, vmap):
    logger.debug('UShrLong : %s', ins.get_output())
    return assign_binary_exp(ins, Op.LONGSHR, 'J', vmap)


# add-float vAA, vBB, vCC ( 8b, 8b, 8b )
def addfloat(ins, vmap):
    logger.debug('AddFloat : %s', ins.get_output())
    return assign_binary_exp(ins, Op.ADD, 'F', vmap)


# sub-float vAA, vBB, vCC ( 8b, 8b, 8b )
def subfloat(ins, vmap):
    logger.debug('SubFloat : %s', ins.get_output())
    return assign_binary_exp(ins, Op.SUB, 'F', vmap)


# mul-float vAA, vBB, vCC ( 8b, 8b, 8b )
def mulfloat(ins, vmap):
    logger.debug('MulFloat : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MUL, 'F', vmap)


# div-float vAA, vBB, vCC ( 8b, 8b, 8b )
def divfloat(ins, vmap):
    logger.debug('DivFloat : %s', ins.get_output())
    return assign_binary_exp(ins, Op.DIV, 'F', vmap)


# rem-float vAA, vBB, vCC ( 8b, 8b, 8b )
def remfloat(ins, vmap):
    logger.debug('RemFloat : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MOD, 'F', vmap)


# add-double vAA, vBB, vCC ( 8b, 8b, 8b )
def adddouble(ins, vmap):
    logger.debug('AddDouble : %s', ins.get_output())
    return assign_binary_exp(ins, Op.ADD, 'D', vmap)


# sub-double vAA, vBB, vCC ( 8b, 8b, 8b )
def subdouble(ins, vmap):
    logger.debug('SubDouble : %s', ins.get_output())
    return assign_binary_exp(ins, Op.SUB, 'D', vmap)


# mul-double vAA, vBB, vCC ( 8b, 8b, 8b )
def muldouble(ins, vmap):
    logger.debug('MulDouble : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MUL, 'D', vmap)


# div-double vAA, vBB, vCC ( 8b, 8b, 8b )
def divdouble(ins, vmap):
    logger.debug('DivDouble : %s', ins.get_output())
    return assign_binary_exp(ins, Op.DIV, 'D', vmap)


# rem-double vAA, vBB, vCC ( 8b, 8b, 8b )
def remdouble(ins, vmap):
    logger.debug('RemDouble : %s', ins.get_output())
    return assign_binary_exp(ins, Op.MOD, 'D', vmap)


# add-int/2addr vA, vB ( 4b, 4b )
def addint2addr(ins, vmap):
    logger.debug('AddInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.ADD, 'I', vmap)


# sub-int/2addr vA, vB ( 4b, 4b )
def subint2addr(ins, vmap):
    logger.debug('SubInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.SUB, 'I', vmap)


# mul-int/2addr vA, vB ( 4b, 4b )
def mulint2addr(ins, vmap):
    logger.debug('MulInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MUL, 'I', vmap)


# div-int/2addr vA, vB ( 4b, 4b )
def divint2addr(ins, vmap):
    logger.debug('DivInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.DIV, 'I', vmap)


# rem-int/2addr vA, vB ( 4b, 4b )
def remint2addr(ins, vmap):
    logger.debug('RemInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MOD, 'I', vmap)


# and-int/2addr vA, vB ( 4b, 4b )
def andint2addr(ins, vmap):
    logger.debug('AndInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.AND, 'I', vmap)


# or-int/2addr vA, vB ( 4b, 4b )
def orint2addr(ins, vmap):
    logger.debug('OrInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.OR, 'I', vmap)


# xor-int/2addr vA, vB ( 4b, 4b )
def xorint2addr(ins, vmap):
    logger.debug('XorInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.XOR, 'I', vmap)


# shl-int/2addr vA, vB ( 4b, 4b )
def shlint2addr(ins, vmap):
    logger.debug('ShlInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.INTSHL, 'I', vmap)


# shr-int/2addr vA, vB ( 4b, 4b )
def shrint2addr(ins, vmap):
    logger.debug('ShrInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.INTSHR, 'I', vmap)


# ushr-int/2addr vA, vB ( 4b, 4b )
def ushrint2addr(ins, vmap):
    logger.debug('UShrInt2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.INTSHR, 'I', vmap)


# add-long/2addr vA, vB ( 4b, 4b )
def addlong2addr(ins, vmap):
    logger.debug('AddLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.ADD, 'J', vmap)


# sub-long/2addr vA, vB ( 4b, 4b )
def sublong2addr(ins, vmap):
    logger.debug('SubLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.SUB, 'J', vmap)


# mul-long/2addr vA, vB ( 4b, 4b )
def mullong2addr(ins, vmap):
    logger.debug('MulLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MUL, 'J', vmap)


# div-long/2addr vA, vB ( 4b, 4b )
def divlong2addr(ins, vmap):
    logger.debug('DivLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.DIV, 'J', vmap)


# rem-long/2addr vA, vB ( 4b, 4b )
def remlong2addr(ins, vmap):
    logger.debug('RemLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MUL, 'J', vmap)


# and-long/2addr vA, vB ( 4b, 4b )
def andlong2addr(ins, vmap):
    logger.debug('AndLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.AND, 'J', vmap)


# or-long/2addr vA, vB ( 4b, 4b )
def orlong2addr(ins, vmap):
    logger.debug('OrLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.OR, 'J', vmap)


# xor-long/2addr vA, vB ( 4b, 4b )
def xorlong2addr(ins, vmap):
    logger.debug('XorLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.XOR, 'J', vmap)


# shl-long/2addr vA, vB ( 4b, 4b )
def shllong2addr(ins, vmap):
    logger.debug('ShlLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.LONGSHL, 'J', vmap)


# shr-long/2addr vA, vB ( 4b, 4b )
def shrlong2addr(ins, vmap):
    logger.debug('ShrLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.LONGSHR, 'J', vmap)


# ushr-long/2addr vA, vB ( 4b, 4b )
def ushrlong2addr(ins, vmap):
    logger.debug('UShrLong2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.LONGSHR, 'J', vmap)


# add-float/2addr vA, vB ( 4b, 4b )
def addfloat2addr(ins, vmap):
    logger.debug('AddFloat2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.ADD, 'F', vmap)


# sub-float/2addr vA, vB ( 4b, 4b )
def subfloat2addr(ins, vmap):
    logger.debug('SubFloat2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.SUB, 'F', vmap)


# mul-float/2addr vA, vB ( 4b, 4b )
def mulfloat2addr(ins, vmap):
    logger.debug('MulFloat2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MUL, 'F', vmap)


# div-float/2addr vA, vB ( 4b, 4b )
def divfloat2addr(ins, vmap):
    logger.debug('DivFloat2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.DIV, 'F', vmap)


# rem-float/2addr vA, vB ( 4b, 4b )
def remfloat2addr(ins, vmap):
    logger.debug('RemFloat2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MOD, 'F', vmap)


# add-double/2addr vA, vB ( 4b, 4b )
def adddouble2addr(ins, vmap):
    logger.debug('AddDouble2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.ADD, 'D', vmap)


# sub-double/2addr vA, vB ( 4b, 4b )
def subdouble2addr(ins, vmap):
    logger.debug('subDouble2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.SUB, 'D', vmap)


# mul-double/2addr vA, vB ( 4b, 4b )
def muldouble2addr(ins, vmap):
    logger.debug('MulDouble2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MUL, 'D', vmap)


# div-double/2addr vA, vB ( 4b, 4b )
def divdouble2addr(ins, vmap):
    logger.debug('DivDouble2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.DIV, 'D', vmap)


# rem-double/2addr vA, vB ( 4b, 4b )
def remdouble2addr(ins, vmap):
    logger.debug('RemDouble2Addr : %s', ins.get_output())
    return assign_binary_2addr_exp(ins, Op.MOD, 'D', vmap)


# add-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def addintlit16(ins, vmap):
    logger.debug('AddIntLit16 : %s', ins.get_output())
    return assign_lit(Op.ADD, ins.CCCC, ins.A, ins.B, vmap)


# rsub-int vA, vB, #+CCCC ( 4b, 4b, 16b )
def rsubint(ins, vmap):
    logger.debug('RSubInt : %s', ins.get_output())
    return assign_lit(Op.SUB, ins.CCCC, ins.A, ins.B, vmap)


# mul-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def mulintlit16(ins, vmap):
    logger.debug('MulIntLit16 : %s', ins.get_output())
    return assign_lit(Op.MUL, ins.CCCC, ins.A, ins.B, vmap)


# div-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def divintlit16(ins, vmap):
    logger.debug('DivIntLit16 : %s', ins.get_output())
    return assign_lit(Op.DIV, ins.CCCC, ins.A, ins.B, vmap)


# rem-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def remintlit16(ins, vmap):
    logger.debug('RemIntLit16 : %s', ins.get_output())
    return assign_lit(Op.MOD, ins.CCCC, ins.A, ins.B, vmap)


# and-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def andintlit16(ins, vmap):
    logger.debug('AndIntLit16 : %s', ins.get_output())
    return assign_lit(Op.AND, ins.CCCC, ins.A, ins.B, vmap)


# or-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def orintlit16(ins, vmap):
    logger.debug('OrIntLit16 : %s', ins.get_output())
    return assign_lit(Op.OR, ins.CCCC, ins.A, ins.B, vmap)


# xor-int/lit16 vA, vB, #+CCCC ( 4b, 4b, 16b )
def xorintlit16(ins, vmap):
    logger.debug('XorIntLit16 : %s', ins.get_output())
    return assign_lit(Op.XOR, ins.CCCC, ins.A, ins.B, vmap)


# add-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def addintlit8(ins, vmap):
    logger.debug('AddIntLit8 : %s', ins.get_output())
    literal, op = [(ins.CC, Op.ADD), (-ins.CC, Op.SUB)][ins.CC < 0]
    return assign_lit(op, literal, ins.AA, ins.BB, vmap)


# rsub-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def rsubintlit8(ins, vmap):
    logger.debug('RSubIntLit8 : %s', ins.get_output())
    return assign_lit(Op.SUB, ins.CC, ins.AA, ins.BB, vmap)


# mul-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def mulintlit8(ins, vmap):
    logger.debug('MulIntLit8 : %s', ins.get_output())
    return assign_lit(Op.MUL, ins.CC, ins.AA, ins.BB, vmap)


# div-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def divintlit8(ins, vmap):
    logger.debug('DivIntLit8 : %s', ins.get_output())
    return assign_lit(Op.DIV, ins.CC, ins.AA, ins.BB, vmap)


# rem-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def remintlit8(ins, vmap):
    logger.debug('RemIntLit8 : %s', ins.get_output())
    return assign_lit(Op.MOD, ins.CC, ins.AA, ins.BB, vmap)


# and-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def andintlit8(ins, vmap):
    logger.debug('AndIntLit8 : %s', ins.get_output())
    return assign_lit(Op.AND, ins.CC, ins.AA, ins.BB, vmap)


# or-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def orintlit8(ins, vmap):
    logger.debug('OrIntLit8 : %s', ins.get_output())
    return assign_lit(Op.OR, ins.CC, ins.AA, ins.BB, vmap)


# xor-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def xorintlit8(ins, vmap):
    logger.debug('XorIntLit8 : %s', ins.get_output())
    return assign_lit(Op.XOR, ins.CC, ins.AA, ins.BB, vmap)


# shl-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def shlintlit8(ins, vmap):
    logger.debug('ShlIntLit8 : %s', ins.get_output())
    return assign_lit(Op.INTSHL, ins.CC, ins.AA, ins.BB, vmap)


# shr-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def shrintlit8(ins, vmap):
    logger.debug('ShrIntLit8 : %s', ins.get_output())
    return assign_lit(Op.INTSHR, ins.CC, ins.AA, ins.BB, vmap)


# ushr-int/lit8 vAA, vBB, #+CC ( 8b, 8b, 8b )
def ushrintlit8(ins, vmap):
    logger.debug('UShrIntLit8 : %s', ins.get_output())
    return assign_lit(Op.INTSHR, ins.CC, ins.AA, ins.BB, vmap)


INSTRUCTION_SET = {
    'nop':                    nop,
    'move':                   move,
    'move/from16':            movefrom16,
    'move/16':                move16,
    'move-wide':              movewide,
    'move-wide/from16':       movewidefrom16,
    'move-wide/16':           movewide16,
    'move-object':            moveobject,
    'move-object/from16':     moveobjectfrom16,
    'move-object/16':         moveobject16,
    'move-result':            moveresult,
    'move-result-wide':       moveresultwide,
    'move-result-object':     moveresultobject,
    'move-exception':         moveexception,
    'return-void':            returnvoid,
    'return':                 return_reg,
    'return-wide':            returnwide,
    'return-object':          returnobject,
    'const/4':                const4,
    'const/16':               const16,
    'const':                  const,
    'const/high16':           consthigh16,
    'const-wide/16':          constwide16,
    'const-wide/32':          constwide32,
    'const-wide':             constwide,
    'const-wide/high16':      constwidehigh16,
    'const-string':           conststring,
    'const-string/jumbo':     conststringjumbo,
    'const-class':            constclass,
    'monitor-enter':          monitorenter,
    'monitor-exit':           monitorexit,
    'check-cast':             checkcast,
    'instance-of':            instanceof,
    'array-length':           arraylength,
    'new-instance':           newinstance,
    'new-array':              newarray,
    'filled-new-array':       fillednewarray,
    'filled-new-array/range': fillednewarrayrange,
    'fill-array-data':        fillarraydata,
    'fill-array-data-payload': fillarraydatapayload,
    'throw':                  throw,
    'goto':                   goto,
    'goto/16':                goto16,
    'goto/32':                goto32,
    'packed-switch':          packedswitch,
    'sparse-switch':          sparseswitch,
    'cmpl-float':             cmplfloat,
    'cmpg-float':             cmpgfloat,
    'cmpl-double':            cmpldouble,
    'cmpg-double':            cmpgdouble,
    'cmp-long':               cmplong,
    'if-eq':                  ifeq,
    'if-ne':                  ifne,
    'if-lt':                  iflt,
    'if-ge':                  ifge,
    'if-gt':                  ifgt,
    'if-le':                  ifle,
    'if-eqz':                 ifeqz,
    'if-nez':                 ifnez,
    'if-ltz':                 ifltz,
    'if-gez':                 ifgez,
    'if-gtz':                 ifgtz,
    'if-lez':                 iflez,
    'aget':                   aget,
    'aget-wide':              agetwide,
    'aget-object':            agetobject,
    'aget-boolean':           agetboolean,
    'aget-byte':              agetbyte,
    'aget-char':              agetchar,
    'aget-short':             agetshort,
    'aput':                   aput,
    'aput-wide':              aputwide,
    'aput-object':            aputobject,
    'aput-boolean':           aputboolean,
    'aput-byte':              aputbyte,
    'aput-char':              aputchar,
    'aput-short':             aputshort,
    'iget':                   iget,
    'iget-wide':              igetwide,
    'iget-object':            igetobject,
    'iget-boolean':           igetboolean,
    'iget-byte':              igetbyte,
    'iget-char':              igetchar,
    'iget-short':             igetshort,
    'iput':                   iput,
    'iput-wide':              iputwide,
    'iput-object':            iputobject,
    'iput-boolean':           iputboolean,
    'iput-byte':              iputbyte,
    'iput-char':              iputchar,
    'iput-short':             iputshort,
    'sget':                   sget,
    'sget-wide':              sgetwide,
    'sget-object':            sgetobject,
    'sget-boolean':           sgetboolean,
    'sget-byte':              sgetbyte,
    'sget-char':              sgetchar,
    'sget-short':             sgetshort,
    'sput':                   sput,
    'sput-wide':              sputwide,
    'sput-object':            sputobject,
    'sput-boolean':           sputboolean,
    'sput-byte':              sputbyte,
    'sput-char':              sputchar,
    'sput-short':             sputshort,
    'invoke-virtual':         invokevirtual,
    'invoke-super':           invokesuper,
    'invoke-direct':          invokedirect,
    'invoke-static':          invokestatic,
    'invoke-interface':       invokeinterface,
    'invoke-virtual/range':   invokevirtualrange,
    'invoke-super/range':     invokesuperrange,
    'invoke-direct/range':    invokedirectrange,
    'invoke-static/range':    invokestaticrange,
    'invoke-interface/range': invokeinterfacerange,
    'neg-int':                negint,
    'not-int':                notint,
    'neg-long':               neglong,
    'not-long':               notlong,
    'neg-float':              negfloat,
    'neg-double':             negdouble,
    'int-to-long':            inttolong,
    'int-to-float':           inttofloat,
    'int-to-double':          inttodouble,
    'long-to-int':            longtoint,
    'long-to-float':          longtofloat,
    'long-to-double':         longtodouble,
    'float-to-int':           floattoint,
    'float-to-long':          floattolong,
    'float-to-double':        floattodouble,
    'double-to-int':          doubletoint,
    'double-to-long':         doubletolong,
    'double-to-float':        doubletofloat,
    'int-to-byte':            inttobyte,
    'int-to-char':            inttochar,
    'int-to-short':           inttoshort,
    'add-int':                addint,
    'sub-int':                subint,
    'mul-int':                mulint,
    'div-int':                divint,
    'rem-int':                remint,
    'and-int':                andint,
    'or-int':                 orint,
    'xor-int':                xorint,
    'shl-int':                shlint,
    'shr-int':                shrint,
    'ushr-int':               ushrint,
    'add-long':               addlong,
    'sub-long':               sublong,
    'mul-long':               mullong,
    'div-long':               divlong,
    'rem-long':               remlong,
    'and-long':               andlong,
    'or-long':                orlong,
    'xor-long':               xorlong,
    'shl-long':               shllong,
    'shr-long':               shrlong,
    'ushr-long':              ushrlong,
    'add-float':              addfloat,
    'sub-float':              subfloat,
    'mul-float':              mulfloat,
    'div-float':              divfloat,
    'rem-float':              remfloat,
    'add-double':             adddouble,
    'sub-double':             subdouble,
    'mul-double':             muldouble,
    'div-double':             divdouble,
    'rem-double':             remdouble,
    'add-int/2addr':          addint2addr,
    'sub-int/2addr':          subint2addr,
    'mul-int/2addr':          mulint2addr,
    'div-int/2addr':          divint2addr,
    'rem-int/2addr':          remint2addr,
    'and-int/2addr':          andint2addr,
    'or-int/2addr':           orint2addr,
    'xor-int/2addr':          xorint2addr,
    'shl-int/2addr':          shlint2addr,
    'shr-int/2addr':          shrint2addr,
    'ushr-int/2addr':         ushrint2addr,
    'add-long/2addr':         addlong2addr,
    'sub-long/2addr':         sublong2addr,
    'mul-long/2addr':         mullong2addr,
    'div-long/2addr':         divlong2addr,
    'rem-long/2addr':         remlong2addr,
    'and-long/2addr':         andlong2addr,
    'or-long/2addr':          orlong2addr,
    'xor-long/2addr':         xorlong2addr,
    'shl-long/2addr':         shllong2addr,
    'shr-long/2addr':         shrlong2addr,
    'ushr-long/2addr':        ushrlong2addr,
    'add-float/2addr':        addfloat2addr,
    'sub-float/2addr':        subfloat2addr,
    'mul-float/2addr':        mulfloat2addr,
    'div-float/2addr':        divfloat2addr,
    'rem-float/2addr':        remfloat2addr,
    'add-double/2addr':       adddouble2addr,
    'sub-double/2addr':       subdouble2addr,
    'mul-double/2addr':       muldouble2addr,
    'div-double/2addr':       divdouble2addr,
    'rem-double/2addr':       remdouble2addr,
    'add-int/lit16':          addintlit16,
    'rsub-int':               rsubint,
    'mul-int/lit16':          mulintlit16,
    'div-int/lit16':          divintlit16,
    'rem-int/lit16':          remintlit16,
    'and-int/lit16':          andintlit16,
    'or-int/lit16':           orintlit16,
    'xor-int/lit16':          xorintlit16,
    'add-int/lit8':           addintlit8,
    'rsub-int/lit8':          rsubintlit8,
    'mul-int/lit8':           mulintlit8,
    'div-int/lit8':           divintlit8,
    'rem-int/lit8':           remintlit8,
    'and-int/lit8':           andintlit8,
    'or-int/lit8':            orintlit8,
    'xor-int/lit8':           xorintlit8,
    'shl-int/lit8':           shlintlit8,
    'shr-int/lit8':           shrintlit8,
    'ushr-int/lit8':          ushrintlit8,
}
