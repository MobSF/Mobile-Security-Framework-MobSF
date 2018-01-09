# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections, struct
from functools import partial

from . import ir
from .. import flags, dalvik
from .jvmops import *
from . import arraytypes as arrays
from . import scalartypes as scalars
from . import mathops
from .optimization import stack
from .. import util
from ..typeinference import typeinference

# Code for converting dalvik bytecode to intermediate representation
# effectively this is just Java bytecode instructions with some abstractions for
# later optimization

_ilfdaOrd = [scalars.INT, scalars.LONG, scalars.FLOAT, scalars.DOUBLE, scalars.OBJ].index
_newArrayCodes = {('['+t).encode(): v for t, v in zip('ZCFDBSIJ', range(4, 12))}
_arrStoreOps = {t.encode(): v for t, v in zip('IJFD BCS', range(IASTORE, SASTORE+1))}
_arrLoadOps = {t.encode(): v for t, v in zip('IJFD BCS', range(IALOAD, SALOAD+1))}

# For generating IR instructions corresponding to a single Dalvik instruction
class IRBlock:
    def __init__(self, parent, pos):
        self.type_data = parent.types[pos]
        self.pool = parent.pool
        self.delay_consts = parent.opts.delay_consts
        self.pos = pos
        self.instructions = [ir.Label(pos)]

    def add(self, jvm_instr):
        self.instructions.append(jvm_instr)

    def _other(self, bytecode):
        self.add(ir.Other(bytecode=bytecode))

    def u8(self, op): self._other(struct.pack('>B', op))
    def u8u8(self, op, x): self._other(struct.pack('>BB', op, x))
    def u8u16(self, op, x): self._other(struct.pack('>BH', op, x))
    # wide non iinc
    def u8u8u16(self, op, op2, x): self._other(struct.pack('>BBH', op, op2, x))
    # invokeinterface
    def u8u16u8u8(self, op, x, y, z): self._other(struct.pack('>BHBB', op, x, y, z))

    def ldc(self, index):
        if index < 256:
            self.add(ir.OtherConstant(bytecode=bytes([LDC, index])))
        else:
            self.add(ir.OtherConstant(bytecode=struct.pack('>BH', LDC_W, index)))

    def load(self, reg, stype, desc=None, clsname=None):
        # if we know the register to be 0/null, don't bother loading
        if self.type_data.arrs[reg] == arrays.NULL:
            self.const(0, stype)
        else:
            self.add(ir.RegAccess(reg, stype, store=False))
            # cast to appropriate type if tainted
            if stype == scalars.OBJ and self.type_data.tainted[reg]:
                assert(desc is None or clsname is None)
                if clsname is None:
                    # remember to handle arrays - also fallthrough if desc is None
                    clsname = desc[1:-1] if (desc and desc.startswith(b'L')) else desc
                if clsname is not None and clsname != b'java/lang/Object':
                    self.u8u16(CHECKCAST, self.pool.class_(clsname))

    def loadAsArray(self, reg):
        at = self.type_data.arrs[reg]
        if at == arrays.NULL:
            self.const_null()
        else:
            self.add(ir.RegAccess(reg, scalars.OBJ, store=False))
            if self.type_data.tainted[reg]:
                if at == arrays.INVALID:
                    # needs to be some type of object array, so just cast to Object[]
                    self.u8u16(CHECKCAST, self.pool.class_(b'[Ljava/lang/Object;'))
                else:
                    # note - will throw if actual type is boolean[] but there's not
                    # much we can do in this case
                    self.u8u16(CHECKCAST, self.pool.class_(at))

    def store(self, reg, stype):
        self.add(ir.RegAccess(reg, stype, store=True))

    def return_(self, stype=None):
        if stype is None:
            self.u8(RETURN)
        else:
            self.u8(IRETURN + _ilfdaOrd(stype))

    def const(self, val, stype):
        assert((1<<64) > val >= 0)
        if stype == scalars.OBJ:
            assert(val == 0)
            self.const_null()
        else:
            # If constant pool is simple, assume we're in non-opt mode and only use
            # the constant pool for generating constants instead of calculating
            # bytecode sequences for them. If we're in opt mode, pass None for pool
            # to generate bytecode instead
            pool = None if self.delay_consts else self.pool
            self.add(ir.PrimConstant(stype, val, pool=pool))

    def const_null(self):
        self.add(ir.OtherConstant(bytecode=bytes([ACONST_NULL])))

    def fillarraysub(self, op, cbs, pop=True):
        gen = stack.genDups(len(cbs), 0 if pop else 1)
        for i, cb in enumerate(cbs):
            for bytecode in next(gen):
                self._other(bytecode)
            self.const(i, scalars.INT)
            cb()
            self.u8(op)
        # may need to pop at end
        for bytecode in next(gen):
            self._other(bytecode)

    def newarray(self, desc):
        if desc in _newArrayCodes:
            self.u8u8(NEWARRAY, _newArrayCodes[desc])
        else:
            # can be either multidim array or object array descriptor
            desc = desc[1:]
            if desc.startswith(b'L'):
                desc = desc[1:-1]
            self.u8u16(ANEWARRAY, self.pool.class_(desc))

    def fillarraydata(self, op, stype, vals):
        self.fillarraysub(op, [partial(self.const, val, stype) for val in vals])

    def cast(self, dex, reg, index):
        self.load(reg, scalars.OBJ)
        self.u8u16(CHECKCAST, self.pool.class_(dex.clsType(index)))
        self.store(reg, scalars.OBJ)

    def goto(self, target):
        self.add(ir.Goto(target))

    def if_(self, op, target):
        self.add(ir.If(op, target))

    def switch(self, default, jumps):
        jumps = {util.s32(k):v for k,v in jumps.items() if v != default}
        if jumps:
            self.add(ir.Switch(default, jumps))
        else:
            self.goto(default)

    def generateExceptLabels(self):
        s_ind = 0
        e_ind = len(self.instructions)
        # assume only Other instructions can throw
        while s_ind < e_ind and not isinstance(self.instructions[s_ind], ir.Other):
            s_ind += 1
        while s_ind < e_ind and not isinstance(self.instructions[e_ind-1], ir.Other):
            e_ind -= 1

        assert(s_ind < e_ind)
        start_lbl, end_lbl = ir.Label(), ir.Label()
        self.instructions.insert(s_ind, start_lbl)
        self.instructions.insert(e_ind+1, end_lbl)
        return start_lbl, end_lbl

class IRWriter:
    def __init__(self, pool, method, types, opts):
        self.pool = pool
        self.method = method
        self.types = types
        self.opts = opts

        self.iblocks = {}

        self.flat_instructions = None
        self.excepts = []
        self.labels = {}
        self.initial_args = None
        self.exception_redirects = {}

        self.except_starts = set()
        self.except_ends = set()
        self.jump_targets = set()
        # used to detect jump targets with a unique predecessor
        self.target_pred_counts = collections.defaultdict(int)

        self.numregs = None # will be set once registers are allocated (see registers.py)
        self.upper_bound = None # upper bound on code length

    def calcInitialArgs(self, nregs, scalar_ptypes):
        self.initial_args = args = []
        regoff = nregs - len(scalar_ptypes)
        for i, st in enumerate(scalar_ptypes):
            if st == scalars.INVALID:
                args.append(None)
            else:
                args.append((i + regoff, st))

    def addExceptionRedirect(self, target):
        return self.exception_redirects.setdefault(target, ir.Label())

    def createBlock(self, instr):
        block = IRBlock(self, instr.pos)
        self.iblocks[block.pos] = block
        self.labels[block.pos] = block.instructions[0]
        return block

    def flatten(self):
        instructions = []
        for pos in sorted(self.iblocks):
            if pos in self.exception_redirects:
                # check if we can put handler pop in front of block
                if instructions and not instructions[-1].fallsthrough():
                    instructions.append(self.exception_redirects.pop(pos))
                    instructions.append(ir.Other(bytecode=bytes([POP])))
                # if not, leave it in dict to be redirected later
            # now add instructions for actual block
            instructions += self.iblocks[pos].instructions

        # exception handler pops that couldn't be placed inline
        # in this case, just put them at the end with a goto back to the handler
        for target in sorted(self.exception_redirects):
            instructions.append(self.exception_redirects[target])
            instructions.append(ir.Other(bytecode=bytes([POP])))
            instructions.append(ir.Goto(target))

        self.flat_instructions = instructions
        self.iblocks = self.exception_redirects = None

    def replaceInstrs(self, replace):
        if replace:
            instructions = []
            for instr in self.flat_instructions:
                instructions.extend(replace.get(instr, [instr]))
            self.flat_instructions = instructions
            assert(len(set(instructions)) == len(instructions))

    def calcUpperBound(self):
        # Get an uppper bound on the size of the bytecode
        size = 0
        for ins in self.flat_instructions:
            if ins.bytecode is None:
                size += ins.max
            else:
                size += len(ins.bytecode)
        self.upper_bound = size
        return size

################################################################################
def visitNop(method, dex, instr_d, type_data, block, instr):
    pass

def visitMove(method, dex, instr_d, type_data, block, instr):
    for st in (scalars.INT, scalars.OBJ, scalars.FLOAT):
        if st & type_data.prims[instr.args[1]]:
            block.load(instr.args[1], st)
            block.store(instr.args[0], st)

def visitMoveWide(method, dex, instr_d, type_data, block, instr):
    for st in (scalars.LONG, scalars.DOUBLE):
        if st & type_data.prims[instr.args[1]]:
            block.load(instr.args[1], st)
            block.store(instr.args[0], st)

def visitMoveResult(method, dex, instr_d, type_data, block, instr):
    st = scalars.fromDesc(instr.prev_result)
    block.store(instr.args[0], st)

def visitReturn(method, dex, instr_d, type_data, block, instr):
    if method.id.return_type == b'V':
        block.return_()
    else:
        st = scalars.fromDesc(method.id.return_type)
        block.load(instr.args[0], st, desc=method.id.return_type)
        block.return_(st)

def visitConst32(method, dex, instr_d, type_data, block, instr):
    val = instr.args[1] % (1<<32)
    block.const(val, scalars.INT)
    block.store(instr.args[0], scalars.INT)
    block.const(val, scalars.FLOAT)
    block.store(instr.args[0], scalars.FLOAT)
    if not val:
        block.const_null()
        block.store(instr.args[0], scalars.OBJ)

def visitConst64(method, dex, instr_d, type_data, block, instr):
    val = instr.args[1] % (1<<64)
    block.const(val, scalars.LONG)
    block.store(instr.args[0], scalars.LONG)
    block.const(val, scalars.DOUBLE)
    block.store(instr.args[0], scalars.DOUBLE)

def visitConstString(method, dex, instr_d, type_data, block, instr):
    val = dex.string(instr.args[1])
    block.ldc(block.pool.string(val))
    block.store(instr.args[0], scalars.OBJ)

def visitConstClass(method, dex, instr_d, type_data, block, instr):
    # Could use dex.type here since the JVM doesn't care, but this is cleaner
    val = dex.clsType(instr.args[1])
    block.ldc(block.pool.class_(val))
    block.store(instr.args[0], scalars.OBJ)

def visitMonitorEnter(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[0], scalars.OBJ)
    block.u8(MONITORENTER)

def visitMonitorExit(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[0], scalars.OBJ)
    block.u8(MONITOREXIT)

def visitCheckCast(method, dex, instr_d, type_data, block, instr):
    block.cast(dex, instr.args[0], instr.args[1])

def visitInstanceOf(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[1], scalars.OBJ)
    block.u8u16(INSTANCEOF, block.pool.class_(dex.clsType(instr.args[2])))
    block.store(instr.args[0], scalars.INT)

def visitArrayLen(method, dex, instr_d, type_data, block, instr):
    block.loadAsArray(instr.args[1])
    block.u8(ARRAYLENGTH)
    block.store(instr.args[0], scalars.INT)

def visitNewInstance(method, dex, instr_d, type_data, block, instr):
    block.u8u16(NEW, block.pool.class_(dex.clsType(instr.args[1])))
    block.store(instr.args[0], scalars.OBJ)

def visitNewArray(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[1], scalars.INT)
    block.newarray(dex.type(instr.args[2]))
    block.store(instr.args[0], scalars.OBJ)

def visitFilledNewArray(method, dex, instr_d, type_data, block, instr):
    regs = instr.args[1]
    block.const(len(regs), scalars.INT)
    block.newarray(dex.type(instr.args[0]))
    st, elet = arrays.eletPair(arrays.fromDesc(dex.type(instr.args[0])))
    op = _arrStoreOps.get(elet, AASTORE)
    cbs = [partial(block.load, reg, st) for reg in regs]
    # if not followed by move-result, don't leave it on the stack
    mustpop = instr_d.get(instr.pos2).type != dalvik.MoveResult
    block.fillarraysub(op, cbs, pop=mustpop)

def visitFillArrayData(method, dex, instr_d, type_data, block, instr):
    width, arrdata = instr_d[instr.args[1]].fillarrdata
    at = type_data.arrs[instr.args[0]]

    block.loadAsArray(instr.args[0])
    if at is arrays.NULL:
        block.u8(ATHROW)
    else:
        if len(arrdata) == 0:
            # fill-array-data throws a NPE if array is null even when
            # there is 0 data, so we need to add an instruction that
            # throws a NPE in this case
            block.u8(ARRAYLENGTH)
            block.u8(POP)
        else:
            st, elet = arrays.eletPair(at)
            # check if we need to sign extend
            if elet == b'B':
                arrdata = [util.signExtend(x, 8) & 0xFFFFFFFF for x in arrdata]
            elif elet == b'S':
                arrdata = [util.signExtend(x, 16) & 0xFFFFFFFF for x in arrdata]
            block.fillarraydata(_arrStoreOps.get(elet, AASTORE), st, arrdata)

def visitThrow(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[0], scalars.OBJ, clsname=b'java/lang/Throwable')
    block.u8(ATHROW)

def visitGoto(method, dex, instr_d, type_data, block, instr):
    block.goto(instr.args[0])

def visitSwitch(method, dex, instr_d, type_data, block, instr):
    block.load(instr.args[0], scalars.INT)
    switchdata = instr_d[instr.args[1]].switchdata
    default = instr.pos2
    jumps = {k:(offset + instr.pos) % (1<<32) for k, offset in switchdata.items()}
    block.switch(default, jumps)

def visitCmp(method, dex, instr_d, type_data, block, instr):
    op = [FCMPL, FCMPG, DCMPL, DCMPG, LCMP][instr.opcode - 0x2d]
    st = [scalars.FLOAT, scalars.FLOAT, scalars.DOUBLE, scalars.DOUBLE, scalars.LONG][instr.opcode - 0x2d]
    block.load(instr.args[1], st)
    block.load(instr.args[2], st)
    block.u8(op)
    block.store(instr.args[0], scalars.INT)

def visitIf(method, dex, instr_d, type_data, block, instr):
    st = type_data.prims[instr.args[0]] & type_data.prims[instr.args[1]]
    if st & scalars.INT:
        block.load(instr.args[0], scalars.INT)
        block.load(instr.args[1], scalars.INT)
        op = [IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE][instr.opcode - 0x32]
    else:
        block.load(instr.args[0], scalars.OBJ)
        block.load(instr.args[1], scalars.OBJ)
        op = [IF_ACMPEQ, IF_ACMPNE][instr.opcode - 0x32]
    block.if_(op, instr.args[2])

def visitIfZ(method, dex, instr_d, type_data, block, instr):
    if type_data.prims[instr.args[0]] & scalars.INT:
        block.load(instr.args[0], scalars.INT)
        op = [IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE][instr.opcode - 0x38]
    else:
        block.load(instr.args[0], scalars.OBJ)
        op = [IFNULL, IFNONNULL][instr.opcode - 0x38]
    block.if_(op, instr.args[1])

def visitArrayGet(method, dex, instr_d, type_data, block, instr):
    at = type_data.arrs[instr.args[1]]
    if at is arrays.NULL:
        block.const_null()
        block.u8(ATHROW)
    else:
        block.loadAsArray(instr.args[1])
        block.load(instr.args[2], scalars.INT)
        st, elet = arrays.eletPair(at)
        block.u8(_arrLoadOps.get(elet, AALOAD))
        block.store(instr.args[0], st)

def visitArrayPut(method, dex, instr_d, type_data, block, instr):
    at = type_data.arrs[instr.args[1]]
    if at is arrays.NULL:
        block.const_null()
        block.u8(ATHROW)
    else:
        block.loadAsArray(instr.args[1])
        block.load(instr.args[2], scalars.INT)
        st, elet = arrays.eletPair(at)
        block.load(instr.args[0], st)
        block.u8(_arrStoreOps.get(elet, AASTORE))

def visitInstanceGet(method, dex, instr_d, type_data, block, instr):
    field_id = dex.field_id(instr.args[2])
    st = scalars.fromDesc(field_id.desc)
    block.load(instr.args[1], scalars.OBJ, clsname=field_id.cname)
    block.u8u16(GETFIELD, block.pool.field(field_id.triple()))
    block.store(instr.args[0], st)

def visitInstancePut(method, dex, instr_d, type_data, block, instr):
    field_id = dex.field_id(instr.args[2])
    st = scalars.fromDesc(field_id.desc)
    block.load(instr.args[1], scalars.OBJ, clsname=field_id.cname)
    block.load(instr.args[0], st, desc=field_id.desc)
    block.u8u16(PUTFIELD, block.pool.field(field_id.triple()))

def visitStaticGet(method, dex, instr_d, type_data, block, instr):
    field_id = dex.field_id(instr.args[1])
    st = scalars.fromDesc(field_id.desc)
    block.u8u16(GETSTATIC, block.pool.field(field_id.triple()))
    block.store(instr.args[0], st)

def visitStaticPut(method, dex, instr_d, type_data, block, instr):
    field_id = dex.field_id(instr.args[1])
    st = scalars.fromDesc(field_id.desc)
    block.load(instr.args[0], st, desc=field_id.desc)
    block.u8u16(PUTSTATIC, block.pool.field(field_id.triple()))

def visitInvoke(method, dex, instr_d, type_data, block, instr):
    isstatic = instr.type == dalvik.InvokeStatic

    called_id = dex.method_id(instr.args[0])
    sts = scalars.paramTypes(called_id, static=isstatic)
    descs = called_id.getSpacedParamTypes(isstatic=isstatic)
    assert(len(sts) == len(instr.args[1]) == len(descs))

    for st, desc, reg in zip(sts, descs, instr.args[1]):
        if st != scalars.INVALID: # skip long/double tops
            block.load(reg, st, desc=desc)
    op = {
        dalvik.InvokeVirtual: INVOKEVIRTUAL,
        dalvik.InvokeSuper: INVOKESPECIAL,
        dalvik.InvokeDirect: INVOKESPECIAL,
        dalvik.InvokeStatic: INVOKESTATIC,
        dalvik.InvokeInterface: INVOKEINTERFACE,
    }[instr.type]

    if instr.type == dalvik.InvokeInterface:
        block.u8u16u8u8(op, block.pool.imethod(called_id.triple()), len(descs), 0)
    else:
        block.u8u16(op, block.pool.method(called_id.triple()))

    # check if we need to pop result instead of leaving on stack
    if instr_d.get(instr.pos2).type != dalvik.MoveResult:
        if called_id.return_type != b'V':
            st = scalars.fromDesc(called_id.return_type)
            block.u8(POP2 if scalars.iswide(st) else POP)

def visitUnaryOp(method, dex, instr_d, type_data, block, instr):
    op, srct, destt = mathops.UNARY[instr.opcode]
    block.load(instr.args[1], srct)
    # *not requires special handling since there's no direct Java equivalent. Instead we have to do x ^ -1
    if op == IXOR:
        block.u8(ICONST_M1)
    elif op == LXOR:
        block.u8(ICONST_M1)
        block.u8(I2L)

    block.u8(op)
    block.store(instr.args[0], destt)

def visitBinaryOp(method, dex, instr_d, type_data, block, instr):
    op, st, st2 = mathops.BINARY[instr.opcode]
    # index arguments as negative so it works for regular and 2addr forms
    block.load(instr.args[-2], st)
    block.load(instr.args[-1], st2)
    block.u8(op)
    block.store(instr.args[0], st)

def visitBinaryOpConst(method, dex, instr_d, type_data, block, instr):
    op = mathops.BINARY_LIT[instr.opcode]
    if op == ISUB: # rsub
        block.const(instr.args[2] % (1<<32), scalars.INT)
        block.load(instr.args[1], scalars.INT)
    else:
        block.load(instr.args[1], scalars.INT)
        block.const(instr.args[2] % (1<<32), scalars.INT)
    block.u8(op)
    block.store(instr.args[0], scalars.INT)
################################################################################
VISIT_FUNCS = {
    dalvik.Nop: visitNop,
    dalvik.Move: visitMove,
    dalvik.MoveWide: visitMoveWide,
    dalvik.MoveResult: visitMoveResult,
    dalvik.Return: visitReturn,
    dalvik.Const32: visitConst32,
    dalvik.Const64: visitConst64,
    dalvik.ConstString: visitConstString,
    dalvik.ConstClass: visitConstClass,
    dalvik.MonitorEnter: visitMonitorEnter,
    dalvik.MonitorExit: visitMonitorExit,
    dalvik.CheckCast: visitCheckCast,
    dalvik.InstanceOf: visitInstanceOf,
    dalvik.ArrayLen: visitArrayLen,
    dalvik.NewInstance: visitNewInstance,
    dalvik.NewArray: visitNewArray,
    dalvik.FilledNewArray: visitFilledNewArray,
    dalvik.FillArrayData: visitFillArrayData,
    dalvik.Throw: visitThrow,
    dalvik.Goto: visitGoto,
    dalvik.Switch: visitSwitch,
    dalvik.Cmp: visitCmp,
    dalvik.If: visitIf,
    dalvik.IfZ: visitIfZ,

    dalvik.ArrayGet: visitArrayGet,
    dalvik.ArrayPut: visitArrayPut,
    dalvik.InstanceGet: visitInstanceGet,
    dalvik.InstancePut: visitInstancePut,
    dalvik.StaticGet: visitStaticGet,
    dalvik.StaticPut: visitStaticPut,

    dalvik.InvokeVirtual: visitInvoke,
    dalvik.InvokeSuper: visitInvoke,
    dalvik.InvokeDirect: visitInvoke,
    dalvik.InvokeStatic: visitInvoke,
    dalvik.InvokeInterface: visitInvoke,

    dalvik.UnaryOp: visitUnaryOp,
    dalvik.BinaryOp: visitBinaryOp,
    dalvik.BinaryOpConst: visitBinaryOpConst,
}

def writeBytecode(pool, method, opts):
    dex = method.dex
    code = method.code
    instr_d = {instr.pos: instr for instr in code.bytecode}
    types, all_handlers = typeinference.doInference(dex, method, code, code.bytecode, instr_d)

    scalar_ptypes = scalars.paramTypes(method.id, static=(method.access & flags.ACC_STATIC))

    writer = IRWriter(pool, method, types, opts)
    writer.calcInitialArgs(code.nregs, scalar_ptypes)

    for instr in code.bytecode:
        if instr.pos not in types: # skip unreachable instructions
            continue
        type_data = types[instr.pos]
        block = writer.createBlock(instr)
        VISIT_FUNCS[instr.type](method, dex, instr_d, type_data, block, instr)

    for instr in sorted(all_handlers, key=lambda instr: instr.pos):
        assert(all_handlers[instr])
        if instr.pos not in types: # skip unreachable instructions
            continue

        start, end = writer.iblocks[instr.pos].generateExceptLabels()
        writer.except_starts.add(start)
        writer.except_ends.add(end)

        for ctype, handler_pos in all_handlers[instr]:
            # If handler doesn't use the caught exception, we need to redirect to a pop instead
            if instr_d.get(handler_pos).type != dalvik.MoveResult:
                target = writer.addExceptionRedirect(handler_pos)
            else:
                target = writer.labels[handler_pos]
            writer.jump_targets.add(target)
            writer.target_pred_counts[target] += 1

            # When catching Throwable, we can use the special index 0 instead,
            # potentially saving a constant pool entry or two
            jctype = 0 if ctype == b'java/lang/Throwable' else pool.class_(ctype)
            writer.excepts.append((start, end, target, jctype))
    writer.flatten()

    # find jump targets (in addition to exception handler targets)
    for instr in writer.flat_instructions:
        for target in instr.targets():
            label = writer.labels[target]
            writer.jump_targets.add(label)
            writer.target_pred_counts[label] += 1

    return writer
