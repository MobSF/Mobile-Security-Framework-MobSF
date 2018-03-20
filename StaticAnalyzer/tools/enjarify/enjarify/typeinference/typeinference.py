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

import collections, operator

from ..jvm import arraytypes as arrays
from ..jvm import scalartypes as scalars
from ..jvm import mathops, jvmops
from ..treelist import TreeList
from .. import flags, dalvik


# The two main things we need type inference for are determining the types of
# primative values and arrays. Luckily, we don't care about actual classes in
# these cases, we just need to know whether it is int,float,reference, etc. to
# generate the correct bytecode instructions, which are typed in Java.
#
# One additional problem is that ART's implicit casts narrow the type instead of
# replacing it like regular checkcasts do. This means that there is no way to
# replicate the behavior in Java using normal casts unless you know which class
# is a subclass of another and which classes are interfaces. However, we want to
# be able to translate code without knowing about every other class that could be
# referenced by the application, so we make do with a hack.
#
# Variables subjected to implicit casting are marked as tainted. Whenever a
# tained value is used, it is explcitly checkcasted to the expected type. This
# isn't ideal since it will incorrectly throw in the cast of bad interface casts,
# but it's the best we can do without requiring knowledge of the whole inheritance
# hierarchy.

class TypeInfo:
    def __init__(self, prims, arrs, tainted):
        # copy on write
        self.prims = prims
        self.arrs = arrs
        self.tainted = tainted

    def _copy(self): return TypeInfo(self.prims.copy(), self.arrs.copy(), self.tainted.copy())
    def _get(self, reg): return self.prims[reg], self.arrs[reg], self.tainted[reg]

    def _set(self, reg, st, at, taint=False):
        self.prims[reg] = st
        self.arrs[reg] = at
        self.tainted[reg] = taint
        return self

    def move(self, src, dest, wide):
        new = self._copy()._set(dest, *self._get(src))
        if wide:
            new._set(dest+1, *self._get(src+1))
        return new

    def assign(self, reg, st, at=arrays.INVALID, taint=False):
        assert(st is not None)
        return self._copy()._set(reg, st, at, taint)

    def assign2(self, reg, st):
        assert(st is not None)
        at = arrays.INVALID
        return self._copy()._set(reg, st, at)._set(reg+1, scalars.INVALID, at)

    def assignFromDesc(self, reg, desc):
        st = scalars.fromDesc(desc)
        at = arrays.fromDesc(desc)
        if scalars.iswide(st):
            return self.assign2(reg, st)
        else:
            return self.assign(reg, st, at)

    def isSame(self, other):
        return (self.prims.data is other.prims.data and
            self.arrs.data is other.arrs.data and
            self.tainted.data is other.tainted.data)

def merge(old, new):
    temp = old._copy()
    temp.prims.merge(new.prims)
    temp.arrs.merge(new.arrs)
    temp.tainted.merge(new.tainted)
    return old if old.isSame(temp) else temp

def fromParams(method, num_regs):
    isstatic = method.access & flags.ACC_STATIC
    full_ptypes = method.id.getSpacedParamTypes(isstatic)
    offset = num_regs - len(full_ptypes)

    prims = TreeList(scalars.INVALID, operator.__and__)
    arrs = TreeList(arrays.INVALID, arrays.merge)
    tainted = TreeList(False, operator.__or__)

    for i, desc in enumerate(full_ptypes):
        if desc is not None:
            prims[offset + i] = scalars.fromDesc(desc)
            arrs[offset + i] = arrays.fromDesc(desc)
    return TypeInfo(prims, arrs, tainted)

_MATH_THROW_OPS = [jvmops.IDIV, jvmops.IREM, jvmops.LDIV, jvmops.LREM]
def pruneHandlers(all_handlers):
    result = collections.defaultdict(list)
    for instr, handlers in all_handlers.items():
        if not instr.type in dalvik.PRUNED_THROW_TYPES:
            continue
        # if math op, make sure it is int div/rem
        if instr.type == dalvik.BinaryOp:
            if mathops.BINARY[instr.opcode][0] not in _MATH_THROW_OPS:
                continue
        elif instr.type == dalvik.BinaryOpConst:
            if mathops.BINARY_LIT[instr.opcode] not in _MATH_THROW_OPS:
                continue

        types = set()
        for ctype, handler in handlers:
            # if multiple handlers with same catch type, only include the first
            if ctype not in types:
                result[instr].append((ctype, handler))
                types.add(ctype)
            # stop as soon as we reach a catch all handler
            if ctype == b'java/lang/Throwable':
                break
    return dict(result)

################################################################################
# Lots of instructions just return an object or int for type inference purposes
# so we have a single function for these cases
def visitRetObj(dex, instr, cur):
    return cur.assign(instr.args[0], scalars.OBJ)
def visitRetInt(dex, instr, cur):
    return cur.assign(instr.args[0], scalars.INT)

# Instruction specific callbacks
def visitMove(dex, instr, cur):
    return cur.move(instr.args[1], instr.args[0], wide=False)
def visitMoveWide(dex, instr, cur):
    return cur.move(instr.args[1], instr.args[0], wide=True)
def visitMoveResult(dex, instr, cur):
    return cur.assignFromDesc(instr.args[0], instr.prev_result)
def visitConst32(dex, instr, cur):
    val = instr.args[1] % (1<<32)
    if val == 0:
        return cur.assign(instr.args[0], scalars.ZERO, arrays.NULL)
    else:
        return cur.assign(instr.args[0], scalars.C32)
def visitConst64(dex, instr, cur):
    return cur.assign2(instr.args[0], scalars.C64)
def visitCheckCast(dex, instr, cur):
    at = arrays.fromDesc(dex.type(instr.args[1]))
    at = arrays.narrow(cur.arrs[instr.args[0]], at)
    return cur.assign(instr.args[0], scalars.OBJ, at)
def visitNewArray(dex, instr, cur):
    at = arrays.fromDesc(dex.type(instr.args[2]))
    return cur.assign(instr.args[0], scalars.OBJ, at)
def visitArrayGet(dex, instr, cur):
    arr_at = cur.arrs[instr.args[1]]
    if arr_at is arrays.NULL:
        # This is unreachable, so use (ALL, NULL), which can be merged with anything
        return cur.assign(instr.args[0], scalars.ALL, arrays.NULL)
    else:
        st, at = arrays.eletPair(arr_at)
        return cur.assign(instr.args[0], st, at)
def visitInstanceGet(dex, instr, cur):
    field_id = dex.field_id(instr.args[2])
    return cur.assignFromDesc(instr.args[0], field_id.desc)
def visitStaticGet(dex, instr, cur):
    field_id = dex.field_id(instr.args[1])
    return cur.assignFromDesc(instr.args[0], field_id.desc)

def visitUnaryOp(dex, instr, cur):
    _, _, st = mathops.UNARY[instr.opcode]
    if scalars.iswide(st):
        return cur.assign2(instr.args[0], st)
    else:
        return cur.assign(instr.args[0], st)

def visitBinaryOp(dex, instr, cur):
    _, st, _ = mathops.BINARY[instr.opcode]
    if scalars.iswide(st):
        return cur.assign2(instr.args[0], st)
    else:
        return cur.assign(instr.args[0], st)

FUNCS = {
    dalvik.ConstString: visitRetObj,
    dalvik.ConstClass: visitRetObj,
    dalvik.NewInstance: visitRetObj,
    dalvik.InstanceOf: visitRetInt,
    dalvik.ArrayLen: visitRetInt,
    dalvik.Cmp: visitRetInt,
    dalvik.BinaryOpConst: visitRetInt,

    dalvik.Move: visitMove,
    dalvik.MoveWide: visitMoveWide,
    dalvik.MoveResult: visitMoveResult,
    dalvik.Const32: visitConst32,
    dalvik.Const64: visitConst64,
    dalvik.CheckCast: visitCheckCast,
    dalvik.NewArray: visitNewArray,
    dalvik.ArrayGet: visitArrayGet,
    dalvik.InstanceGet: visitInstanceGet,
    dalvik.StaticGet: visitStaticGet,
    dalvik.UnaryOp: visitUnaryOp,
    dalvik.BinaryOp: visitBinaryOp,
}

CONTROL_FLOW_OPS = {dalvik.Goto, dalvik.If, dalvik.IfZ, dalvik.Switch}

def doInference(dex, method, code, bytecode, instr_d):
    # get exception handlers
    all_handlers = collections.defaultdict(list)
    for tryi in code.tries:
        for instr in code.bytecode:
            if tryi.start < instr.pos2 and tryi.end > instr.pos:
                all_handlers[instr] += tryi.catches
    all_handlers = pruneHandlers(all_handlers)

    types = {}
    types[0] = fromParams(method, code.nregs)
    dirty = {0}

    def doMerge(pos, new):
        # prevent infinite loops
        if pos not in instr_d:
            return

        if pos in types:
            old = types[pos]
            new = merge(old, new)
            if new is not old:
                types[pos] = new
                dirty.add(pos)
        else:
            types[pos] = new
            dirty.add(pos)

    while dirty: # iterate until convergence
        for instr in bytecode:
            if instr.pos not in dirty:
                continue

            dirty.remove(instr.pos)
            cur = types[instr.pos]
            itype = instr.type
            if itype in FUNCS:
                after = FUNCS[itype](dex, instr, cur)
            elif itype in CONTROL_FLOW_OPS:
                # control flow - none of these are in FUNCS
                result = after = after2 = cur
                if instr.implicit_casts is not None:
                    desc_ind, regs = instr.implicit_casts
                    for reg in regs:
                        st = cur.prims[reg] # could != OBJ if null
                        at = arrays.narrow(cur.arrs[reg], arrays.fromDesc(dex.type(desc_ind)))
                        result = result.assign(reg, st, at, taint=True)
                    # merge into branch if op = if-nez else merge into fallthrough
                    if instr.opcode == 0x39:
                        after2 = result
                    else:
                        after = result

                if instr.type == dalvik.Goto:
                    doMerge(instr.args[0], after2)
                elif instr.type == dalvik.If:
                    doMerge(instr.args[2], after2)
                elif instr.type == dalvik.IfZ:
                    doMerge(instr.args[1], after2)
                elif instr.type == dalvik.Switch:
                    switchdata = instr_d[instr.args[1]].switchdata
                    for offset in switchdata.values():
                        target = (instr.pos + offset) % (1<<32)
                        doMerge(target, cur)
            else:
                after = cur

            # these instructions don't fallthrough
            if instr.type not in (dalvik.Return, dalvik.Throw, dalvik.Goto):
                doMerge(instr.pos2, after)

            # exception handlers
            if instr in all_handlers:
                for ctype, handler in all_handlers[instr]:
                    doMerge(handler, cur)
    return types, all_handlers
