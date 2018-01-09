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

import struct

from .constants import calc
from .jvmops import *
from . import constantpool, error
from . import scalartypes as scalars

# IR representation roughly corresponding to JVM bytecode instructions. Note that these
# may correspond to more than one instruction in the actual bytecode generated but they
# are useful logical units for the internal optimization passes.

class JvmInstruction:
    def __init__(self, bytecode=None):
        self.bytecode = bytecode # None or bytestring

    def fallsthrough(self): return True
    def targets(self): return []

# Used to mark locations in the IR instructions for various purposes. These are
# seperate IR 'instructions' since the optimization passes may remove or replace
# the other instructions.
class Label(JvmInstruction):
    def __init__(self, id=None):
        super().__init__(b'')
        self.id = id # None or int

_ilfdaOrd = [scalars.INT, scalars.LONG, scalars.FLOAT, scalars.DOUBLE, scalars.OBJ].index
class RegAccess(JvmInstruction):
    max = 4 # upper limit on length of bytecode
    def __init__(self, dreg, st, store):
        super().__init__()
        self.key = dreg, st
        self.store = store
        self.wide = scalars.iswide(st)

    @staticmethod
    def raw(local, stype, store):
        new = RegAccess(0, stype, store)
        new.calcBytecode(local)
        return new

    def calcBytecode(self, local):
        assert(self.bytecode is None)
        stype = self.key[1]
        op_off = (ISTORE - ILOAD) if self.store else 0
        if local < 4:
            self.bytecode = struct.pack('>B', ILOAD_0 + op_off + local + _ilfdaOrd(stype)*4)
        elif local < 256:
            self.bytecode = struct.pack('>BB', ILOAD + op_off + _ilfdaOrd(stype), local)
        else:
            self.bytecode = struct.pack('>BBH', WIDE, ILOAD + op_off + _ilfdaOrd(stype), local)

class PrimConstant(JvmInstruction):
    def __init__(self, st, val, pool=None):
        super().__init__()
        self.st = st
        self.val = val = calc.normalize(st, val)
        self.wide = scalars.iswide(st)

        # If pool is passed in, just grab an entry greedily, otherwise calculate
        # a sequence of bytecode to generate the constant
        if pool is not None:
            self.bytecode = calc.lookupOnly(st, val)
            if self.bytecode is None:
                self._from_pool(pool)
            if self.bytecode is None:
                raise error.ClassfileLimitExceeded()
        else:
            self.bytecode = calc.calc(st, val)

    def cpool_key(self):
        tag = {
            scalars.INT: constantpool.CONSTANT_Integer,
            scalars.FLOAT: constantpool.CONSTANT_Float,
            scalars.DOUBLE: constantpool.CONSTANT_Double,
            scalars.LONG: constantpool.CONSTANT_Long,
        }[self.st]
        return tag, self.val

    def _from_pool(self, pool):
        index = pool.tryGet(self.cpool_key())
        if index is not None:
            if scalars.iswide(self.st):
                code = struct.pack('>BH', LDC2_W, index)
            elif index >= 256:
                code = struct.pack('>BH', LDC_W, index)
            else:
                code = struct.pack('>BB', LDC, index)
            self.bytecode = code

    def fix_with_pool(self, pool):
        if len(self.bytecode) > 2:
            self._from_pool(pool)

class OtherConstant(JvmInstruction):
    wide = False # will be null, string or class - always single

class LazyJumpBase(JvmInstruction):
    def __init__(self, target):
        super().__init__()
        self.target = target

    def targets(self): return [self.target]

    def widenIfNecessary(self, labels, posd):
        offset = posd[labels[self.target]] - posd[self]
        if not -32768 <= offset < 32768:
            self.min = self.max
            return True
        return False

class Goto(LazyJumpBase):
    def __init__(self, target):
        super().__init__(target)
        self.min = 3
        self.max = 5 # upper limit on length of bytecode

    def fallsthrough(self): return False

    def calcBytecode(self, posd, labels):
        offset = posd[labels[self.target]] - posd[self]
        if self.max == 3:
            self.bytecode = struct.pack('>Bh', GOTO, offset)
        else:
            self.bytecode = struct.pack('>Bi', GOTO_W, offset)

_ifOpposite = {}
for _op1, _op2 in [(IFEQ, IFNE), (IFLT, IFGE), (IFGT, IFLE), (IF_ICMPEQ, IF_ICMPNE), (IF_ICMPLT, IF_ICMPGE), (IF_ICMPGT, IF_ICMPLE), (IFNULL, IFNONNULL), (IF_ACMPEQ, IF_ACMPNE)]:
    _ifOpposite[_op1] = _op2
    _ifOpposite[_op2] = _op1
class If(LazyJumpBase):
    def __init__(self, op, target):
        super().__init__(target)
        self.op = op
        self.min = 3
        self.max = 8 # upper limit on length of bytecode

    # Unlike with goto, if instructions are limited to a 16 bit jump offset.
    # Therefore, for larger jumps, we have to substitute a different sequence
    #
    # if x goto A
    # B: whatever
    #
    # becomes
    #
    # if !x goto B
    # goto A
    # B: whatever
    def calcBytecode(self, posd, labels):
        if self.max == 3:
            offset = posd[labels[self.target]] - posd[self]
            self.bytecode = struct.pack('>Bh', self.op, offset)
        else:
            op = _ifOpposite[self.op]
            offset = posd[labels[self.target]] - posd[self] - 3
            self.bytecode = struct.pack('>BhBi', op, 8, GOTO_W, offset)

class Switch(JvmInstruction):
    def __init__(self, default, jumps):
        super().__init__()
        self.default = default
        self.jumps = jumps

        assert(jumps)
        self.low = min(jumps)
        self.high = max(jumps)

        table_count = self.high - self.low + 1
        table_size =  4*(table_count+1)
        jump_size = 8*len(jumps)

        self.istable = jump_size > table_size
        self.nopad_size = 9 + (table_size if self.istable else jump_size)
        self.max = self.nopad_size + 3

    def fallsthrough(self): return False
    def targets(self): return sorted(set(self.jumps.values())) + [self.default]

    def calcBytecode(self, posd, labels):
        pos = posd[self]
        offset = posd[labels[self.default]] - pos
        pad = (-pos-1) % 4

        bytecode = bytearray()
        if self.istable:
            bytecode += bytes([TABLESWITCH] + [0]*pad)
            bytecode += struct.pack('>iii', offset, self.low, self.high)
            for k in range(self.low, self.high + 1):
                target = self.jumps.get(k, self.default)
                bytecode += struct.pack('>i', posd[labels[target]] - pos)
        else:
            bytecode += bytes([LOOKUPSWITCH] + [0]*pad)
            bytecode += struct.pack('>iI', offset, len(self.jumps))
            for k, target in sorted(self.jumps.items()):
                offset = posd[labels[target]] - pos
                bytecode += struct.pack('>ii', k, offset)
        self.bytecode = bytes(bytecode)

_return_or_throw_bytecodes = {bytes([op]) for op in range(IRETURN, RETURN+1) }
_return_or_throw_bytecodes.add(bytes([ATHROW]))
class Other(JvmInstruction):
    def fallsthrough(self): return self.bytecode not in _return_or_throw_bytecodes
