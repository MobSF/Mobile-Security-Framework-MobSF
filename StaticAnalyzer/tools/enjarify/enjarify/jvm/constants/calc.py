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

from ...util import s16, s32, s64
from .. import scalartypes as scalars
from ..jvmops import *

from . import lookup
from .genlookup import FLOAT_SIGN, FLOAT_INF, FLOAT_NINF, FLOAT_NAN, DOUBLE_SIGN, DOUBLE_INF, DOUBLE_NINF, DOUBLE_NAN

# Calculate a sequence of bytecode instructions to generate the given constant
# to be used in the rare case that the constant pool is full.

# NaN has multiple representations, so normalize Floats to a single NaN representation
def normalizeFloat(x):
    x %= 1<<32
    if x | FLOAT_SIGN > FLOAT_NINF:
        return FLOAT_NAN
    return x

def normalizeDouble(x):
    x %= 1<<64
    if x | DOUBLE_SIGN > DOUBLE_NINF:
        return DOUBLE_NAN
    return x

def _calcInt(x):
    assert(x == s32(x))
    if x in lookup.INTS:
        return lookup.INTS[x]

    # max required - 10 bytes
    # (high << 16) ^ low
    low = s16(x)
    high = (x ^ low) >> 16
    assert(high)
    if not low:
        return _calcInt(high) + _calcInt(16) + bytes([ISHL])
    return _calcInt(high) + _calcInt(16) + bytes([ISHL]) + _calcInt(low) + bytes([IXOR])

def _calcLong(x):
    assert(x == s64(x))
    if x in lookup.LONGS:
        return lookup.LONGS[x]

    # max required - 26 bytes
    # (high << 32) ^ low
    low = s32(x)
    high = (x ^ low) >> 32
    if not high:
        return _calcInt(low) + bytes([I2L])

    result = _calcInt(high) + bytes([I2L]) + _calcInt(32) + bytes([LSHL])
    if low:
        result += _calcInt(low) + bytes([I2L, LXOR])
    return result

def _calcFloat(x):
    assert(x == normalizeFloat(x))
    if x in lookup.FLOATS:
        return lookup.FLOATS[x]

    # max required - 27 bytes
    exponent = ((x >> 23) & 0xFF) - 127
    mantissa = x % (1<<23)
    # check for denormals!
    if exponent == -127:
        exponent += 1
    else:
        mantissa += 1<<23
    exponent -= 23

    if x & FLOAT_SIGN:
        mantissa = -mantissa

    ex_combine_op = FDIV if exponent < 0 else FMUL
    exponent = abs(exponent)
    exponent_parts = bytearray()
    while exponent >= 63: # max 2 iterations since -149 <= exp <= 104
        exponent_parts.extend([LCONST_1, ICONST_M1, LSHL, L2F, ex_combine_op])
        mantissa = -mantissa
        exponent -= 63

    if exponent > 0:
        exponent_parts.append(LCONST_1)
        exponent_parts.extend(_calcInt(exponent))
        exponent_parts.extend([LSHL, L2F, ex_combine_op])
    return _calcInt(mantissa) + bytes([I2F]) + exponent_parts

def _calcDouble(x):
    assert(x == normalizeDouble(x))
    if x in lookup.DOUBLES:
        return lookup.DOUBLES[x]

    # max required - 55 bytes
    exponent = ((x >> 52) & 0x7FF) - 1023
    mantissa = x % (1<<52)
    # check for denormals!
    if exponent == -1023:
        exponent += 1
    else:
        mantissa += 1<<52
    exponent -= 52

    if x & DOUBLE_SIGN:
        mantissa = -mantissa

    abs_exponent = abs(exponent)
    exponent_parts = bytearray()

    part63 = abs_exponent // 63
    if part63: #create *63 part of exponent by repeated squaring
        # use 2^-x instead of calculating 2^x and dividing to avoid overflow in
        # case we need 2^-1071
        if exponent < 0: # -2^-63
            exponent_parts.extend([DCONST_1, LCONST_1, ICONST_M1, LSHL, L2D, DDIV])
        else: # -2^63
            exponent_parts.extend([LCONST_1, ICONST_M1, LSHL, L2D])
        # adjust sign of mantissa for odd powers since we're actually using -2^63 rather than positive
        if part63 & 1:
            mantissa = -mantissa

        last_needed = part63 & 1
        stack = [1] # Not actually required to compute the results - it's just used for a sanity check
        for bi in range(1, part63.bit_length()):
            exponent_parts.append(DUP2)
            stack.append(stack[-1])
            if last_needed:
                exponent_parts.append(DUP2)
                stack.append(stack[-1])
            exponent_parts.append(DMUL)
            stack.append(stack.pop() + stack.pop())
            last_needed = part63 & (1<<bi)

        assert(sum(stack) == part63 and len(stack) == bin(part63).count('1'))
        exponent_parts.extend([DMUL] * bin(part63).count('1'))

    # now handle the rest
    rest = abs_exponent % 63
    if rest:
        exponent_parts.append(LCONST_1)
        exponent_parts.extend(_calcInt(rest))
        exponent_parts.extend([LSHL, L2D])
        exponent_parts.append(DDIV if exponent < 0 else DMUL)

    return _calcLong(mantissa) + bytes([L2D]) + exponent_parts

def calcInt(x): return _calcInt(s32(x))
def calcLong(x): return _calcLong(s64(x))
def calcFloat(x): return _calcFloat(normalizeFloat(x))
def calcDouble(x): return _calcDouble(normalizeDouble(x))

def normalize(st, val):
    if st == scalars.FLOAT:
        return normalizeFloat(val)
    elif st == scalars.DOUBLE:
        return normalizeDouble(val)
    return val

def calc(st, val):
    if st == scalars.INT:
        return calcInt(val)
    elif st == scalars.FLOAT:
        return calcFloat(val)
    elif st == scalars.LONG:
        return calcLong(val)
    elif st == scalars.DOUBLE:
        return calcDouble(val)
    assert(0)

def lookupOnly(st, val):
    # assume floats and double have already been normalized but int/longs haven't
    if st == scalars.INT:
        return lookup.INTS.get(s32(val))
    elif st == scalars.FLOAT:
        return lookup.FLOATS.get(val)
    elif st == scalars.LONG:
        return lookup.LONGS.get(s64(val))
    elif st == scalars.DOUBLE:
        return lookup.DOUBLES.get(val)
