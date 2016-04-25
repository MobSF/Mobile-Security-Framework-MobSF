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

import struct, itertools

from ..jvmops import *
from ...util import s32

# Create a precomputed lookup table giving the bytecode sequence to generate
# any primative constant of 3 bytes or less plus special float values (negative
# infinity requires 4 bytes but is included anyway to simplify things elsewhere)
#
# For example
# 128 -> sipush 128
# -65535 -> iconst_m1 i2c ineg
# 2147483647 -> iconst_m1 iconst_m1 iushr
# 1L -> lconst_1
# 127L -> bipush 127 i2l
# 42.0f -> bipush 42 i2f
# -Inf -> dconst_1 dneg dconst_0 ddiv
#
# Lookup table keys are s32/s64 for ints/longs and u32/u64 for floats/doubles
# There are multiple NaN representations, so we normalize NaNs to the
# representation of all 1s (e.g. float NaN = 0xFFFFFFFF)

def u32(x): return x % (1<<32)
def u64(x): return x % (1<<64)

FLOAT_SIGN = 1<<31
FLOAT_NAN = u32(-1)
FLOAT_INF = 0xFF << 23
FLOAT_NINF = FLOAT_INF ^ FLOAT_SIGN
def i2f(x):
    if x == 0:
        return 0
    if x < 0:
        return i2f(-x) ^ FLOAT_SIGN
    shift = 24 - x.bit_length()
    # Don't bother implementing rounding since we'll only convert small ints
    # that can be exactly represented anyway
    assert(shift >= 0)
    mantissa = x << shift
    exponent = shift + 127
    return (exponent << 23) | mantissa

DOUBLE_SIGN = 1<<63
DOUBLE_NAN = u64(-1)
DOUBLE_INF = 0x7FF << 52
DOUBLE_NINF = DOUBLE_INF ^ DOUBLE_SIGN
def i2d(x):
    if x == 0:
        return 0
    if x < 0:
        return i2d(-x) ^ DOUBLE_SIGN
    shift = 53 - x.bit_length()
    assert(shift >= 0)
    mantissa = x << shift
    exponent = shift + 1023
    return (exponent << 52) | mantissa

# add if value is shorter then current best
def add(d, k, v):
    if k not in d or len(v) < len(d[k]):
        d[k] = v

if __name__ == "__main__":
    # int constants
    all_ints = {}

    # 1 byte ints
    for i in range(-1, 6):
        add(all_ints, i, bytes([ICONST_0 + i]))
    # Sort for determinism. Otherwise -0x80000000 could be either
    # 1 << -1 or -1 << -1, for example
    int_1s = sorted({k for k,v in all_ints.items() if len(v) == 1})

    # 2 byte ints
    for i in range(-128, 128):
        add(all_ints, i, struct.pack('>Bb', BIPUSH, i))
    for i in int_1s:
        add(all_ints, i % 65536, all_ints[i] + bytes([I2C]))
    int_2s = sorted({k for k,v in all_ints.items() if len(v) == 2})

    # 3 byte ints
    for i in range(-32768, 32768):
        add(all_ints, i, struct.pack('>Bh', SIPUSH, i))
    for i in int_2s:
        add(all_ints, i % 65536, all_ints[i] + bytes([I2C]))
        add(all_ints, s32(-i), all_ints[i] + bytes([INEG]))
    for x, y in itertools.product(int_1s, int_1s):
        add(all_ints, s32(x << (y % 32)), all_ints[x] + all_ints[y] + bytes([ISHL]))
        add(all_ints, s32(x >> (y % 32)), all_ints[x] + all_ints[y] + bytes([ISHR]))
        add(all_ints, s32(u32(x) >> (y % 32)), all_ints[x] + all_ints[y] + bytes([IUSHR]))

    # long constants
    all_longs = {}
    for i in range(0, 2):
        add(all_longs, i, bytes([LCONST_0 + i]))

    for i in int_1s + int_2s:
        add(all_longs, i, all_ints[i] + bytes([I2L]))

    # float constants
    all_floats = {}
    for i in range(0, 2):
        add(all_floats, i2f(i), bytes([FCONST_0 + i]))

    for i in int_1s + int_2s:
        add(all_floats, i2f(i), all_ints[i] + bytes([I2F]))

    # hardcode unusual float values for simplicity
    add(all_floats, FLOAT_SIGN, bytes([FCONST_0, FNEG])) # -0.0
    add(all_floats, FLOAT_NAN, bytes([FCONST_0, FCONST_0, FDIV])) # NaN
    add(all_floats, FLOAT_INF, bytes([FCONST_1, FCONST_0, FDIV])) # Inf
    add(all_floats, FLOAT_NINF, bytes([FCONST_1, FNEG, FCONST_0, FDIV])) # -Inf

    # double constants
    all_doubles = {}
    for i in range(0, 2):
        add(all_doubles, i2d(i), bytes([DCONST_0 + i]))

    for i in int_1s + int_2s:
        add(all_doubles, i2d(i), all_ints[i] + bytes([I2D]))

    add(all_doubles, DOUBLE_SIGN, bytes([DCONST_0, DNEG])) # -0.0
    add(all_doubles, DOUBLE_NAN, bytes([DCONST_0, DCONST_0, DDIV])) # NaN
    add(all_doubles, DOUBLE_INF, bytes([DCONST_1, DCONST_0, DDIV])) # Inf
    add(all_doubles, DOUBLE_NINF, bytes([DCONST_1, DNEG, DCONST_0, DDIV])) # -Inf

    print('''
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

# Autogenerated by genlookup.py - do not edit''')

    for name, d in zip('INTS LONGS FLOATS DOUBLES'.split(), [all_ints, all_longs, all_floats, all_doubles]):
        print(name + ' = {')
        for k, v in sorted(d.items()):
            print('    {}: {},'.format(hex(k), v))
        print('}')