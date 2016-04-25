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

from .. import ir
from ..jvmops import *

def _calcMinimumPositions(instrs):
    posd = {}
    pos = 0
    for ins in instrs:
        posd[ins] = pos
        if isinstance(ins, ir.LazyJumpBase):
            pos += ins.min
        elif isinstance(ins, ir.Switch):
            pad = (-pos-1) % 4
            pos += pad + ins.nopad_size
        else:
            pos += len(ins.bytecode)
    return posd, pos

def optimizeJumps(irdata):
    # For jump offsets of more than +-32767, a longer form of the jump instruction
    # is required. This function finds the optimal jump widths by optimistically
    # starting with everything narrow and then iteratively marking instructions
    # as wide if their offset is too large (in rare cases, this can in turn cause
    # other jumps to become wide, hence iterating until convergence)
    instrs = irdata.flat_instructions
    jump_instrs = [ins for ins in instrs if isinstance(ins, ir.LazyJumpBase)]

    while 1:
        done = True
        posd, _ = _calcMinimumPositions(instrs)

        for ins in jump_instrs:
            if ins.min < ins.max and ins.widenIfNecessary(irdata.labels, posd):
                done = False
        if done:
            break

    for ins in jump_instrs:
        assert(ins.min <= ins.max)
        ins.max = ins.min

def createBytecode(irdata):
    instrs = irdata.flat_instructions
    posd, end_pos = _calcMinimumPositions(instrs)

    bytecode = bytearray()
    for ins in instrs:
        if isinstance(ins, (ir.LazyJumpBase, ir.Switch)):
            ins.calcBytecode(posd, irdata.labels)
        bytecode += ins.bytecode
    assert(len(bytecode) == end_pos)

    prev_instr_map = dict(zip(instrs[1:], instrs))
    packed_excepts = []
    for s, e, h, c in irdata.excepts:
        # There appears to be a bug in the JVM where in rare cases, it throws
        # the exception at the address of the instruction _before_ the instruction
        # that actually caused the exception, triggering the wrong handler
        # therefore we include the previous (IR) instruction too
        # Note that this cannot cause an overlap because in that case the previous
        # instruction would just be a label and hence not change anything
        s = prev_instr_map.get(s, s)

        s_off = posd[s]
        e_off = posd[e]
        h_off = posd[h]
        assert(s_off <= e_off)
        if s_off < e_off:
            packed_excepts.append(struct.pack('>HHHH', s_off, e_off, h_off, c))
        else:
            print('Skipping zero width exception!')
            assert(0)

    return bytes(bytecode), packed_excepts
