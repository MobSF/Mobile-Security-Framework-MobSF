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

import collections

from .. import ir
from .. import scalartypes as scalars
from ..jvmops import *

# Copy propagation - when one register is moved to another, keep track and replace
# all loads with loads from the original register (as long as it hasn't since been
# overwritten). Note that stores won't be removed, since they may still be needed
# in some cases, but if they are unused, they'll be removed in a subsequent pass
# As usual, assume no iincs

# A set of registers that currently are copies of each other.
class _CopySet:
    def __init__(self, key):
        self.root = key
        self.set = {key}
        self.q = [] # keep track of insertion order in case root is overwritten

    def add(self, key):
        assert(self.set)
        self.set.add(key)
        self.q.append(key)

    def remove(self, key):
        self.set.remove(key)
        # Heuristic - use oldest element still in set as new root
        while self.q and self.root not in self.set:
            self.root = self.q.pop(0)

    def copy(self):
        new = _CopySet(self.root)
        new.set = self.set.copy()
        new.q = self.q[:]
        return new

# Map registers to CopySets
class _CopySetsMap:
    def __init__(self):
        self.lookup = {}

    def _get(self, key): return self.lookup.setdefault(key, _CopySet(key))

    def clobber(self, key):
        self._get(key).remove(key)
        del self.lookup[key]

    def move(self, dest, src):
        # return false if the corresponding instructions should be removed
        s_set = self._get(src)
        d_set = self._get(dest)
        if s_set is d_set:
            # src and dest are copies of same value, so we can remove
            return False
        d_set.remove(dest)
        s_set.add(dest)
        self.lookup[dest] = s_set
        return True

    def load(self, key):
        return self._get(key).root

    def copy(self):
        copies = {}
        new = _CopySetsMap()
        for k, v in self.lookup.items():
            if v not in copies:
                copies[v] = v.copy()
            new.lookup[k] = copies[v]
        return new

def copyPropagation(irdata):
    instrs = irdata.flat_instructions
    replace = {}

    single_pred_infos = {}

    prev = None
    current = _CopySetsMap()
    for instr in instrs:
        # reset all info when control flow is merged
        if instr in irdata.jump_targets:
            # try to use info if this was a single predecessor forward jump
            if prev and not prev.fallsthrough() and irdata.target_pred_counts.get(instr) == 1:
                current = single_pred_infos.get(instr, _CopySetsMap())
            else:
                current = _CopySetsMap()

        elif isinstance(instr, ir.RegAccess):
            key = instr.key
            if instr.store:
                # check if previous instr was a load
                if isinstance(prev, ir.RegAccess) and not prev.store:
                    if not current.move(dest=key, src=prev.key):
                        replace[prev] = []
                        replace[instr] = []
                else:
                    current.clobber(key)
            else:
                root_key = current.load(key)
                if key != root_key:
                    assert(instr not in replace)
                    # replace with load from root register instead
                    replace[instr] = [ir.RegAccess(root_key[0], root_key[1], False)]

        else:
            for target in instr.targets():
                label = irdata.labels[target]
                if irdata.target_pred_counts.get(label) == 1:
                    single_pred_infos[label] = current.copy()

        prev = instr
    irdata.replaceInstrs(replace)

def _isRemoveable(instr):
    # can remove if load or const since we know there are no side effects
    # note - instr may be None
    if isinstance(instr, ir.RegAccess) and not instr.store:
        return True
    return isinstance(instr, (ir.PrimConstant, ir.OtherConstant))

def removeUnusedRegisters(irdata):
    # Remove stores to registers that are not read from anywhere in the method
    instrs = irdata.flat_instructions
    used = set()
    for instr in instrs:
        if isinstance(instr, ir.RegAccess) and not instr.store:
            used.add(instr.key)

    replace = {}
    prev = None
    for instr in instrs:
        if isinstance(instr, ir.RegAccess) and instr.key not in used:
            assert(instr.store)
            # if prev instruction is load or const, just remove it and the store
            # otherwise, replace the store with a pop
            if _isRemoveable(prev):
                replace[prev] = []
                replace[instr] = []
            else:
                op = POP2 if instr.wide else POP
                replace[instr] = [ir.Other(bytecode=bytes([op]))]
        prev = instr
    irdata.replaceInstrs(replace)

# Allocate registers to JVM registers on a first come, first serve basis
# For simplicity, parameter registers are preserved as is
def simpleAllocateRegisters(irdata):
    instrs = irdata.flat_instructions
    regmap = {v:i for i,v in enumerate(irdata.initial_args)}
    nextreg = len(irdata.initial_args)

    for instr in instrs:
        if isinstance(instr, ir.RegAccess):
            if instr.key not in regmap:
                regmap[instr.key] = nextreg
                nextreg += 1
                if instr.wide:
                    nextreg += 1
            instr.calcBytecode(regmap[instr.key])
    irdata.numregs = nextreg

# Sort registers by number of uses so that more frequently used registers will
# end up in slots 0-3 or 4-255 and benefit from the shorter instruction forms
# For simplicity, parameter registers are still preserved as is with one exception
def sortAllocateRegisters(irdata):
    instrs = irdata.flat_instructions

    use_counts = collections.Counter()
    for instr in instrs:
        if isinstance(instr, ir.RegAccess):
            use_counts[instr.key] += 1

    regs = irdata.initial_args[:]
    rest = sorted(use_counts, key=lambda k:(-use_counts[k], k))
    for key in rest:
        # If key is a param, it was already added at the beginning
        if key not in irdata.initial_args:
            regs.append(key)
            if scalars.iswide(key[1]):
                regs.append(None)

    # Sometimes the non-param regsisters are used more times than the param registers
    # and it is beneificial to swap them (which requires inserting code at the
    # beginning of the method to move the value if the param is not unused)
    # This is very complicated to do in general, so the following code only does
    # this in one specific circumstance which should nevertheless be sufficient
    # to capture the majority of the benefit
    # Specificially, it only swaps at most one register, and only in the case that
    # it is nonwide and there is a nonwide parameter in the first 4 slots that
    # it can be swapped with. Also, it doesn't bother to check if param is unused.
    candidate_i = max(4, len(irdata.initial_args))
    # make sure candidate is valid, nonwide register
    if len(regs) > candidate_i and regs[candidate_i] is not None:
        candidate = regs[candidate_i]
        if not scalars.iswide(candidate[1]) and use_counts[candidate] >= 3:
            for i in range(min(4, len(irdata.initial_args))):
                # make sure target is not wide
                if regs[i] is None or regs[i+1] is None:
                    continue

                target = regs[i]
                if use_counts[candidate] > use_counts[target] + 3:
                    # swap register assignments
                    regs[i], regs[candidate_i] = candidate, target
                    # add move instructions at beginning of method
                    load = ir.RegAccess.raw(i, target[1], False)
                    store = ir.RegAccess(target[0], target[1], True)
                    instrs = [load, store] + instrs
                    irdata.flat_instructions = instrs
                    break

    # Now generate bytecode from the selected register allocations
    irdata.numregs = len(regs)
    regmap = {v:i for i,v in enumerate(regs) if v is not None}
    for instr in instrs:
        if instr.bytecode is None and isinstance(instr, ir.RegAccess):
            instr.calcBytecode(regmap[instr.key])
