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

from .. import ir
from ..jvmops import *

_dup = bytes([DUP])
_dup2 = bytes([DUP2])
_pop = bytes([POP])
_pop2 = bytes([POP2])

def visitLinearCode(irdata, visitor):
    # Visit linear sections of code, pessimistically treating all exception
    # handler ranges as jumps.
    except_level = 0
    for instr in irdata.flat_instructions:
        if instr in irdata.except_starts:
            except_level += 1
            visitor.visitExceptionRange()
        elif instr in irdata.except_ends:
            except_level -= 1

        if except_level > 0:
            continue

        if instr in irdata.jump_targets or isinstance(instr, (ir.LazyJumpBase, ir.Switch)):
            visitor.visitJumpTargetOrBranch(instr)
        elif not instr.fallsthrough():
            visitor.visitReturn()
        else:
            visitor.visit(instr)
    assert(except_level == 0)
    return visitor

class NoExceptVisitorBase:
    def visitExceptionRange(self): self.reset()
    def visitJumpTargetOrBranch(self, instr): self.reset()

class ConstInliner(NoExceptVisitorBase):
    def __init__(self):
        self.uses = {}
        self.notmultiused = set()
        self.current = {}

    def reset(self):
        self.current = {}

    def visitReturn(self):
        for key in self.current:
            self.notmultiused.add(self.current[key])
        self.reset()

    def visit(self, instr):
        if isinstance(instr, ir.RegAccess):
            key = instr.key
            if instr.store:
                if key in self.current:
                    self.notmultiused.add(self.current[key])
                self.current[key] = instr
            elif key in self.current:
                # if currently used 0, mark it used once
                # if used once already, mark it as multiused
                if self.current[key] in self.uses:
                    del self.current[key]
                else:
                    self.uses[self.current[key]] = instr

def inlineConsts(irdata):
    # Inline constants which are only used once or not at all. This only covers
    # linear sections of code and pessimistically assumes everything is used
    # when it reaches a jump or exception range. Essentially, this means that
    # the value can only be considered unused if it is either overwritten by a
    # store or reaches a return or throw before any jumps.
    # As usual, assume no iinc.
    instrs = irdata.flat_instructions
    visitor = visitLinearCode(irdata, ConstInliner())

    remove = set()
    replace = {}
    for ins1, ins2 in zip(instrs, instrs[1:]):
        if ins2 in visitor.notmultiused and isinstance(ins1, (ir.PrimConstant, ir.OtherConstant)):
            replace[ins1] = []
            replace[ins2] = []
            if ins2 in visitor.uses:
                replace[visitor.uses[ins2]] = [ins1]
    irdata.replaceInstrs(replace)

class StoreLoadPruner(NoExceptVisitorBase):
    def __init__(self):
        self.current = {}
        self.last = None
        self.removed = set()

    def reset(self):
        self.current = {}
        self.last = None

    def visitReturn(self):
        for pair in self.current.values():
            assert(pair[0].store and not pair[1].store)
            self.removed.update(pair)
        self.reset()

    def visit(self, instr):
        if isinstance(instr, ir.RegAccess):
            key = instr.key
            if instr.store:
                if key in self.current:
                    pair = self.current[key]
                    assert(pair[0].store and not pair[1].store)
                    self.removed.update(self.current.pop(key))
                self.last = instr
            else:
                self.current.pop(key, None)
                if self.last and self.last.key == key:
                    self.current[key] = self.last, instr
                self.last = None
        elif not isinstance(instr, ir.Label):
            self.last = None

def pruneStoreLoads(irdata):
    # Remove a store immediately followed by a load from the same register
    # (potentially with a label in between) if it can be proven that this
    # register isn't read again. As above, this only considers linear sections of code.
    # Must not be run before dup2ize!
    data = visitLinearCode(irdata, StoreLoadPruner())
    irdata.replaceInstrs({instr:[] for instr in data.removed})

# used by writeir too
def genDups(needed, needed_after):
    # Generate a sequence of dup and dup2 instructions to duplicate the given
    # value. This keeps up to 4 copies of the value on the stack. Thanks to dup2
    # this asymptotically takes only half a byte per access.
    have = 1
    ele_count = needed
    needed += needed_after

    for _ in range(ele_count):
        cur = []
        if have < needed:
            if have == 1 and needed >= 2:
                cur.append(_dup)
                have += 1
            if have == 2 and needed >= 4:
                cur.append(_dup2)
                have += 2
        have -= 1
        needed -= 1
        yield cur
    assert(have >= needed)
    # check if we have to pop at end
    yield [_pop]*(have-needed)

# Range of instruction indexes at which a given register is read (in linear code)
class UseRange:
    def __init__(self, uses):
        self.uses = uses

    def add(self, i):
        self.uses.append(i)

    @property
    def start(self): return self.uses[0]
    @property
    def end(self): return self.uses[-1]

    def subtract(self, other):
        s, e = other.start, other.end
        left = [i for i in self.uses if i < s]
        right = [i for i in self.uses if i > e]
        if len(left) >= 2:
            yield UseRange(left)
        if len(right) >= 2:
            yield UseRange(right)

    def sortkey(self): return len(self.uses), self.uses[0]

def makeRange(instr):
    assert(isinstance(instr, ir.RegAccess) and not instr.store)
    return UseRange([])

def dup2ize(irdata):
    # This optimization replaces narrow registers which are frequently read at
    # stack height 0 with a single read followed by the more efficient dup and
    # dup2 instructions. This asymptotically uses only half a byte per access.
    # For simplicity, instead of explicitly keeping track of which locations
    # have stack height 0, we take advantage of the invariant that ranges of code
    # corresponding to a single Dalvik instruction always begin with empty stack.
    # These can be recognized by labels with a non-None id.
    # This isn't true for move-result instructions, but in that case the range
    # won't begin with a register load so it doesn't matter.
    # Note that pruneStoreLoads breaks this invariant, so dup2ize must be run first.
    # Also, for simplicity, we only keep at most one such value on the stack at
    # a time (duplicated up to 4 times).
    instrs = irdata.flat_instructions

    ranges = []
    current = {}
    at_head = False
    for i, instr in enumerate(instrs):
        # if not linear section of bytecode, reset everything. Exceptions are ok
        # since they clear the stack, but jumps obviously aren't.
        if instr in irdata.jump_targets or isinstance(instr, (ir.If, ir.Switch)):
            ranges.extend(current.values())
            current = {}

        if isinstance(instr, ir.RegAccess):
            key = instr.key
            if not instr.wide:
                if instr.store:
                    if key in current:
                        ranges.append(current.pop(key))
                elif at_head:
                    current.setdefault(key, makeRange(instr)).add(i)

        at_head = isinstance(instr, ir.Label) and instr.id is not None
    ranges.extend(current.values())
    ranges = [ur for ur in ranges if len(ur.uses) >= 2]
    ranges.sort(key=UseRange.sortkey)

    # Greedily choose a set of disjoint ranges to dup2ize.
    chosen = []
    while ranges:
        best = ranges.pop()
        chosen.append(best)
        newranges = []
        for ur in ranges:
            newranges.extend(ur.subtract(best))
        ranges = sorted(newranges, key=UseRange.sortkey)

    replace = {}
    for ur in chosen:
        gen = genDups(len(ur.uses), 0)
        for pos in ur.uses:
            ops = [ir.Other(bytecode) for bytecode in next(gen)]
            # remember to include initial load!
            if pos == ur.start:
                ops = [instrs[pos]] + ops
            replace[instrs[pos]] = ops
    irdata.replaceInstrs(replace)
