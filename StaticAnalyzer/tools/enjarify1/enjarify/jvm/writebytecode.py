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

from ..byteio import Writer
from . import writeir, ir, error
from .optimization import registers, jumps, stack, consts, options

def getCodeIR(pool, method, opts):
    if method.code is not None:
        irdata = writeir.writeBytecode(pool, method, opts)

        if opts.inline_consts:
            stack.inlineConsts(irdata)

        if opts.copy_propagation:
            registers.copyPropagation(irdata)

        if opts.remove_unused_regs:
            registers.removeUnusedRegisters(irdata)

        if opts.dup2ize:
            stack.dup2ize(irdata)

        if opts.prune_store_loads:
            stack.pruneStoreLoads(irdata)
            if opts.remove_unused_regs:
                registers.removeUnusedRegisters(irdata)

        if opts.sort_registers:
            registers.sortAllocateRegisters(irdata)
        else:
            registers.simpleAllocateRegisters(irdata)
        return irdata
    return None

def finishCodeAttrs(pool, code_irs, opts):
    code_irs = [x for x in code_irs if x is not None]
    # if we have any code, make sure to reserve pool slot for attr name
    if code_irs:
        pool.utf8(b"Code")

    if opts.delay_consts:
        # In the rare case where the class references too many constants to fit in
        # the constant pool, we can workaround this by replacing primative constants
        # e.g. ints, longs, floats, and doubles, with a sequence of bytecode instructions
        # to generate that constant. This obviously increases the size of the method's
        # bytecode, so we ideally only want to do it to constants in short methods.

        # First off, we find which methods are potentially too long. If a method
        # will be under 65536 bytes even with all constants replaced, then it
        # will be ok no matter what we do.
        long_irs = []
        for _ir in code_irs:
            if _ir.calcUpperBound() >= 65536:
                long_irs.append(_ir)

        # Now allocate constants used by potentially long methods
        if long_irs:
            consts.allocateRequiredConstants(pool, long_irs)

        # If there's space left in the constant pool, allocate constants used by short methods
        for _ir in code_irs:
            for ins in _ir.flat_instructions:
                if isinstance(ins, ir.PrimConstant):
                    ins.fix_with_pool(pool)

    return {irdata.method: writeCodeAttributeTail(pool, irdata, opts=opts) for irdata in code_irs}

def writeCodeAttributeTail(pool, irdata, opts):
    method = irdata.method
    jumps.optimizeJumps(irdata)
    bytecode, excepts = jumps.createBytecode(irdata)

    stream = Writer()
    # For simplicity, don't bother calculating the actual maximum stack height
    # of the generated code. Instead, just use a value that will always be high
    # enough. Note that just setting this to 65535 is a bad idea since it tends
    # to cause StackOverflowErrors under default JVM memory settings
    stream.u16(300) # stack
    stream.u16(irdata.numregs) # locals

    stream.u32(len(bytecode))
    stream.write(bytecode)

    if len(bytecode) > 65535:
        # If code is too long and optimization is off, raise exception so we can
        # retry with optimization. If it is still too long with optimization,
        # don't raise an error, since a class with illegally long code is better
        # than no output at all.
        if opts is not options.ALL:
            raise error.ClassfileLimitExceeded()

    # exceptions
    stream.u16(len(excepts))
    stream.write(b''.join(excepts))

    # attributes
    stream.u16(0)
    return stream
