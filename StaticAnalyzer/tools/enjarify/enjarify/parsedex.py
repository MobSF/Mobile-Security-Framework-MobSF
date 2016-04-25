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

import array

from .byteio import Reader
from .dalvik import parseBytecode
from .util import signExtend

NO_INDEX = 0xFFFFFFFF

def typeList(dex, off, parseClsDesc=False):
    if off == 0:
        return []
    size = dex.u32s[off//4]
    u16_off = (off//4 + 1) * 2
    idxs = dex.u16s[u16_off:u16_off+size]
    func = dex.clsType if parseClsDesc else dex.type
    return list(map(func, idxs))

def encodedValue(dex, stream):
    tag = stream.u8()
    vtype, varg = tag & 31, tag >> 5

    if vtype == 0x1c: # ARRAY
        size = stream.uleb128()
        return [encodedValue(dex, stream) for _ in range(size)]
    if vtype == 0x1d: # ANNOTATION
        # We don't actually care about annotations but still need to read it to
        # find out how much data is taken up
        stream.uleb128()
        for _ in range(stream.uleb128()):
            stream.uleb128()
            encodedValue(dex, stream)
        return None
    if vtype == 0x1e: # NULL
        return None

    # For the rest, we just return it as unsigned integers without recording type
    # extended to either u32 or u64 depending on int/float or long/double
    if vtype == 0x1f: # BOOLEAN
        return b'I', varg
    # the rest are an int encoded into varg + 1 bytes in some way
    size = varg + 1
    val = sum(stream.u8() << (i*8) for i in range(size))

    if vtype == 0x00: # BYTE
        return b'I', signExtend(val, 8) % (1<<32)
    if vtype == 0x02: # SHORT
        return b'I', signExtend(val, 16) % (1<<32)
    if vtype == 0x03: # CHAR
        return b'I', val
    if vtype == 0x04: # INT
        return b'I', val

    if vtype == 0x06: # LONG
        return b'J', val

    # floats are 0 extended to the right
    if vtype == 0x10: # FLOAT
        return b'F', val << (32 - size * 8)
    if vtype == 0x11: # DOUBLE
        return b'D', val << (64 - size * 8)

    if vtype == 0x17: # STRING
        return b'Ljava/lang/String;', dex.string(val)
    if vtype == 0x18: # TYPE
        return b'Ljava/lang/Class;', dex.clsType(val)

class MFIdMixin:
    def triple(self): return self.cname, self.name, self.desc

class FieldId(MFIdMixin):
    def __init__(self, dex, field_idx):
        stream = dex.stream(dex.field_ids.off + field_idx * 8)
        self.cname = dex.clsType(stream.u16())
        self.desc = dex.type(stream.u16())
        self.name = dex.string(stream.u32())

class Field:
    def __init__(self, dex, field_idx, access):
        self.dex = dex
        self.id = FieldId(dex, field_idx)
        self.access = access
        self.constant_value = None # will be set later

class MethodId(MFIdMixin):
    def __init__(self, dex, method_idx):
        stream = dex.stream(dex.method_ids.off + method_idx * 8)
        self.cname = dex.clsType(stream.u16())
        proto_idx = stream.u16()
        self.name = dex.string(stream.u32())
        off = (dex.proto_ids.off + proto_idx * 12)//4
        shorty_idx, return_idx, parameters_off = dex.u32s[off:off+3]
        self.return_type = dex.type(return_idx)
        self.param_types = typeList(dex, parameters_off)

        # rearrange things to Java format
        parts = [b'('] + self.param_types + [b')', self.return_type]
        self.desc = b''.join(parts)

    def getSpacedParamTypes(self, isstatic):
        results = []
        if not isstatic:
            if self.cname.startswith(b'['):
                results.append(self.cname)
            else:
                results.append(b'L' + self.cname + b';')

        for ptype in self.param_types:
            results.append(ptype)
            if ptype == b'J' or ptype == b'D':
                results.append(None)
        return results

class TryItem:
    def __init__(self, stream):
        self.start, self.count, self.handler_off = stream.u32(), stream.u16(), stream.u16()
        self.end = self.start + self.count
        self.catches = None # to be filled in later

    def finish(self, dex, list_off):
        stream = dex.stream(list_off + self.handler_off)
        size = stream.sleb128()
        self.catches = results = []
        for _ in range(abs(size)):
            results.append((dex.clsType(stream.uleb128()), stream.uleb128()))
        if size <= 0:
            results.append((b'java/lang/Throwable', stream.uleb128()))

class CodeItem:
    def __init__(self, dex, offset):
        stream = dex.stream(offset)
        self.nregs = registers_size = stream.u16()
        ins_size = stream.u16()
        outs_size = stream.u16()
        tries_size = stream.u16()
        debug_off = stream.u32()
        self.insns_size = stream.u32()
        insns_start_pos = stream.pos
        insns = [stream.u16() for _ in range(self.insns_size)]
        if tries_size and self.insns_size & 1:
            stream.u16() # padding
        self.tries = [TryItem(stream) for _ in range(tries_size)]
        self.list_off = stream.pos
        for item in self.tries:
            item.finish(dex, self.list_off)

        catch_addrs = set()
        for tryi in self.tries:
            catch_addrs.update(t[1] for t in tryi.catches)
        self.bytecode = parseBytecode(dex, insns_start_pos, insns, catch_addrs)

class Method:
    def __init__(self, dex, method_idx, access, code_off):
        self.dex = dex
        self.id = MethodId(dex, method_idx)
        self.access = access
        self.code_off = code_off
        self.code = CodeItem(dex, code_off) if code_off else None

class ClassData:
    def __init__(self, dex, offset):
        self.fields = []
        self.methods = []
        # for offset 0, leave dummy data with no fields or methods
        if offset != 0:
            self._parse(dex, dex.stream(offset))

    def _parse(self, dex, stream):
        numstatic = stream.uleb128()
        numinstance = stream.uleb128()
        numdirect = stream.uleb128()
        numvirtual = stream.uleb128()

        fields = self.fields
        for num in (numstatic, numinstance):
            field_idx = 0
            for i in range(num):
                field_idx += stream.uleb128()
                fields.append(Field(dex, field_idx, stream.uleb128()))

        methods = self.methods
        for num in (numdirect, numvirtual):
            method_idx = 0
            for i in range(num):
                method_idx += stream.uleb128()
                methods.append(Method(dex, method_idx, stream.uleb128(), stream.uleb128()))

class DexClass:
    def __init__(self, dex, base_off, i):
        self.dex = dex
        offset = base_off//4 + i*8
        words = dex.u32s[offset:offset+8]
        self.name = dex.clsType(words[0])
        self.access = words[1]
        self.super = dex.clsType(words[2]) if words[2] != NO_INDEX else None
        self.interfaces = typeList(dex, words[3], parseClsDesc=True)
        # ignore sourcefile for now
        # ignore annotations for now
        self.data_off = words[6]
        self.data = None # parse data lazily in parseData()
        self.constant_values_off = words[7]

    def parseData(self):
        if self.data is None:
            self.data = ClassData(self.dex, self.data_off)
            if self.constant_values_off:
                stream = self.dex.stream(self.constant_values_off)
                size = stream.uleb128()
                constant_vals = [encodedValue(self.dex, stream) for _ in range(size)]
                for field, val in zip(self.data.fields, constant_vals):
                    field.constant_value = val

class SizeOff:
    def __init__(self, stream):
        self.size = stream.u32()
        self.off = stream.u32()

class DexFile:
    def __init__(self, data):
        self.raw = data
        self.u16s = array.array('H', data[:len(data) & ~1])
        assert(self.u16s.itemsize == 2)
        self.u32s = array.array('I', data[:len(data) & ~3])
        assert(self.u32s.itemsize == 4)

        stream = Reader(data)

        # parse header
        stream.read(36)
        if stream.u32() != 0x70:
            print('Warning, unexpected header size!')
        if stream.u32() != 0x12345678:
            print('Warning, unexpected endianess tag!')

        self.link = SizeOff(stream)
        self.map_off = stream.u32()
        self.string_ids = SizeOff(stream)
        self.type_ids = SizeOff(stream)
        self.proto_ids = SizeOff(stream)
        self.field_ids = SizeOff(stream)
        self.method_ids = SizeOff(stream)
        self.class_defs = SizeOff(stream)
        self.data = SizeOff(stream)

        defs = self.class_defs
        self.classes = []
        for i in range(defs.size):
            self.classes.append(DexClass(self, defs.off, i))

    def stream(self, offset): return Reader(self.raw, offset)

    def string(self, i):
        data_off = self.u32s[self.string_ids.off//4 + i]
        stream = self.stream(data_off)
        stream.uleb128() # ignore decoded length
        return stream.readCStr()

    def type(self, i):
        if 0 <= i < NO_INDEX:
            return self.string(self.u32s[self.type_ids.off//4 + i])

    def clsType(self, i):
        # Can be either class _name_ or array _descriptor_
        desc = self.type(i)
        if desc.startswith(b'['):
            return desc
        elif desc.startswith(b'L'):
            return desc[1:-1]

    def field_id(self, i): return FieldId(self, i)
    def method_id(self, i): return MethodId(self, i)
