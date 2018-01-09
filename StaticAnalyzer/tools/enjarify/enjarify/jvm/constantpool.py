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

from . import error

CONSTANT_Class = 7
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String = 8
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6
CONSTANT_NameAndType = 12
CONSTANT_Utf8 = 1
# CONSTANT_MethodHandle = 15
# CONSTANT_MethodType = 16
# CONSTANT_InvokeDynamic = 18
MAX_CONST = CONSTANT_NameAndType

def _width(tag):
    return 2 if tag in (CONSTANT_Long, CONSTANT_Double) else 1

class ConstantPoolBase:
    def __init__(self):
        # lookup dicts for deduplicating constants
        self.lookup = [{} for _ in range(MAX_CONST + 1)]

    def _get(self, tag, args):
        d = self.lookup[tag]
        try:
            return d[args]
        except KeyError:
            low = tag in (CONSTANT_Integer, CONSTANT_Float, CONSTANT_String)
            d[args] = index = self._getInd(low, _width(tag))

            assert(self.vals[index] is None)
            self.vals[index] = tag, args
        return d[args]

    def insertDirectly(self, pair, low):
        tag, x = pair
        d = self.lookup[tag]
        d[x] = index = self._getInd(low, _width(tag))
        self.vals[index] = pair

    def tryGet(self, pair):
        tag, x = pair
        d = self.lookup[tag]
        try:
            return d[x]
        except KeyError:
            pass
        width = _width(tag)
        if width > self.space():
            return None
        d[x] = index = self._getInd(True, width)
        self.vals[index] = pair
        return index

    def utf8(self, s):
        assert(isinstance(s, bytes))
        if len(s) > 65535:
            raise error.ClassfileLimitExceeded()
        return self._get(CONSTANT_Utf8, s)

    def class_(self, s): return self._get(CONSTANT_Class, self.utf8(s))
    def string(self, s): return self._get(CONSTANT_String, self.utf8(s))

    def nat(self, name, desc):
        return self._get(CONSTANT_NameAndType, (self.utf8(name), self.utf8(desc)))

    def _triple(self, tag, trip):
        return self._get(tag, (self.class_(trip[0]), self.nat(trip[1], trip[2])))

    def field(self, trip): return self._triple(CONSTANT_Fieldref, trip)
    def method(self, trip): return self._triple(CONSTANT_Methodref, trip)
    def imethod(self, trip): return self._triple(CONSTANT_InterfaceMethodref, trip)

    def int(self, x): return self._get(CONSTANT_Integer, x)
    def float(self, x): return self._get(CONSTANT_Float, x)
    def long(self, x): return self._get(CONSTANT_Long, x)
    def double(self, x): return self._get(CONSTANT_Double, x)

    def _writeEntry(self, stream, item):
        if item is None:
            return
        tag, val = item
        stream.u8(tag)

        if tag == CONSTANT_Utf8:
            stream.u16(len(val))
            stream.write(val)
        elif tag in (CONSTANT_Integer, CONSTANT_Float):
            stream.u32(val)
        elif tag in (CONSTANT_Long, CONSTANT_Double):
            stream.u64(val)
        elif tag in (CONSTANT_Class, CONSTANT_String):
            stream.u16(val)
        else:
            stream.u16(val[0])
            stream.u16(val[1])

# A simple constant pool that just allocates slots in increasing order.
class SimpleConstantPool(ConstantPoolBase):
    def __init__(self):
        super().__init__()
        self.vals = [None]

    def space(self): return 65535 - len(self.vals)
    def lowspace(self): return 256 - len(self.vals)

    def _getInd(self, low, width):
        if self.space() < width:
            raise error.ClassfileLimitExceeded()
        temp = len(self.vals)
        self.vals += [None]*width
        return temp

    def write(self, stream):
        stream.u16(len(self.vals))
        for item in self.vals:
            self._writeEntry(stream, item)

# Constant pool slots 1-255 are special because they can be referred to by the
# two byte ldc instruction (as opposed to 3 byte ldc_w/ldc2_w). Therefore, it is
# desireable to allocate constants which could use ldc in the first 255 slots,
# while not wasting these valuable low slots with pool entries that can't use
# ldc (utf8s, longs, etc.)
# One possible approach is to allocate the ldc entries starting at 1 and the
# others starting at 256, (possibly leaving a gap if there are less than 255 of
# the former). However, this is not ideal because the empty slots are not
# continguous. This means that you could end up in the sitatuation where there
# are exactly two free slots and you wish to add a long/double entry but the
# free slots are not continguous.
# To solve this, we take a different approach - always create the pool as the
# largest possible size (65534 entries) and allocate the non-ldc constants
# starting from the highest index and counting down. This ensures that the free
# slots are always contiguous. Since the classfile representation doesn't
# actually allow gaps like that, the empty spaces if any are filled in with
# dummy entries at the end.
# For simplicity, we always allocate ints, floats, and strings in the low entries
# and everything else in the high entries, regardless of whether they are actaully
# referenced by a ldc or not. (see ConstantPoolBase._get)

# Fill in unused space with shortest possible item (Utf8 ''), preencoded for efficiency
PLACEHOLDER_ENTRY = struct.pack('>BH', CONSTANT_Utf8, 0)
class SplitConstantPool(ConstantPoolBase):
    def __init__(self):
        super().__init__()
        self.vals = [None]*65535
        self.bot = 1
        self.top = len(self.vals)

    def space(self): return self.top - self.bot
    def lowspace(self): return 256 - self.bot

    def _getInd(self, low, width):
        if self.space() < width:
            raise error.ClassfileLimitExceeded()
        if low:
            self.bot += width
            return self.bot - width
        self.top -= width
        return self.top

    def write(self, stream):
        stream.u16(len(self.vals))

        assert(self.bot <= self.top)
        for item in self.vals[:self.bot]:
            self._writeEntry(stream, item)

        stream.write(PLACEHOLDER_ENTRY * self.space())

        for item in self.vals[self.top:]:
            self._writeEntry(stream, item)
