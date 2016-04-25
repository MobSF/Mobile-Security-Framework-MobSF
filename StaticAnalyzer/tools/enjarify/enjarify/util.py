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

def keysToRanges(d, limit):
    starts = sorted(d)
    for s, e in zip(starts, starts[1:] + [limit]):
        for k in range(s, e):
            d[k] = d[s]
    return d

def signExtend(val, size):
    if val & (1 << (size-1)):
        val -= (1 << size)
    return val

def s16(val):
    val %= 1 << 16
    if val >= 1 << 15:
        val -= 1 << 16
    return val

def s32(val):
    val %= 1 << 32
    if val >= 1 << 31:
        val -= 1 << 32
    return val

def s64(val):
    val %= 1 << 64
    if val >= 1 << 63:
        val -= 1 << 64
    return val
