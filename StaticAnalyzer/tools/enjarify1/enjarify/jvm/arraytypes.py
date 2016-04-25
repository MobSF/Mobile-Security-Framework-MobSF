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

from . import scalartypes as scalars

# Array type inference -
# For object arrays, we don't actually care which type of object it is, so we just
# use a single value for them (INVALID) and assume all such values are an object
# array of some type. For primative arrays, we just use the entire array descriptor
# e.g. b'[[[C', except that bool arrays are treated as byte arrays.
# For null we use a special marker object

# These strings can't be valid descriptors so there's no conflict
INVALID = b'INVALID'
NULL = b'NULL'

def merge(t1, t2):
    if t1 is NULL:
        return t2
    if t2 is NULL:
        return t1
    return t1 if (t1 == t2) else INVALID

# intersect types
def narrow(t1, t2):
    if t1 is INVALID:
        return t2
    if t2 is INVALID:
        return t1
    return t1 if (t1 == t2) else NULL

def eletPair(t):
    assert(t is not NULL)
    if t is INVALID:
        return scalars.OBJ, t

    assert(t.startswith(b'['))
    t = t[1:]
    return scalars.fromDesc(t), t

def fromDesc(desc):
    if not desc.startswith(b'[') or desc.endswith(b';'):
        return INVALID
    return desc.replace(b'Z', b'B') # treat bool arrays as byte arrays
