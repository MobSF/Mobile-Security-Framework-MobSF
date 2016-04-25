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

# Primative type inference
# In dalvik bytecode, constants are untyped, which effectively means a union type
# They can be zero (int/float/null), narrow (int/float) or wide (long/double)

INVALID = 0
INT = 1 << 0
FLOAT = 1 << 1
OBJ = 1 << 2
LONG = 1 << 3
DOUBLE = 1 << 4

ZERO = INT | FLOAT | OBJ
C32 = INT | FLOAT
C64 = LONG | DOUBLE
ALL = ZERO | C64

_descToScalar = dict(zip(map(ord, 'ZBCSIFJDL['), [INT, INT, INT, INT, INT, FLOAT, LONG, DOUBLE, OBJ, OBJ]))
def fromDesc(desc):
    return _descToScalar[desc[0]]

def iswide(st):
    return st & C64

def paramTypes(method_id, static):
    temp = method_id.getSpacedParamTypes(static)
    return [(INVALID if desc is None else fromDesc(desc)) for desc in temp]
