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

from .. import flags
from ..byteio import Writer
from . import constantpool, writebytecode, error
from .optimization import options

def writeField(pool, stream, field):
    stream.u16(field.access & flags.FIELD_FLAGS)
    stream.u16(pool.utf8(field.id.name))
    stream.u16(pool.utf8(field.id.desc))
    if field.constant_value is not None:
        stream.u16(1)
        stream.u16(pool.utf8(b"ConstantValue"))
        stream.u32(2)

        ctype, val = field.constant_value
        # Ignore dalvik constant type and use actual field type instead
        index = {
            b'Z': pool.int,
            b'B': pool.int,
            b'S': pool.int,
            b'C': pool.int,
            b'I': pool.int,
            b'F': pool.float,
            b'J': pool.long,
            b'D': pool.double,
            b'Ljava/lang/String;': pool.string,
            b'Ljava/lang/Class;': pool.class_,
        }[field.id.desc](val)
        stream.u16(index)
    else:
        stream.u16(0) # no attributes

def writeMethod(pool, stream, method, code_attr_data):
    stream.u16(method.access & flags.METHOD_FLAGS)
    stream.u16(pool.utf8(method.id.name))
    stream.u16(pool.utf8(method.id.desc))

    if code_attr_data is not None:
        code_attr_data = code_attr_data.toBytes()
        stream.u16(1)
        stream.u16(pool.utf8(b"Code"))
        stream.u32(len(code_attr_data))
        stream.write(code_attr_data)
    else:
        stream.u16(0) # no attributes

def writeMethods(pool, stream, methods, opts):
    code_irs = []
    for method in methods:
        code_irs.append(writebytecode.getCodeIR(pool, method, opts=opts))
    code_attrs = writebytecode.finishCodeAttrs(pool, code_irs, opts=opts)

    stream.u16(len(methods))
    for method in methods:
        writeMethod(pool, stream, method, code_attrs.get(method))

def classFileAfterPool(cls, opts):
    stream = Writer()
    if opts.split_pool:
        pool = constantpool.SplitConstantPool()
    else:
        pool = constantpool.SimpleConstantPool()

    cls.parseData()
    stream.u16(cls.access & flags.CLASS_FLAGS) # access
    stream.u16(pool.class_(cls.name)) # this
    super_ = pool.class_(cls.super) if cls.super is not None else 0
    stream.u16(super_) # super

    # interfaces
    stream.u16(len(cls.interfaces))
    for interface in cls.interfaces:
        stream.u16(pool.class_(interface))

    # fields
    stream.u16(len(cls.data.fields))
    for field in cls.data.fields:
        writeField(pool, stream, field)

    # methods
    writeMethods(pool, stream, cls.data.methods, opts=opts)

    # attributes
    stream.u16(0)
    return pool, stream

def toClassFile(cls, opts):
    stream = Writer()
    stream.u32(0xCAFEBABE)
    # bytecode version 49.0
    stream.u16(0)
    stream.u16(49)

    # Optimistically try translating without optimization to speed things up
    # if the resulting code is too big, retry with optimization
    try:
        pool, rest_stream = classFileAfterPool(cls, opts=opts)
    except error.ClassfileLimitExceeded:
        # print('Retrying {} with optimization enabled'.format(cls.name))
        pool, rest_stream = classFileAfterPool(cls, opts=options.ALL)

    # write constant pool
    pool.write(stream)
    # write rest of file
    stream.write(rest_stream.toBytes())
    return stream.toBytes()
