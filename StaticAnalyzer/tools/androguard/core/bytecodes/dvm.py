# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

from StaticAnalyzer.tools.androguard.core import bytecode

from StaticAnalyzer.tools.androguard.core.bytecode import object_to_str
from StaticAnalyzer.tools.androguard.core.bytecode import FormatClassToPython, FormatNameToPython, FormatDescriptorToPython
from StaticAnalyzer.tools.androguard.core.androconf import CONF

import sys, re
from struct import pack, unpack, calcsize


import logging
log_andro = logging.getLogger("andro")
#log_andro.setLevel(logging.DEBUG)

######################################################## DEX FORMAT ########################################################
DEX_FILE_MAGIC = 'dex\n035\x00'

TYPE_MAP_ITEM = {
                        0x0  : "TYPE_HEADER_ITEM",
                        0x1  : "TYPE_STRING_ID_ITEM",
                        0x2  : "TYPE_TYPE_ID_ITEM",
                        0x3  : "TYPE_PROTO_ID_ITEM",
                        0x4  : "TYPE_FIELD_ID_ITEM",
                        0x5  : "TYPE_METHOD_ID_ITEM",
                        0x6  : "TYPE_CLASS_DEF_ITEM",
                        0x1000 : "TYPE_MAP_LIST",
                        0x1001 : "TYPE_TYPE_LIST",
                        0x1002 : "TYPE_ANNOTATION_SET_REF_LIST",
                        0x1003 : "TYPE_ANNOTATION_SET_ITEM",
                        0x2000 : "TYPE_CLASS_DATA_ITEM",
                        0x2001 : "TYPE_CODE_ITEM",
                        0x2002 : "TYPE_STRING_DATA_ITEM",
                        0x2003 : "TYPE_DEBUG_INFO_ITEM",
                        0x2004 : "TYPE_ANNOTATION_ITEM",
                        0x2005 : "TYPE_ENCODED_ARRAY_ITEM",
                        0x2006 : "TYPE_ANNOTATIONS_DIRECTORY_ITEM",
                     }

ACCESS_FLAGS_METHODS = [ 
    (0x1    , 'public'),
    (0x2    , 'private'),
    (0x4    , 'protected'),
    (0x8    , 'static'),
    (0x10   , 'final'),
    (0x20   , 'synchronized'),
    (0x40   , 'bridge'),
    (0x80   , 'varargs'),
    (0x100  , 'native'),
    (0x200  , 'interface'),
    (0x400  , 'abstract'),
    (0x800  , 'strict'),
    (0x1000 , 'synthetic'),
    (0x4000 , 'enum'),
    (0x8000 , 'unused'),
    (0x10000, 'constructors'),
    (0x20000, 'synchronized'),
]

TYPE_DESCRIPTOR = {
    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
    'STR': 'String',
    'StringBuilder': 'String'
}
def get_type(atype, size=None):
    '''
    Retrieve the type of a descriptor (e.g : I)
    '''
    if atype.startswith('java.lang'):
        atype = atype.replace('java.lang.', '')
    res = TYPE_DESCRIPTOR.get(atype.lstrip('java.lang'))
    if res is None:
        if atype[0] == 'L':
            res = atype[1:-1].replace('/', '.')
        elif atype[0] == '[':
            if size is None:
                res = '%s[]' % get_type(atype[1:])
            else:
                res = '%s[%s]' % (get_type(atype[1:]), size)
        else:
            res = atype
    return res

NORMAL_DVM_INS = 0
SPECIFIC_DVM_INS = 1

class FillArrayData :
    def __init__(self, buff) :
        self.notes = []
        self.info = []

        self.format_general_size = calcsize("=HHI")
        self.ident = unpack("=H", buff[0:2])[0]
        self.element_width = unpack("=H", buff[2:4])[0]
        self.size = unpack("=I", buff[4:8])[0]

        self.data = buff[ self.format_general_size : self.format_general_size + (self.size * self.element_width ) ]

    def add_info(self, msg) :
      self.info.append( msg )

    def add_note(self, msg) :
      self.notes.append( msg )

    def get_notes(self) :
      return self.notes

    def get_op_value(self) :
        return -1

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.element_width) + pack("=I", self.size) + self.data

    def get_data(self) :
        return self.data

    def get_output(self, idx=-1) :
        return self.get_output_formatted()

    def get_operands(self) :
        return self.data

    def get_name(self) :
        return "fill-array-data-payload"

    def get_output_formatted(self) :
        buff = ""

        if len(self.info) != [] :
          buff = ' '.join(i for i in self.info)
          buff += ' '

        buff += repr(self.data) + " | "

        for i in xrange(0, len(self.data)) :
          buff += "\\x%02x" % ord( self.data[i] )
        return buff

    def show_buff(self, pos) :
        buff = self.get_name() + " "

        for i in xrange(0, len(self.data)) :
            buff += "\\x%02x" % ord( self.data[i] )
        return buff

    def show(self, pos) :
        print self.show_buff(pos),

    def get_length(self) :
        return ((self.size * self.element_width + 1) / 2 + 4) * 2

class SparseSwitch :
    def __init__(self, buff) :
        self.notes = []

        self.format_general_size = calcsize("=HH")
        self.ident = unpack("=H", buff[0:2])[0]
        self.size = unpack("=H", buff[2:4])[0]

        self.keys = []
        self.targets = []

        idx = self.format_general_size
        for i in xrange(0, self.size) :
            self.keys.append( unpack('=L', buff[idx:idx+4])[0] )
            idx += 4

        for i in xrange(0, self.size) :
            self.targets.append( unpack('=L', buff[idx:idx+4])[0] )
            idx += 4


    def add_note(self, msg) :
      self.notes.append( msg )

    def get_notes(self) :
      return self.notes

    def get_op_value(self) :
        return -1

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.size) + \
               ''.join(pack("=L", i) for i in self.keys) + ''.join(pack("=L", i) for i in self.targets)

    def get_keys(self) :
        return self.keys

    def get_targets(self) :
        return self.targets

    def get_operands(self) :
        return [ self.keys, self.targets ]

    def get_output(self, idx=-1) :
      return " ".join("%x" % i for i in self.keys)

    def get_values(self) :
      return self.keys

    def get_name(self) :
        return "sparse-switch-payload"

    def show_buff(self, pos) :
        buff = self.get_name() + " "
        for i in xrange(0, len(self.keys)) :
            buff += "%x:%x " % (self.keys[i], self.targets[i])

        return buff

    def show(self, pos) :
        print self.show_buff( pos ),

    def get_length(self) :
        return self.format_general_size + (self.size * calcsize('<L')) * 2

class PackedSwitch :
    def __init__(self, buff) :
        self.notes = []

        self.format_general_size = calcsize( "=HHI" )

        self.ident = unpack("=H", buff[0:2])[0]
        self.size = unpack("=H", buff[2:4])[0]
        self.first_key = unpack("=I", buff[4:8])[0]

        self.targets = []

        idx = self.format_general_size

        max_size = min(self.size, len(buff) - idx - 8)
        for i in xrange(0, max_size) :
            self.targets.append( unpack('=L', buff[idx:idx+4])[0] )
            idx += 4

    def add_note(self, msg) :
      self.notes.append( msg )

    def get_notes(self) :
      return self.notes

    def get_op_value(self) :
        return -1

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.size) + \
            pack("=I", self.first_key) + ''.join(pack("=L", i) for i in self.targets)

    def get_operands(self) :
        return [ self.first_key, self.targets ]

    def get_output(self, idx=-1) :
      return " ".join("%x" % (self.first_key+i) for i in range(0, len(self.targets)))

    def get_values(self) :
      return [(self.first_key+i) for i in range(0, len(self.targets))]

    def get_targets(self) :
        return self.targets

    def get_name(self) :
        return "packed-switch-payload"

    def show_buff(self, pos) :
        buff = self.get_name() + " "
        buff += "%x:" % self.first_key

        for i in self.targets :
            buff += " %x" % i

        return buff

    def show(self, pos) :
        print self.show_buff( pos ),

    def get_length(self) :
        return self.format_general_size + (self.size * calcsize('=L'))

MATH_DVM_OPCODES = {        "add." : '+',
                            "div." : '/',
                            "mul." : '*',
                            "or." : '|',
                            "sub." : '-',
                            "and." : '&',
                            "xor." : '^',
                            "shl." : "<<",
                            "shr." : ">>",
                    }

INVOKE_DVM_OPCODES = [ "invoke." ]

FIELD_READ_DVM_OPCODES = [ ".get" ]
FIELD_WRITE_DVM_OPCODES = [ ".put" ]

BREAK_DVM_OPCODES = [ "invoke.", "move.", ".put", "if." ]

BRANCH_DVM_OPCODES = [ "if.", "goto", "goto.", "return", "return.", "packed-switch$",  "sparse-switch$" ]

def clean_name_instruction( instruction ) :
    op_value = instruction.get_op_value()
    
    # goto range
    if op_value >= 0x28 and op_value <= 0x2a :
        return "goto"

    return instruction.get_name()

def static_operand_instruction( instruction ) :
    buff = ""

    if isinstance(instruction, Instruction) :
      # get instructions without registers
      for val in instruction.get_literals() :
          buff += "%s" % val
    
    op_value = instruction.get_op_value()
    if op_value == 0x1a or op_value == 0x1b :
        buff += instruction.get_string()

    return buff

def dot_buff(ins, idx) :
    return ins.get_name() + " " + ins.get_output(idx)

def readuleb128(buff) :
    result = ord( buff.read(1) )
    if result > 0x7f :
        cur = ord( buff.read(1) )
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        if cur > 0x7f :
            cur = ord( buff.read(1) )
            result |= (cur & 0x7f) << 14
            if cur > 0x7f :
                cur = ord( buff.read(1) )
                result |= (cur & 0x7f) << 21
                if cur > 0x7f :
                    cur = ord( buff.read(1) )
                    if cur > 0x0f :
                      raise("prout")
                    result |= cur << 28

    return result

def readusleb128(buff) :
    result = ord( buff.read(1) )
    if result > 0x7f :
        cur = ord( buff.read(1) )
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        if cur > 0x7f :
            cur = ord( buff.read(1) )
            result |= (cur & 0x7f) << 14
            if cur > 0x7f :
                cur = ord( buff.read(1) )
                result |= (cur & 0x7f) << 21
                if cur > 0x7f :
                    cur = ord( buff.read(1) )
                    result |= cur << 28

    return result

def readuleb128p1(buff) :
  return readuleb128( buff ) - 1

def readsleb128(buff) :
    result = unpack( '=b', buff.read(1) )[0]

    if result <= 0x7f :
        result = (result << 25)
        if result > 0x7fffffff :
            result = (0x7fffffff & result) - 0x80000000
        result = result >> 25
    else :
        cur = unpack( '=b', buff.read(1) )[0]
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        if cur <= 0x7f :
            result = (result << 18) >> 18
        else :
            cur = unpack( '=b', buff.read(1) )[0]
            result |= (cur & 0x7f) << 14
            if cur <= 0x7f :
                result = (result << 11) >> 11
            else :
                cur = unpack( '=b', buff.read(1) )[0]
                result |= (cur & 0x7f) << 21
                if cur <= 0x7f :
                    result = (result << 4) >> 4
                else :
                    cur = unpack( '=b', buff.read(1) )[0]
                    result |= cur << 28

    return result

def get_sbyte(buff) :
  return unpack( '=b', buff.read(1) )[0]

def readsleb128_2(buff) :
  result = get_sbyte(buff)
  if result <= 0x7f :
    result = (result << 25) >> 25
  else :
    cur = get_sbyte(buff)
    result = (result & 0x7f) | ((cur & 0x7f) << 7)
    if cur <= 0x7f :
      result = (result << 18) >> 18
    else :
      cur = get_sbyte(buff)
      result |= (cur & 0x7f) << 14
      if cur <= 0x7f :
        result = (result << 11) >> 11 
      else :
        cur = get_sbyte(buff)
        result |= (cur & 0x7f) << 21 
        if cur <= 0x7f :
          result = (result << 4) >> 4
        else :
          cur = get_sbyte(buff)
          result |= cur << 28

  return result


def writeuleb128(value) :
    remaining = value >> 7

    buff = ""
    while remaining > 0 :
        buff += pack( "=B", ((value & 0x7f) | 0x80) )

        value = remaining
        remaining >>= 7

    buff += pack( "=B", value & 0x7f )
    return buff

def writesleb128(value) :
    remaining = value >> 7
    hasMore = True
    end = 0
    buff = ""

    if (value & (-sys.maxint - 1)) == 0 :
        end = 0
    else :
        end = -1

    while hasMore :
        hasMore = (remaining != end) or ((remaining & 1) != ((value >> 6) & 1))
        tmp = 0
        if hasMore :
            tmp = 0x80

        buff += pack( "=B", (value & 0x7f) | (tmp) )
        value = remaining
        remaining >>= 7

    return buff

def determineNext(i, end, m) :
    op_value = i.get_op_value()

    # return*
    if op_value >= 0x0e and op_value <= 0x11 :
        return [ -1 ]
    # goto
    elif op_value >= 0x28 and op_value <= 0x2a :
        off = i.get_ref_off() * 2
        return [ off + end ]
    # if
    elif op_value >= 0x32 and op_value <= 0x3d :
        off = i.get_ref_off() * 2
        return [ end + i.get_length(), off + (end) ]
    # sparse/packed
    elif op_value == 0x2b or op_value == 0x2c :
        x = []

        x.append( end + i.get_length() )

        code = m.get_code().get_bc()
        off = i.get_ref_off() * 2

        data = code.get_ins_off( off + end )

        if data != None :
            for target in data.get_targets() :
                x.append( target*2 + end )

        return x
    return []

def determineException(vm, m) :
    # no exceptions !
    if m.get_code().get_tries_size() <= 0 :
        return []

    h_off = {}

    handler_catch_list = m.get_code().get_handlers()

    for try_item in m.get_code().get_tries() :
    #    print m.get_name(), try_item, (value.start_addr * 2) + (value.insn_count * 2)# - 1m.get_code().get_bc().get_next_addr( value.start_addr * 2, value.insn_count )
        h_off[ try_item.get_handler_off() + handler_catch_list.get_offset() ] = [ try_item ]

    #print m.get_name(), "\t HANDLER_CATCH_LIST SIZE", handler_catch_list.size, handler_catch_list.get_offset()
    for handler_catch in handler_catch_list.get_list() :
    #    print m.get_name(), "\t\t HANDLER_CATCH SIZE ", handler_catch.size, handler_catch.get_offset()
       
        if handler_catch.get_offset() not in h_off :
            continue

        h_off[ handler_catch.get_offset() ].append( handler_catch )

   #     if handler_catch.size <= 0 :
   #         print m.get_name(), handler_catch.catch_all_addr

   #     for handler in handler_catch.handlers :
   #         print m.get_name(), "\t\t\t HANDLER", handler.type_idx, vm.get_class_manager().get_type( handler.type_idx ), handler.addr

    exceptions = []
    #print m.get_name(), h_off
    for i in h_off :
        value = h_off[ i ][0]
        z = [ value.get_start_addr() * 2, (value.get_start_addr() * 2) + (value.get_insn_count() * 2) - 1 ]

        handler_catch = h_off[ i ][1]
        if handler_catch.get_size() <= 0 :
            z.append( [ "any", handler_catch.get_catch_all_addr() * 2 ] )

        for handler in handler_catch.get_handlers() :
            z.append( [ vm.get_cm_type( handler.get_type_idx() ), handler.get_addr() * 2 ] )

        exceptions.append( z )

    #print m.get_name(), exceptions 
    return exceptions

def DVM_TOSTRING() :
    return { "O" : MATH_DVM_OPCODES.keys(),
             "I" : INVOKE_DVM_OPCODES,
             "G" : FIELD_READ_DVM_OPCODES,
             "P" : FIELD_WRITE_DVM_OPCODES,
            }

class HeaderItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.magic = unpack("=Q", buff.read(8))[0]
        self.checksum = unpack("=I", buff.read(4))[0]
        self.signature = unpack("=20s", buff.read(20))[0]
        self.file_size = unpack("=I", buff.read(4))[0]
        self.header_size = unpack("=I", buff.read(4))[0]
        self.endian_tag = unpack("=I", buff.read(4))[0]
        self.link_size = unpack("=I", buff.read(4))[0]
        self.link_off = unpack("=I", buff.read(4))[0]
        self.map_off = unpack("=I", buff.read(4))[0]
        self.string_ids_size = unpack("=I", buff.read(4))[0]
        self.string_ids_off = unpack("=I", buff.read(4))[0]
        self.type_ids_size = unpack("=I", buff.read(4))[0]
        self.type_ids_off = unpack("=I", buff.read(4))[0]
        self.proto_ids_size = unpack("=I", buff.read(4))[0]
        self.proto_ids_off = unpack("=I", buff.read(4))[0]
        self.field_ids_size = unpack("=I", buff.read(4))[0]
        self.field_ids_off = unpack("=I", buff.read(4))[0]
        self.method_ids_size = unpack("=I", buff.read(4))[0]
        self.method_ids_off = unpack("=I", buff.read(4))[0]
        self.class_defs_size = unpack("=I", buff.read(4))[0]
        self.class_defs_off = unpack("=I", buff.read(4))[0]
        self.data_size = unpack("=I", buff.read(4))[0]
        self.data_off = unpack("=I", buff.read(4))[0]

    def reload(self) :
        pass

    def get_obj(self) :
        return []

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, 
            pack("=Q", self.magic) +
            pack("=I", self.checksum) +
            pack("=20s", self.signature) + 
            pack("=I", self.file_size) +
            pack("=I", self.header_size) +
            pack("=I", self.endian_tag) +
            pack("=I", self.link_size) +
            pack("=I", self.link_off) +
            pack("=I", self.map_off) + 
            pack("=I", self.string_ids_size) +
            pack("=I", self.string_ids_off) +
            pack("=I", self.type_ids_size) +
            pack("=I", self.type_ids_off) +
            pack("=I", self.proto_ids_size) +
            pack("=I", self.proto_ids_off) +
            pack("=I", self.field_ids_size) +
            pack("=I", self.field_ids_off) +
            pack("=I", self.method_ids_size) +
            pack("=I", self.method_ids_off) +
            pack("=I", self.class_defs_size) +
            pack("=I", self.class_defs_off) +
            pack("=I", self.data_size) +
            pack("=I", self.data_off)
            ) ]

    def show(self) :
        print "HEADER", self.magic, self.checksum, self.signature

    def get_off(self) :
        return self.__offset.off

class AnnotationOffItem :
    def __init__(self,  buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.annotation_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        print "ANNOTATION_OFF_ITEM annotation_off=0x%x" % self.annotation_off

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, 
            pack("=I", self.annotation_off) )

class AnnotationSetItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.annotation_off_item = []

        self.size = unpack("=I", buff.read( 4 ) )[0]
        for i in xrange(0, self.size) :
            self.annotation_off_item.append( AnnotationOffItem(buff, cm) )

    def reload(self) :
        pass

    def get_annotation_off_item(self) :
        return self.annotation_off_item

    def show(self) :
        print "ANNOTATION_SET_ITEM"
        nb = 0
        for i in self.annotation_off_item :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.annotation_off_item ]

    def get_raw(self) :
        return [ bytecode.Buff(self.__offset.off, pack("=I", self.size)) ] + [ i.get_raw() for i in self.annotation_off_item ]

    def get_off(self) :
        return self.__offset.off

class AnnotationSetRefItem :
    def __init__(self,  buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        print "ANNOTATION_SET_REF_ITEM annotations_off=0x%x" % self.annotations_off

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, pack("=I", self.annotations_off) )

class AnnotationSetRefList :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.list = []

        self.size = unpack("=I", buff.read( 4 ) )[0]
        for i in xrange(0, self.size) :
            self.list.append( AnnotationSetRefItem(buff, cm) )

    def reload(self) :
        pass

    def show(self) :
        print "ANNOTATION_SET_REF_LIST"
        nb = 0
        for i in self.list :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.list ]

    def get_raw(self) :
        return [ bytecode.Buff(self.__offset.off, pack("=I", self.size)) ] + [ i.get_raw() for i in self.list ]

    def get_off(self) :
        return self.__offset.off

class FieldAnnotation :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.field_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        print "FIELD_ANNOTATION field_idx=0x%x annotations_off=0x%x" % (self.field_idx, self.annotations_off)

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff(self.__offset.off, pack("=I", self.field_idx) +
            pack("=I", self.annotations_off))

class MethodAnnotation :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.method_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        print "METHOD_ANNOTATION method_idx=0x%x annotations_off=0x%x" % ( self.method_idx, self.annotations_off)

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff(self.__offset.off, pack("=I", self.method_idx) +
            pack("=I", self.annotations_off))

class ParameterAnnotation :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.method_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        print "PARAMETER_ANNOTATION method_idx=0x%x annotations_off=0x%x" % (self.method_idx, self.annotations_off)

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff(self.__offset.off, pack("=I", self.method_idx) +
            pack("=I", self.annotations_off))

class AnnotationsDirectoryItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.class_annotations_off = unpack("=I", buff.read(4))[0]
        self.fields_size = unpack("=I", buff.read(4))[0]
        self.annotated_methods_size = unpack("=I", buff.read(4))[0]
        self.annotated_parameters_size = unpack("=I", buff.read(4))[0]

        self.field_annotations = []
        for i in xrange(0, self.fields_size) :
            self.field_annotations.append( FieldAnnotation( buff, cm ) )

        self.method_annotations = []
        for i in xrange(0, self.annotated_methods_size) :
            self.method_annotations.append( MethodAnnotation( buff, cm ) )

        self.parameter_annotations = []
        for i in xrange(0, self.annotated_parameters_size) :
            self.parameter_annotations.append( ParameterAnnotation( buff, cm ) )

    def reload(self) :
        pass

    def show(self) :
        print "ANNOTATIONS_DIRECTORY_ITEM"
        for i in self.field_annotations :
            i.show()

        for i in self.method_annotations :
            i.show()

        for i in self.parameter_annotations :
            i.show()

    def get_obj(self) :
        return [ i for i in self.field_annotations ] + \
                 [ i for i in self.method_annotations ] + \
                 [ i for i in self.parameter_annotations ]

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, 
                                pack("=I", self.class_annotations_off) + 
                                pack("=I", self.fields_size) +
                                pack("=I", self.annotated_methods_size) + 
                                pack("=I", self.annotated_parameters_size)) ] + \
                 [ i.get_raw() for i in self.field_annotations ] + \
                 [ i.get_raw() for i in self.method_annotations ] + \
                 [ i.get_raw() for i in self.parameter_annotations ]

    def get_off(self) :
        return self.__offset.off

class TypeLItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        self.type_idx = unpack("=H", buff.read(2))[0]

    def show(self) :
        print "TYPE_LITEM", self.type_idx

    def get_string(self) :
        return self.__CM.get_type( self.type_idx )

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff(self.__offset.off, pack("=H", self.type_idx))

class TypeList :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )
        offset = buff.get_idx()

        self.pad = ""
        if offset % 4 != 0 :
            self.pad = buff.read( offset % 4 )

        self.len_pad = len(self.pad)

        self.size = unpack("=I", buff.read( 4 ) )[0]

        self.list = []
        for i in xrange(0, self.size) :
            self.list.append( TypeLItem( buff, cm ) )

    def reload(self) :
        pass

    def get_type_list_off(self) :
        return self.__offset.off + self.len_pad

    def get_string(self) :
        return ' '.join(i.get_string() for i in self.list)

    def show(self) :
        print "TYPE_LIST"
        nb = 0
        for i in self.list :
            print nb, self.__offset.off + self.len_pad,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.list ]

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, self.pad + pack("=I", self.size) ) ] + [ i.get_raw() for i in self.list ]

    def get_off(self) :
        return self.__offset.off

DBG_END_SEQUENCE                    = 0x00 #    (none)  terminates a debug info sequence for a code_item
DBG_ADVANCE_PC                      = 0x01 #     uleb128 addr_diff       addr_diff: amount to add to address register    advances the address register without emitting a positions entry
DBG_ADVANCE_LINE                    = 0x02 #    sleb128 line_diff       line_diff: amount to change line register by    advances the line register without emitting a positions entry
DBG_START_LOCAL                     = 0x03 #   uleb128 register_num
                                                    #    uleb128p1 name_idx
                                                    #    uleb128p1 type_idx
                                                    #         register_num: register that will contain local name_idx: string index of the name
                                                    #         type_idx: type index of the type  introduces a local variable at the current address. Either name_idx or type_idx may be NO_INDEX to indicate that that value is unknown.
DBG_START_LOCAL_EXTENDED            = 0x04 #   uleb128 register_num uleb128p1 name_idx uleb128p1 type_idx uleb128p1 sig_idx
                                                    #         register_num: register that will contain local
                                                    #         name_idx: string index of the name
                                                    #         type_idx: type index of the type
                                                    #         sig_idx: string index of the type signature
                                                    # introduces a local with a type signature at the current address. Any of name_idx, type_idx, or sig_idx may be NO_INDEX to indicate that that value is unknown. (
                                                    # If sig_idx is -1, though, the same data could be represented more efficiently using the opcode DBG_START_LOCAL.)
                                                    # Note: See the discussion under "dalvik.annotation.Signature" below for caveats about handling signatures.
DBG_END_LOCAL                       = 0x05 #    uleb128 register_num
                                                    #           register_num: register that contained local
                                                    #           marks a currently-live local variable as out of scope at the current address
DBG_RESTART_LOCAL                   = 0x06 #     uleb128 register_num
                                                    #           register_num: register to restart re-introduces a local variable at the current address.
                                                    #           The name and type are the same as the last local that was live in the specified register.
DBG_SET_PROLOGUE_END                = 0x07 #     (none)  sets the prologue_end state machine register, indicating that the next position entry that is added should be considered the end of a
                                                    #               method prologue (an appropriate place for a method breakpoint). The prologue_end register is cleared by any special (>= 0x0a) opcode.
DBG_SET_EPILOGUE_BEGIN              = 0x08 #    (none)  sets the epilogue_begin state machine register, indicating that the next position entry that is added should be considered the beginning
                                                    #               of a method epilogue (an appropriate place to suspend execution before method exit). The epilogue_begin register is cleared by any special (>= 0x0a) opcode.
DBG_SET_FILE                        = 0x09 #   uleb128p1 name_idx
                                                    #           name_idx: string index of source file name; NO_INDEX if unknown indicates that all subsequent line number entries make reference to this source file name,
                                                    #           instead of the default name specified in code_item
DBG_Special_Opcodes_BEGIN           = 0x0a #    (none)  advances the line and address registers, emits a position entry, and clears prologue_end and epilogue_begin. See below for description.
DBG_Special_Opcodes_END             = 0xff
DBG_LINE_BASE                       = -4
DBG_LINE_RANGE                      = 15


class DBGBytecode :
    def __init__(self, cm, op_value) :
        self.CM = cm
        self.op_value = op_value
        self.format = []

    def get_op_value(self) :
        return self.op_value.get_value()

    def add(self, value, ttype) :
        self.format.append( (value, ttype) )

    def show(self) :
      if self.get_op_value() == DBG_START_LOCAL :
        print self.format, self.CM.get_string(self.format[1][0])
      elif self.get_op_value() == DBG_START_LOCAL_EXTENDED :
        print self.format, self.CM.get_string(self.format[1][0])

    def get_obj(self) :
        return []

    def get_raw(self) :
        buff = self.op_value.get_value_buff()
        for i in self.format :
            if i[1] == "u" :
                buff += writeuleb128( i[0] )
            elif i[1] == "s" :
                buff += writesleb128( i[0] )
        return buff

class DebugInfoItem2 :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.__buff = buff
        self.__raw = ""

    def reload(self) :
        offset = self.__offset.off

        n = self.__CM.get_next_offset_item( offset )

        s_idx = self.__buff.get_idx()
        self.__buff.set_idx( offset )
        self.__raw = self.__buff.read( n - offset )
        self.__buff.set_idx( s_idx )

    def show(self) :
        pass

    def get_obj(self) :
        return []

    def get_raw(self) :
        return [ bytecode.Buff(self.__offset.off, self.__raw) ]

    def get_off(self) :
        return self.__offset.off

class DebugInfoItem :
    def __init__(self, buff, cm) :
        self.CM = cm
        self.__offset = self.CM.add_offset( buff.get_idx(), self )

        self.line_start = readuleb128( buff )
        self.parameters_size = readuleb128( buff )

        print "line", self.line_start, "params", self.parameters_size

        self.parameter_names = []
        for i in xrange(0, self.parameters_size) :
            self.parameter_names.append( readuleb128p1( buff ) )

        self.bytecodes = []
        bcode = DBGBytecode( self.CM, unpack("=B", buff.read(1))[0] )
        self.bytecodes.append( bcode )

        while bcode.get_op_value() != DBG_END_SEQUENCE :
            bcode_value = bcode.get_op_value()

            print "0x%x" % bcode.get_op_value()

            if bcode_value == DBG_ADVANCE_PC :
                bcode.add( readuleb128( buff ), "u" )
            elif bcode_value == DBG_ADVANCE_LINE :
                bcode.add( readsleb128( buff ), "s" )
            elif bcode_value == DBG_START_LOCAL :
                bcode.add( readusleb128( buff ), "u" )
                bcode.add( readuleb128p1( buff ), "u1" )
                bcode.add( readuleb128p1( buff ), "u1" )
            elif bcode_value == DBG_START_LOCAL_EXTENDED :
                bcode.add( readusleb128( buff ), "u" )
                bcode.add( readuleb128p1( buff ), "u1" )
                bcode.add( readuleb128p1( buff ), "u1" )
                bcode.add( readuleb128p1( buff ), "u1" )
            elif bcode_value == DBG_END_LOCAL :
                bcode.add( readusleb128( buff ), "u" )
            elif bcode_value == DBG_RESTART_LOCAL :
                bcode.add( readusleb128( buff ), "u" )
            elif bcode_value == DBG_SET_PROLOGUE_END :
                pass
            elif bcode_value == DBG_SET_EPILOGUE_BEGIN :
                pass
            elif bcode_value == DBG_SET_FILE :
                bcode.add( readuleb128p1( buff ), "u1" )
            else : #bcode_value >= DBG_Special_Opcodes_BEGIN and bcode_value <= DBG_Special_Opcodes_END :
                pass

            bcode = DBGBytecode( self.CM, unpack("=B", buff.read(1))[0] )
            self.bytecodes.append( bcode )
        self.show()

    def reload(self) :
        pass

    def show(self) :
        print self.line_start, self.parameters_size, self.parameter_names
        for i in self.parameter_names :
          print self.CM.get_string( i )

        for i in self.bytecodes :
          i.show()

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset, writeuleb128( self.line_start ) + \
                                                            writeuleb128( self.parameters_size ) + \
                                                            ''.join(writeuleb128(i) for i in self.parameter_names) + \
                                                            ''.join(i.get_raw() for i in self.bytecodes) ) ]

    def get_off(self) :
        return self.__offset.off

VALUE_BYTE      = 0x00    # (none; must be 0)      ubyte[1]         signed one-byte integer value
VALUE_SHORT     = 0x02 # size - 1 (0..1)  ubyte[size]    signed two-byte integer value, sign-extended
VALUE_CHAR      = 0x03    # size - 1 (0..1)  ubyte[size]    unsigned two-byte integer value, zero-extended
VALUE_INT       = 0x04  # size - 1 (0..3)  ubyte[size]    signed four-byte integer value, sign-extended
VALUE_LONG      = 0x06    # size - 1 (0..7)  ubyte[size]    signed eight-byte integer value, sign-extended
VALUE_FLOAT     = 0x10 # size - 1 (0..3)  ubyte[size]    four-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 32-bit floating point value
VALUE_DOUBLE    = 0x11  # size - 1 (0..7)  ubyte[size]    eight-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 64-bit floating point value
VALUE_STRING    = 0x17  # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the string_ids section and representing a string value
VALUE_TYPE      = 0x18    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the type_ids section and representing a reflective type/class value
VALUE_FIELD     = 0x19 # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing a reflective field value
VALUE_METHOD    = 0x1a  # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the method_ids section and representing a reflective method value
VALUE_ENUM      = 0x1b    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing the value of an enumerated type constant
VALUE_ARRAY     = 0x1c # (none; must be 0)      encoded_array  an array of values, in the format specified by "encoded_array Format" below. The size of the value is implicit in the encoding.
VALUE_ANNOTATION         = 0x1d # (none; must be 0)      encoded_annotation     a sub-annotation, in the format specified by "encoded_annotation Format" below. The size of the value is implicit in the encoding.
VALUE_NULL      = 0x1e    # (none; must be 0)      (none)  null reference value
VALUE_BOOLEAN   = 0x1f   # boolean (0..1) (none)  one-bit value; 0 for false and 1 for true. The bit is represented in the value_arg.


class EncodedArray :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.size = readuleb128( buff )

        self.values = []
        for i in xrange(0, self.size) :
            self.values.append( EncodedValue(buff, cm) )

    def show(self) :
        print "ENCODED_ARRAY"
        for i in self.values :
            i.show()

    def get_values(self) :
        return self.values

    def get_obj(self) :
        return [ i for i in self.values ]

    def get_raw(self) :
        return writeuleb128( self.size ) + ''.join(i.get_raw() for i in self.values)

class EncodedValue :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )


        self.val = unpack("=B", buff.read(1))[0]
        self.__value_arg = self.val >> 5
        self.__value_type = self.val & 0x1f

        self.raw_value = None
        self.value = ""

        #  TODO: parse floats/doubles correctly
        if self.__value_type >= VALUE_SHORT and self.__value_type < VALUE_STRING :
            self.value, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
        elif self.__value_type == VALUE_STRING :
            id, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
            self.value = cm.get_raw_string(id)
        elif self.__value_type == VALUE_TYPE :
            id, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
            self.value = cm.get_type(id)
        elif self.__value_type == VALUE_FIELD :
            id, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
            self.value = cm.get_field(id)
        elif self.__value_type == VALUE_METHOD :
            id, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
            self.value = cm.get_method(id)
        elif self.__value_type == VALUE_ENUM :
            id, self.raw_value = self._getintvalue(buff.read( self.__value_arg + 1 ))
            self.value = cm.get_field(id)
        elif self.__value_type == VALUE_ARRAY :
            self.value = EncodedArray( buff, cm )
        elif self.__value_type == VALUE_ANNOTATION :
            self.value = EncodedAnnotation( buff, cm )
        elif self.__value_type == VALUE_BYTE :
            self.value = buff.read( 1 )
        elif self.__value_type == VALUE_NULL :
            self.value = None
        elif self.__value_type == VALUE_BOOLEAN :
            if self.__value_arg:
                self.value = True
            else:
                self.value = False
        else :
            bytecode.Exit( "Unknown value 0x%x" % self.__value_type )

    def _getintvalue(self, buf):
        ret = 0
        shift = 0
        for b in buf:
            ret |= ord(b) << shift
            shift += 8

        return ret, buf

    def show(self) :
        print "ENCODED_VALUE", self.val, self.__value_arg, self.__value_type

    def get_obj(self) :
        if isinstance(self.value, str) == False :
            return [ self.value ]
        return []

    def get_raw(self) :
        if self.raw_value == None :
            return pack("=B", self.val) + object_to_str( self.value )
        else :
            return pack("=B", self.val) + object_to_str( self.raw_value )

class AnnotationElement :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.name_idx = readuleb128( buff )
        self.value = EncodedValue( buff, cm )

    def show(self) :
        print "ANNOTATION_ELEMENT", self.name_idx
        self.value.show()

    def get_obj(self) :
        return [ self.value ]

    def get_raw(self) :
        return [ bytecode.Buff(self.__offset.off, writeuleb128(self.name_idx) + self.value.get_raw()) ]


class EncodedAnnotation :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.type_idx = readuleb128( buff )
        self.size = readuleb128( buff )

        self.elements = []
        for i in xrange(0, self.size) :
            self.elements.append( AnnotationElement( buff, cm ) )

    def show(self) :
        print "ENCODED_ANNOTATION", self.type_idx, self.size
        for i in self.elements :
            i.show()

    def get_obj(self) :
        return [ i for i in self.elements ]

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, writeuleb128(self.type_idx) + writeuleb128(self.size) ) ] + \
                 [ i.get_raw() for i in self.elements ]

class AnnotationItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.visibility = unpack("=B", buff.read(1))[0]
        self.annotation = EncodedAnnotation(buff, cm)

    def reload(self) :
        pass

    def show(self) :
        print "ANNOATATION_ITEM", self.visibility
        self.annotation.show()

    def get_obj(self) :
        return [ self.annotation ]

    def get_raw(self) :
        return [ bytecode.Buff(self.__offset.off, pack("=B", self.visibility)) ] + self.annotation.get_raw()

    def get_off(self) :
        return self.__offset.off

class EncodedArrayItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.value = EncodedArray( buff, cm )

    def reload(self) :
        pass

    def show(self) :
        print "ENCODED_ARRAY_ITEM"
        self.value.show()

    def get_obj(self) :
        return [ self.value ]

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, self.value.get_raw() )

    def get_off(self) :
        return self.__offset.off

class StringDataItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.utf16_size = readuleb128( buff )
        self.data = buff.read( self.utf16_size + 1 )

        if self.data[-1] != '\x00' :
            i = buff.read( 1 )
            self.utf16_size += 1
            self.data += i
            while i != '\x00' :
                i = buff.read( 1 )
                self.utf16_size += 1
                self.data += i

    def reload(self) :
        pass

    def get(self) :
        return self.data[:-1]

    def show(self) :
        print "STRING_DATA_ITEM", "%d %s" % ( self.utf16_size, repr( self.data ) )

    def get_obj(self) :
        return []

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, writeuleb128( self.utf16_size ) + self.data ) ]

    def get_off(self) :
        return self.__offset.off

class StringIdItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.string_data_off = unpack("=I", buff.read(4))[0]

    def reload(self) :
        pass

    def get_data_off(self) :
        return self.string_data_off

    def get_obj(self) :
        return []

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, pack("=I", self.string_data_off) ) ]

    def show(self) :
        print "STRING_ID_ITEM", self.string_data_off

    def get_off(self) :
        return self.__offset.off

class IdItem(object) :
    def __init__(self, size, buff, cm, TClass) :
        self.elem = []
        for i in xrange(0, size) :
            self.elem.append( TClass(buff, cm) )

    def gets(self) :
        return self.elem

    def get(self, idx) :
        return self.elem[ idx ]

    def reload(self) :
        for i in self.elem :
            i.reload()

    def show(self) :
        nb = 0
        for i in self.elem :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.elem ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.elem ]

class TypeItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.val = unpack("=I", buff.read( 4 ) )[0]
        self._name = None

    def reload(self) :
        self._name = self.__CM.get_string( self.val )

    def show(self) :
        print "TYPE_ITEM", self.val, self._name

    def get_value(self) :
        return self.val

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, pack("=I", self.val) )

class TypeIdItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.type = []

        for i in xrange(0, size) :
            self.type.append( TypeItem( buff, cm ) )

    def reload(self) :
        for i in self.type :
            i.reload()

    def get(self, idx) :
        if idx > len(self.type) :
            return self.type[-1].get_value()
        return self.type[ idx ].get_value()

    def show(self) :
        print "TYPE_ID_ITEM"
        nb = 0
        for i in self.type :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.type ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.type ]

    def get_off(self) :
        return self.__offset.off

class ProtoItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.shorty_idx = unpack("=I", buff.read(4))[0]
        self.return_type_idx = unpack("=I", buff.read(4))[0]
        self.parameters_off = unpack("=I", buff.read(4))[0]

        self._shorty = None
        self._return = None
        self._params = None

    def reload(self) :
        self._shorty = self.__CM.get_string( self.shorty_idx )
        self._return = self.__CM.get_type( self.return_type_idx )
        self._params = self.__CM.get_type_list( self.parameters_off )

    def get_params(self) :
        return self._params

    def get_shorty(self) :
        return self._shorty

    def get_return_type(self) :
        return self._return

    def show(self) :
        print "PROTO_ITEM", self._shorty, self._return, self.shorty_idx,
        self.return_type_idx, self.parameters_off

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, 
            pack("=I", self.shorty_idx) + pack("=I", self.return_type_idx) +
            pack("=I", self.parameters_off)
            )

class ProtoIdItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.proto = []

        for i in xrange(0, size) :
            self.proto.append( ProtoItem(buff, cm) )

    def get(self, idx) :
        return self.proto[ idx ]

    def reload(self) :
        for i in self.proto :
            i.reload()

    def show(self) :
        print "PROTO_ID_ITEM"
        nb = 0
        for i in self.proto :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.proto ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.proto ]

    def get_off(self) :
        return self.__offset.off

class FieldItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.class_idx = unpack("=H", buff.read(2))[0]
        self.type_idx = unpack("=H", buff.read(2))[0]
        self.name_idx = unpack("=I", buff.read(4))[0]

        self._class = None
        self._type = None
        self._name = None

    def reload(self) :
        self._class = self.__CM.get_type( self.class_idx )
        self._type = self.__CM.get_type( self.type_idx )
        self._name = self.__CM.get_string( self.name_idx )

    def get_class_name(self) :
        return self._class

    def get_class(self) :
        return self._class

    def get_type(self) :
        return self._type

    def get_descriptor(self) :
        return self._type

    def get_name(self) :
        return self._name

    def get_list(self) :
        return [ self.get_class(), self.get_type(), self.get_name() ]

    def show(self) :
        print "FIELD_ITEM", self._class, self._type, self._name,
        self.class_idx, self.type_idx, self.name_idx

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, 
            pack("=H", self.class_idx) +
            pack("=H", self.type_idx) +
            pack("=I", self.name_idx))

    def get_off(self) :
        return self.__offset.off

class FieldIdItem(IdItem) :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        super(FieldIdItem, self).__init__(size, buff, cm, FieldItem)

    def get_off(self) :
        return self.__offset.off

class MethodItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.class_idx = unpack("=H", buff.read(2))[0]
        self.proto_idx = unpack("=H", buff.read(2))[0]
        self.name_idx = unpack("=I", buff.read(4))[0]

        self._class = None
        self._proto = None
        self._name = None

    def reload(self) :
        self._class = self.__CM.get_type( self.class_idx )
        self._proto = self.__CM.get_proto( self.proto_idx )
        self._name = self.__CM.get_string( self.name_idx )

    def get_type(self) :
        return self.proto_idx

    def show(self) :
        print "METHOD_ITEM", self._name, self._proto, self._class, self.class_idx, self.proto_idx, self.name_idx

    def get_class(self) :
        return self._class

    def get_proto(self) :
        return self._proto

    def get_name(self) :
        return self._name

    def get_list(self) :
        return [ self.get_class(), self.get_name(), self.get_proto() ]

    def get_obj(self) :
        return []

    def get_raw(self) :
        return bytecode.Buff( self.__offset.off, 
            pack("H", self.class_idx) + pack("H", self.proto_idx) + pack("I", self.name_idx))

class MethodIdItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.methods = []
        for i in xrange(0, size) :
            self.methods.append( MethodItem(buff, cm) )

    def get(self, idx) :
        return self.methods[ idx ]

    def reload(self) :
        for i in self.methods :
            i.reload()

    def show(self) :
        print "METHOD_ID_ITEM"
        nb = 0
        for i in self.methods :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.methods ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.methods ]

    def get_off(self) :
        return self.__offset.off

class EncodedField :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.field_idx_diff = readuleb128( buff )
        self.access_flags = readuleb128( buff )

        self.__field_idx = 0

        self._name = None
        self._proto = None
        self._class_name = None

        self.static_init_value = None

    def reload(self) :
        name = self.__CM.get_field( self.__field_idx )
        self._class_name = name[0]
        self._name = name[2]
        self._proto = ''.join(i for i in name[1])

    def set_init_value(self, value) :
        self.static_init_value = value

    def get_access_flags(self) :
        return self.access_flags

    def get_access(self) :
        return self.get_access_flags()

    def get_class_name(self) :
        return self._class_name

    def get_descriptor(self) :
        return self._proto

    def get_name(self) :
        return self._name

    def adjust_idx(self, val) :
        self.__field_idx = self.field_idx_diff + val

    def get_idx(self) :
        return self.__field_idx

    def get_obj(self) :
        return []

    def get_raw(self) :
        return writeuleb128( self.field_idx_diff ) + writeuleb128( self.access_flags )

    def show(self) :
        print "\tENCODED_FIELD access_flags=%d (%s,%s,%s)" % (self.access_flags, self._class_name, self._name, self._proto)
        if self.static_init_value != None :
            print "\tvalue:", self.static_init_value.value

        self.show_dref()

    def show_dref(self) :
        try :
            for i in self.DREFr.items :
                print "R:", i[0].get_class_name(), i[0].get_name(), i[0].get_descriptor(), [ "%x" % j for j in i[1] ]
            for i in self.DREFw.items :
                print "W:", i[0].get_class_name(), i[0].get_name(), i[0].get_descriptor(), [ "%x" % j for j in i[1] ]
        except AttributeError:
            pass

class EncodedMethod :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.method_idx_diff = readuleb128( buff )
        self.access_flags = readuleb128( buff )
        self.code_off = readuleb128( buff )

        self.__method_idx = 0

        self._name = None
        self._proto = None
        self._class_name = None

        self._code = None

        self.access_flags_string = None

        self.notes = []

    def reload(self) :
        v = self.__CM.get_method( self.__method_idx )

        self._class_name = v[0]
        self._name = v[1]
        self._proto = ''.join(i for i in v[2])

        self._code = self.__CM.get_code( self.code_off )

    def set_name(self, value) :
        self.__CM.set_hook_method_name( self.__method_idx, value )
        self.reload()

    def set_class_name(self, value) :
        self.__CM.set_hook_method_class_name( self.__method_idx, value )
        self.reload()

    def get_locals(self) :
        ret = self._proto.split(')')
        params = ret[0][1:].split()

        return self._code.registers_size-len(params) - 1

    def each_params_by_register(self, nb, proto) :
        bytecode._PrintSubBanner("Params") 
        ret = proto.split(')')
        params = ret[0][1:].split()
        if params :
            bytecode._PrintDefault("- local registers: v%d...v%d\n" % (0, nb-len(params)-1))
            j = 0
            for i in xrange(nb - len(params), nb) :
                bytecode._PrintDefault("- v%d:%s\n" % (i, get_type(params[j])))
                j += 1
        else :
            bytecode._PrintDefault("local registers: v%d...v%d\n" % (0, nb-1))
        bytecode._PrintDefault("- return:%s\n" % get_type(ret[1]))
        bytecode._PrintSubBanner() 

    def build_access_flags(self) :
        if self.access_flags_string == None :
            self.access_flags_string = ""
            for i in ACCESS_FLAGS_METHODS :
                if (i[0] & self.access_flags) == i[0] :
                    self.access_flags_string += i[1] + " "

            if self.access_flags_string == "" :
                self.access_flags_string = "0x%x" % self.access_flags
            else :
                self.access_flags_string = self.access_flags_string[:-1]

    def show_info(self) :
        self.build_access_flags()
        bytecode._PrintSubBanner("Method Information") 
        bytecode._PrintDefault("%s->%s%s [access_flags=%s]\n" % (self._class_name, self._name, self._proto, self.access_flags_string))

    def show(self) :
        colors = bytecode.disable_print_colors()
        self.pretty_show() 
        bytecode.enable_print_colors(colors)

    def pretty_show(self) :
        self.show_info()
        self.show_notes()
        if self._code != None :
            self.each_params_by_register( self._code.registers_size, self._proto )
            if self.__CM.get_vmanalysis() == None :
                self._code.show()
            else :
                self._code.pretty_show( self.__CM.get_vmanalysis().get_method( self ) )
                self.show_xref()

    def show_xref(self) :
        try :
            bytecode._PrintSubBanner("XREF") 
            bytecode._PrintXRef("F", self.XREFfrom.items)
            bytecode._PrintXRef("T", self.XREFto.items)
            bytecode._PrintSubBanner() 
        except AttributeError:
            pass

    def show_notes(self) :
      if self.notes != [] :
        bytecode._PrintSubBanner("Notes") 
        for i in self.notes :
          bytecode._PrintNote(i)
        bytecode._PrintSubBanner() 

    def source(self) :
        self.__CM.decompiler_ob.display_source( self.get_class_name(), self.get_name(), self.get_descriptor() )

    def get_access_flags(self) :
        return self.access_flags

    def get_access(self) :
        return self.get_access_flags()

    def get_length(self) :
        if self._code != None :
            return self._code.get_length()
        return 0

    def get_code(self) :
        return self._code

    def get_instructions(self) :
        if self._code == None :
          return []
        #return self._code.get_bc().get()
        return self._code.get_bc().get_instructions()

    def get_instruction(self, idx, off=None) :
        if self._code != None :
            return self._code.get_instruction(idx, off)
        return None

    def get_descriptor(self) :
        return self._proto

    def get_class_name(self) :
        return self._class_name

    def get_name(self) :
        return self._name

    def adjust_idx(self, val) :
        self.__method_idx = self.method_idx_diff + val

    def get_idx(self) :
        return self.__method_idx

    def get_obj(self) :
        return []

    def get_raw(self) :
        return writeuleb128( self.method_idx_diff ) + writeuleb128( self.access_flags ) + writeuleb128( self.code_off )

    def add_inote(self, msg, idx, off=None) :
        if self._code != None :  
            self._code.add_inote(msg, idx, off)

    def add_note(self, msg) :
        self.notes.append( msg )

class ClassDataItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.static_fields_size = readuleb128( buff )
        self.instance_fields_size = readuleb128( buff )
        self.direct_methods_size = readuleb128( buff )
        self.virtual_methods_size = readuleb128( buff )

        self.static_fields = []
        self.instance_fields = []
        self.direct_methods = []
        self.virtual_methods = []

        self.load_field( self.static_fields_size, self.static_fields, EncodedField, buff, cm )
        self.load_field( self.instance_fields_size, self.instance_fields, EncodedField, buff, cm )
        self.load_field( self.direct_methods_size, self.direct_methods, EncodedMethod, buff, cm )
        self.load_field( self.virtual_methods_size, self.virtual_methods, EncodedMethod, buff, cm )

    def set_static_fields(self, values) :
        if values != None :
            if len(values.values) <= len(self.static_fields) :
                for i in xrange(0, len(values.values)) :
                    self.static_fields[i].set_init_value( values.values[i] )

    def load_field(self, size, l, Type, buff, cm) :
        prev = 0
        for i in xrange(0, size) :
            el = Type(buff, cm)
            el.adjust_idx( prev )
            prev = el.get_idx()

            l.append( el )

    def reload(self) :
        for i in self.static_fields :
            i.reload()

        for i in self.instance_fields :
            i.reload()

        for i in self.direct_methods :
            i.reload()

        for i in self.virtual_methods :
            i.reload()

    def show(self) :
        print "CLASS_DATA_ITEM static_fields_size=%d instance_fields_size=%d direct_methods_size=%d virtual_methods_size=%d" % \
                (self.static_fields_size, self.instance_fields_size, self.direct_methods_size, self.virtual_methods_size)

        print "SF"
        for i in self.static_fields :
            i.show()

        print "IF"
        for i in self.instance_fields :
            i.show()

        print "DM"
        for i in self.direct_methods :
            i.show()

        print "VM"
        for i in self.virtual_methods :
            i.show()

    def pretty_show(self) :
        print "CLASS_DATA_ITEM static_fields_size=%d instance_fields_size=%d direct_methods_size=%d virtual_methods_size=%d" % \
                (self.static_fields_size, self.instance_fields_size, self.direct_methods_size, self.virtual_methods_size)

        print "SF"
        for i in self.static_fields :
            i.show()

        print "IF"
        for i in self.instance_fields :
            i.show()

        print "DM"
        for i in self.direct_methods :
            i.pretty_show()

        print "VM"
        for i in self.virtual_methods :
            i.pretty_show()

    def get_methods(self) :
        return [ x for x in self.direct_methods ] + [ x for x in self.virtual_methods ]

    def get_fields(self) :
        return [ x for x in self.static_fields ] + [ x for x in self.instance_fields ]

    def get_off(self) :
        return self.__offset.off

    def get_obj(self) :
        return [ i for i in self.static_fields ] + \
                 [ i for i in self.instance_fields ] + \
                 [ i for i in self.direct_methods ] + \
                 [ i for i in self.virtual_methods ]

    def get_raw(self) :
        buff = writeuleb128( self.static_fields_size ) + \
                 writeuleb128( self.instance_fields_size ) + \
                 writeuleb128( self.direct_methods_size ) + \
                 writeuleb128( self.virtual_methods_size ) + \
                 ''.join(i.get_raw() for i in self.static_fields) + \
                 ''.join(i.get_raw() for i in self.instance_fields) + \
                 ''.join(i.get_raw() for i in self.direct_methods) + \
                 ''.join(i.get_raw() for i in self.virtual_methods)

        return [ bytecode.Buff(self.__offset.off, buff) ]

class ClassItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.class_idx = unpack("=I", buff.read(4))[0]
        self.access_flags = unpack("=I", buff.read(4))[0]
        self.superclass_idx = unpack("=I", buff.read(4))[0]
        self.interfaces_off = unpack("=I", buff.read(4))[0]
        self.source_file_idx = unpack("=I", buff.read(4))[0]
        self.annotations_off = unpack("=I", buff.read(4))[0]
        self.class_data_off = unpack("=I", buff.read(4))[0]
        self.static_values_off = unpack("=I", buff.read(4))[0]

        self._interfaces = None
        self._class_data_item = None
        self._static_values = None

        self._name = None
        self._sname = None

    def reload(self) :
        self._name = self.__CM.get_type( self.class_idx )
        self._sname = self.__CM.get_type( self.superclass_idx )

        if self.interfaces_off != 0 :
            self._interfaces = self.__CM.get_type_list( self.interfaces_off )

        if self.class_data_off != 0 :
            self._class_data_item = self.__CM.get_class_data_item( self.class_data_off )
            self._class_data_item.reload()
    
        if self.static_values_off != 0 :
            self._static_values = self.__CM.get_encoded_array_item ( self.static_values_off )
            if self._class_data_item != None :
                self._class_data_item.set_static_fields( self._static_values.value )

    def show(self) :
        print "CLASS_ITEM", self._name, self._sname, self._interfaces,
        self.class_idx, self.access_flags, self.superclass_idx,
        self.interfaces_off, self.source_file_idx, self.annotations_off,
        self.class_data_off, self.static_values_off

    def source(self) :
        self.__CM.decompiler_ob.display_all( self.get_name() )

    def set_name(self, value) :
        self.__CM.set_hook_class_name( self.class_idx, value )
        self.reload()

    def get_class_data(self) :
        return self._class_data_item

    def get_name(self) :
        return self._name

    def get_superclassname(self) :
        return self._sname

    def get_info(self) :
        return "%s:%s" % (self._name, self._sname)

    def get_methods(self) :
        if self._class_data_item != None :
            return self._class_data_item.get_methods()
        return []

    def get_fields(self) :
        if self._class_data_item != None :
            return self._class_data_item.get_fields()
        return []

    def get_obj(self) :
        return []

    def get_class_idx(self) :
        return self.class_idx

    def get_access_flags(self) :
        return self.access_flags

    def get_superclass_idx(self) :
        return self.superclass_idx

    def get_interfaces_off(self) :
        return self.interfaces_off

    def get_source_file_idx(self) :
        return self.source_file_idx

    def get_annotations_off(self): 
        return self.annotations_off

    def get_class_data_off(self) :
        return self.class_data_off

    def get_static_values_off(self) :
        return self.static_values_off

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, 
            pack("=I", self.class_idx) +
            pack("=I", self.access_flags) +
            pack("=I", self.superclass_idx) +
            pack("=I", self.interfaces_off) +
            pack("=I", self.source_file_idx) +
            pack("=I", self.annotations_off) +
            pack("=I", self.class_data_off) +
            pack("=I", self.static_values_off)
            )]

class ClassDefItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.class_def = []

        for i in xrange(0, size) :
            idx = buff.get_idx()

            class_def = ClassItem( buff, cm )
            self.class_def.append( class_def )

            buff.set_idx( idx + calcsize("=IIIIIIII") )

    def get_method(self, name_class, name_method) :
        l = []

        for i in self.class_def :
            if i.get_name() == name_class :
                for j in i.get_methods() :
                    if j.get_name() == name_method :
                        l.append(j)

        return l

    def get_names(self) :
        return [ x.get_name() for x in self.class_def ]

    def reload(self) :
        for i in self.class_def :
            i.reload()

    def show(self) :
        print "CLASS_DEF_ITEM"
        nb = 0
        for i in self.class_def :
            print nb,
            i.show()
            nb = nb + 1

    def get_obj(self) :
        return [ i for i in self.class_def ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.class_def ]

    def get_off(self) :
        return self.__offset.off

class EncodedTypeAddrPair :
    def __init__(self, buff) :
        self.type_idx = readuleb128( buff )
        self.addr = readuleb128( buff )

    def get_obj(self) :
        return []

    def show(self) :
        print "ENCODED_TYPE_ADDR_PAIR", self.type_idx, self.addr

    def get_raw(self) :
        return writeuleb128( self.type_idx ) + writeuleb128( self.addr )

    def get_type_idx(self) :
        return self.type_idx

    def get_addr(self) :
        return self.addr

class EncodedCatchHandler :
    def __init__(self, buff, cm) :
        self.__offset = cm.add_offset( buff.get_idx(), self ) 
        self.size = readsleb128( buff )

        self.handlers = []

        for i in xrange(0, abs(self.size)) :
            self.handlers.append( EncodedTypeAddrPair(buff) )

        if self.size <= 0 :
            self.catch_all_addr = readuleb128( buff )

    def show(self) :
        print "ENCODED_CATCH_HANDLER size=0x%x" % self.size
        for i in self.handlers :
            i.show()

    def get_obj(self) :
        return [ i for i in self.handlers ]

    def get_raw(self) :
        buff = writesleb128( self.size ) + ''.join(i.get_raw() for i in self.handlers)

        if self.size <= 0 :
            buff += writeuleb128( self.catch_all_addr )

        return buff

    def get_handlers(self) :
        return self.handlers

    def get_offset(self) :
        return self.__offset.off

    def get_size(self) :
        return self.size

    def get_catch_all_addr(self) :
        return self.catch_all_addr

class EncodedCatchHandlerList :
    def __init__(self, buff, cm) :
        self.__offset = cm.add_offset( buff.get_idx(), self ) 

        self.size = readuleb128( buff )
        self.list = []

        for i in xrange(0, self.size) :
            self.list.append( EncodedCatchHandler(buff, cm) )

    def show(self) :
        print "ENCODED_CATCH_HANDLER_LIST size=0x%x" % self.size
        for i in self.list :
            i.show()

    def get_obj(self) :
        return [ i for i in self.list ]

    def get_raw(self) :
        return writeuleb128( self.size ) + ''.join(i.get_raw() for i in self.list)

    def get_offset(self) :
        return self.__offset.off

    def get_list(self) :
        return self.list

DALVIK_OPCODES_PAYLOAD = {
    0x0100 : [PackedSwitch],
    0x0200 : [SparseSwitch],
    0x0300 : [FillArrayData],
}

DALVIK_OPCODES_EXPANDED = {
    0x00ff : [],
    0x01ff : [],
    0x02ff : [],
    0x03ff : [],
    0x04ff : [],
    0x05ff : [],

    0x06ff : [],
    0x07ff : [],
    0x08ff : [],
    0x09ff : [],
    0x10ff : [],
    0x11ff : [],
    0x12ff : [],
    0x13ff : [],

    0x14ff : [],
    0x15ff : [],
    0x16ff : [],
    0x17ff : [],
    0x18ff : [],
    0x19ff : [],
    0x20ff : [],
    0x21ff : [],


    0x22ff : [],
    0x23ff : [],
    0x24ff : [],
    0x25ff : [],
    0x26ff : [],
}


def get_kind(cm, kind, value) :
  if kind == KIND_METH :
    method = cm.get_method_ref(value)
    class_name = method.get_class()
    name = method.get_name()
    proto = method.get_proto()

    proto = proto[0] + proto[1]
    return "%s->%s%s" % (class_name, name, proto)
  elif kind == KIND_STRING :
    return repr(cm.get_string(value))
  elif kind == KIND_FIELD :
    class_name, proto, field_name = cm.get_field(value)
    return "%s->%s %s" % (class_name, field_name, proto)
  elif kind == KIND_TYPE :
    return cm.get_type(value)
  return None

class Instruction(object) :
  def __init__(self) :
    self.notes = []

  def get_kind(self) :
    return DALVIK_OPCODES_FORMAT[ self.OP ][1][1]

  def get_name(self) :
    return DALVIK_OPCODES_FORMAT[ self.OP ][1][0]

  def get_op_value(self) :
    return self.OP

  def get_literals(self) :
    return []

  def show(self, idx) :
    print self.get_name() + " " + self.get_output(idx),

  def show_buff(self, idx) :
    return self.get_output(idx)

  def get_translated_kind(self) :
    return get_kind(self.cm, self.get_kind(), self.get_ref_kind())

  def add_note(self, msg) :
    self.notes.append( msg )

  def get_notes(self) :
    return self.notes

class Instruction35c(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction35c, self).__init__()
      self.cm = cm

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.G = (i16 >> 8) & 0xf
      self.A = (i16 >> 12) & 0xf
      self.BBBB = unpack("=H", buff[2:4])[0]

      i16 = unpack("=H", buff[4:6])[0]
      self.C = i16 & 0xf
      self.D = (i16 >> 4) & 0xf
      self.E = (i16 >> 8) & 0xf
      self.F = (i16 >> 12) & 0xf

      #log_andro.debug("OP:%x %s G:%x A:%x BBBB:%x C:%x D:%x E:%x F:%x" % (self.OP, args[0], self.G, self.A, self.BBBB, self.C, self.D, self.E, self.F))

    def get_output(self, idx=-1) :
      buff = ""

      kind = get_kind(self.cm, self.get_kind(), self.BBBB)

      if self.A == 0 :
        buff += "%s" % (kind)
      elif self.A == 1 :
        buff += "v%d, %s" % (self.C, kind)
      elif self.A == 2 :
        buff += "v%d, v%d, %s" % (self.C, self.D, kind)
      elif self.A == 3 :
        buff += "v%d, v%d, v%d, %s" % (self.C, self.D, self.E, kind)
      elif self.A == 4 :
        buff += "v%d, v%d, v%d, v%d, %s" % (self.C, self.D, self.E, self.F, kind)
      elif self.A == 5 :
        buff += "v%d, v%d, v%d, v%d, v%d, %s" % (self.C, self.D, self.E, self.F, self.G, kind)

      return buff

    def get_length(self) :
      return 6

    def get_ref_kind(self) :
      return self.BBBB

    def get_raw(self) :
      return pack("=HHH", (self.A << 12) | (self.G << 8) | self.OP, self.BBBB, (self.F << 12) | (self.E << 8) | (self.D << 4) | self.C)

class Instruction10x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction10x, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff

      #log_andro.debug("OP:%x %s" % (self.OP, args[0]))

    def get_output(self, idx=-1) :
      buff = ""
      return buff

    def get_length(self) :
      return 2

    def get_raw(self) :
      return pack("=H", self.OP)

class Instruction21h(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction21h, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=h", buff[2:4])[0]

      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

      self.formatted_operands = []

      if self.OP == 0x15 :
        self.formatted_operands.append( unpack( '=f', '\x00\x00' + pack('=h', self.BBBB ) )[0] )
      elif self.OP == 0x19:
        self.formatted_operands.append( unpack( '=d', '\x00\x00\x00\x00\x00\x00' + pack('=h', self.BBBB) )[0] )

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
     
      buff += "v%d, #+%d" % (self.AA, self.BBBB)

      if self.formatted_operands != [] :
        buff += " // %s" % (str(self.formatted_operands))

      return buff

    def get_literals(self) :
      return [ self.BBBB ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction11n(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction11n, self).__init__()

      i16 = unpack("=h", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.A = (i16 >> 8) & 0xf
      self.B = (i16 >> 12) & 0xf

      #log_andro.debug("OP:%x %s A:%x B:%x" % (self.OP, args[0], self.A, self.B))

    def get_length(self) :
      return 2

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, #+%d" % (self.A, self.B)
      return buff

    def get_literals(self) :
      return [ self.B ]

    def get_raw(self) :
      return pack("=h", (self.B << 12) | (self.A << 8) | self.OP)

class Instruction21c(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction21c, self).__init__()
      self.cm = cm

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=h", buff[2:4])[0]
      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      
      kind = get_kind(self.cm, self.get_kind(), self.BBBB)

      buff += "v%d, %s" % (self.AA, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBB
    
    def get_string(self) :
      return get_kind(self.cm, self.get_kind(), self.BBBB)
   
    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction21s(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction21s, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=h", buff[2:4])[0]

      self.formatted_operands = []

      if self.OP == 0x16 :
        self.formatted_operands.append( unpack( '=d', pack('=d', self.BBBB))[0] )

      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, #+%d" % (self.AA, self.BBBB)

      if self.formatted_operands != [] :
        buff += " // %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBB ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction22c(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction22c, self).__init__()
      self.cm = cm

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.A = (i16 >> 8) & 0xf
      self.B = (i16 >> 12) & 0xf
      self.CCCC = unpack("=H", buff[2:4])[0]

      #log_andro.debug("OP:%x %s A:%x B:%x CCCC:%x" % (self.OP, args[0], self.A, self.B, self.CCCC))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      kind = get_kind(self.cm, self.get_kind(), self.CCCC)
      buff += "v%d, v%d, %s" % (self.A, self.B, kind)
      return buff

    def get_ref_kind(self) :
      return self.CCCC

    def get_raw(self) :
      return pack("=HH", (self.B << 12) | (self.A << 8) | (self.OP), self.CCCC)

class Instruction31t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction31t, self).__init__()
      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBBBBBB = unpack("=i", buff[2:6])[0]
      #log_andro.debug("OP:%x %s AA:%x BBBBBBBBB:%x" % (self.OP, args[0], self.AA, self.BBBBBBBB))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, +%x (0x%x)" % (self.AA, self.BBBBBBBB, self.BBBBBBBB * 2 + idx)

      return buff

    def get_ref_off(self) :
      return self.BBBBBBBB 

    def get_raw(self) :
      return pack("=Hi", (self.AA << 8) | self.OP, self.BBBBBBBB)

class Instruction31c(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction31c, self).__init__()
      self.cm = cm

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBBBBBB = unpack("=i", buff[2:6])[0]
      #log_andro.debug("OP:%x %s AA:%x BBBBBBBBB:%x" % (self.OP, args[0], self.AA, self.BBBBBBBB))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""

      kind = get_kind(self.cm, self.get_kind(), self.BBBBBBBB)
      buff += "v%d, %s" % (self.AA, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBBBBBB 

    def get_string(self) :
      return get_kind(self.cm, self.get_kind(), self.BBBBBBBB)

    def get_raw(self) :
      return pack("=Hi", (self.AA << 8) | self.OP, self.BBBBBBBB)

class Instruction12x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction12x, self).__init__()

      i16 = unpack("=h", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.A = (i16 >> 8) & 0xf
      self.B = (i16 >> 12) & 0xf

      #log_andro.debug("OP:%x %s A:%x B:%x" % (self.OP, args[0], self.A, self.B))

    def get_length(self) :
      return 2

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d" % (self.A, self.B)
      return buff

    def get_raw(self) :
      return pack("=H", (self.B << 12) | (self.A << 8) | (self.OP))

class Instruction11x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction11x, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      #log_andro.debug("OP:%x %s AA:%x" % (self.OP, args[0], self.AA))

    def get_length(self) :
      return 2

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d" % (self.AA)
      return buff

    def get_raw(self) :
      return pack("=H", (self.AA << 8) | self.OP)

class Instruction51l(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction51l, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBBBBBBBBBBBBBB = unpack("=q", buff[2:10])[0]

      self.formatted_operands = []

      if self.OP == 0x18 :
        self.formatted_operands.append( unpack( '=d', pack('=q', self.BBBBBBBBBBBBBBBB ) )[0] )

      #log_andro.debug("OP:%x %s AA:%x BBBBBBBBBBBBBBBB:%x" % (self.OP, args[0], self.AA, self.BBBBBBBBBBBBBBBB))

    def get_length(self) :
      return 10

    def get_output(self, idx=-1) :
      buff = ""

      buff += "v%d, #+%d" % (self.AA, self.BBBBBBBBBBBBBBBB)

      if self.formatted_operands != [] :
        buff += " // %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBBBBBBBBBBBBBB ]

    def get_raw(self) :
      return pack("=Hq", (self.AA << 8) | self.OP, self.BBBBBBBBBBBBBBBB)

class Instruction31i(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction31i, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBBBBBB = unpack("=i", buff[2:6])[0]

      self.formatted_operands = []

      if self.OP == 0x14 :
        self.formatted_operands.append( unpack("=f", pack("=i", self.BBBBBBBB))[0] )

      elif self.OP == 0x17 :
        self.formatted_operands.append( unpack( '=d', pack('=d', self.BBBBBBBB))[0] )

      #log_andro.debug("OP:%x %s AA:%x BBBBBBBBB:%x" % (self.OP, args[0], self.AA, self.BBBBBBBB))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, #+%d" % (self.AA, self.BBBBBBBB)

      if self.formatted_operands != [] :
        buff += " // %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBBBBBB ]

    def get_raw(self) :
      return pack("=Hi", (self.AA << 8) | self.OP, self.BBBBBBBB)

class Instruction22x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction22x, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=H", buff[2:4])[0]

      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d" % (self.AA, self.BBBB)
      return buff

    def get_raw(self) :
      return pack("=HH", (self.AA << 8) | self.OP, self.BBBB)

class Instruction23x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction23x, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      i16 = unpack("=H", buff[2:4])[0]
      self.BB = i16 & 0xff
      self.CC = (i16 >> 8) & 0xff

      #log_andro.debug("OP:%x %s AA:%x BB:%x CC:%x" % (self.OP, args[0], self.AA, self.BB, self.CC))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d, v%d" % (self.AA, self.BB, self.CC)
      return buff

    def get_raw(self) :
      return pack("=HH", (self.AA << 8) | self.OP, (self.CC << 8) | self.BB)

class Instruction20t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction20t, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AAAA = unpack("=h", buff[2:4])[0]

      #log_andro.debug("OP:%x %s AAAA:%x" % (self.OP, args[0], self.AAAA))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "%x" % (self.AAAA)
      return buff

    def get_ref_off(self) :
      return self.AAAA

    def get_raw(self) :
      return pack("=Hh", self.OP, self.AAAA)

class Instruction21t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction21t, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=h", buff[2:4])[0]

      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, +%d" % (self.AA, self.BBBB)
      return buff

    def get_ref_off(self) :
      return self.BBBB

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction10t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction10t, self).__init__()

      self.OP = unpack("=B", buff[0:1])[0]
      self.AA = unpack("=b", buff[1:2])[0]

      #log_andro.debug("OP:%x %s AA:%x" % (self.OP, args[0], self.AA))

    def get_length(self) :
      return 2

    def get_output(self, idx=-1) :
      buff = ""
      buff += "%x" % (self.AA)
      return buff

    def get_ref_off(self) :
      return self.AA

    def get_raw(self) :
      return pack("=Bb", self.OP, self.AA)

class Instruction22t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction22t, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.A = (i16 >> 8) & 0xf
      self.B = (i16 >> 12) & 0xf
      self.CCCC = unpack("=h", buff[2:4])[0]

      #log_andro.debug("OP:%x %s A:%x B:%x CCCC:%x" % (self.OP, args[0], self.A, self.B, self.CCCC))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d, +%d" % (self.A, self.B, self.CCCC)
      return buff

    def get_ref_off(self) :
      return self.CCCC

    def get_raw(self) :
      return pack("=Hh", (self.B << 12) | (self.A << 8) | self.OP, self.CCCC)

class Instruction22s(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction22s, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.A = (i16 >> 8) & 0xf
      self.B = (i16 >> 12) & 0xf
      self.CCCC = unpack("=h", buff[2:4])[0]

      #log_andro.debug("OP:%x %s A:%x B:%x CCCC:%x" % (self.OP, args[0], self.A, self.B, self.CCCC))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d, #+%d" % (self.A, self.B, self.CCCC)
      return buff

    def get_literals(self) :
      return [ self.CCCC ]

    def get_raw(self) :
      return pack("=Hh", (self.B << 12) | (self.A << 8) | self.OP, self.CCCC)

class Instruction22b(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction22b, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BB = unpack("=B", buff[2:3])[0]
      self.CC = unpack("=b", buff[3:4])[0]

      #log_andro.debug("OP:%x %s AA:%x BB:%x CC:%x" % (self.OP, args[0], self.AA, self.BB, self.CC))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d, #+%d" % (self.AA, self.BB, self.CC)
      return buff

    def get_literals(self) :
      return [ self.CC ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, (self.CC << 8) | self.BB)

class Instruction30t(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction30t, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff

      self.AAAAAAAA = unpack("=i", buff[2:6])[0]

      #log_andro.debug("OP:%x %s AAAAAAAA:%x" % (self.OP, args[0], self.AAAAAAAA))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""
      buff += "%x" % (self.AAAAAAAA)
      return buff

    def get_ref_off(self) :
      return self.AAAAAAAA

    def get_raw(self) :
      return pack("=Hi", self.OP, self.AAAAAAAA)

class Instruction3rc(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction3rc, self).__init__()
      self.cm = cm

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=H", buff[2:4])[0]
      self.CCCC = unpack("=H", buff[4:6])[0]

      self.NNNN = self.CCCC + self.AA - 1

      #log_andro.debug("OP:%x %s AA:%x BBBB:%x CCCC:%x NNNN:%d" % (self.OP, args[0], self.AA, self.BBBB, self.CCCC, self.NNNN))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""

      kind = get_kind(self.cm, self.get_kind(), self.BBBB)

      if self.CCCC == self.NNNN :
        buff += "v%d, %s" % (self.CCCC, kind)
      else :
        buff += "v%d ... v%d, %s" % (self.CCCC, self.NNNN, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBB

    def get_raw(self) :
      return pack("=HHH", (self.AA << 8) | self.OP, self.BBBB, self.CCCC)

class Instruction32x(Instruction) :
    def __init__(self, cm, buff) :
      super(Instruction32x, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AAAA =  unpack("=H", buff[2:4])[0]
      self.BBBB =  unpack("=H", buff[4:6])[0]

      #log_andro.debug("OP:%x %s AAAAA:%x BBBBB:%x" % (self.OP, args[0], self.AAAA, self.BBBB))

    def get_length(self) :
      return 6

    def get_output(self, idx=-1) :
      buff = ""
      buff += "v%d, v%d" % (self.AAAA, self.BBBBB)
      return buff

    def get_raw(self) :
      return pack("=HHH", self.OP, self.AAAA, self.BBBB)

KIND_METH = 0
KIND_STRING = 1
KIND_FIELD = 2
KIND_TYPE = 3

DALVIK_OPCODES_FORMAT = {
  0x00 : [Instruction10x, [ "nop" ] ],
  0x01 : [Instruction12x, [ "move" ] ],
  0x02 : [Instruction22x, [ "move/from16" ] ],
  0x03 : [Instruction32x, [ "move/16" ] ],
  0x04 : [Instruction12x, [ "move-wide" ] ],
  0x05 : [Instruction22x, [ "move-wide/from16" ] ],
  0x06 : [Instruction32x, [ "move-wide/16" ] ],
  0x07 : [Instruction12x, [ "move-object" ] ],
  0x08 : [Instruction22x, [ "move-object/from16" ] ],
  0x09 : [Instruction32x, [ "move-object/16" ] ],
  0x0a : [Instruction11x, [ "move-result" ] ],
  0x0b : [Instruction11x, [ "move-result-wide" ] ],
  0x0c : [Instruction11x, [ "move-result-object" ] ],
  0x0d : [Instruction11x, [ "move-exception" ] ],
  0x0e : [Instruction10x, [ "return-void" ] ],
  0x0f : [Instruction11x, [ "return" ] ],
  0x10 : [Instruction11x, [ "return-wide" ] ],
  0x11 : [Instruction11x, [ "return-object" ] ],
  0x12 : [Instruction11n, [ "const/4" ] ],
  0x13 : [Instruction21s, [ "const/16" ] ],
  0x14 : [Instruction31i, [ "const" ] ],
  0x15 : [Instruction21h, [ "const/high16" ] ],
  0x16 : [Instruction21s, [ "const-wide/16" ] ],
  0x17 : [Instruction31i, [ "const-wide/32" ] ],
  0x18 : [Instruction51l, [ "const-wide" ] ],
  0x19 : [Instruction21h, [ "const-wide/high16" ] ],
  0x1a : [Instruction21c, [ "const-string", KIND_STRING ] ],
  0x1b : [Instruction31c, [ "const-string/jumbo", KIND_STRING ] ],
  0x1c : [Instruction21c, [ "const-class", KIND_TYPE ] ],
  0x1d : [Instruction11x, [ "monitor-enter" ] ],
  0x1e : [Instruction11x, [ "monitor-exit" ] ],
  0x1f : [Instruction21c, [ "check-cast", KIND_TYPE ] ],
  0x20 : [Instruction22c, [ "instance-of", KIND_TYPE ] ],
  0x21 : [Instruction12x, [ "array-length", KIND_TYPE ] ],
  0x22 : [Instruction21c, [ "new-instance", KIND_TYPE ] ],
  0x23 : [Instruction22c, [ "new-array", KIND_TYPE ] ],

  0x24 : [Instruction35c, [ "filled-new-array", KIND_TYPE ] ],
  0x25 : [Instruction3rc, [ "filled-new-array/range", KIND_TYPE ] ],
  0x26 : [Instruction31t, [ "fill-array-data" ] ],

  0x27 : [Instruction11x, [ "throw" ] ],

  0x28 : [Instruction10t, [ "goto" ] ],
  0x29 : [Instruction20t, [ "goto/16" ] ],
  0x2a : [Instruction30t, [ "goto/32" ] ],

  0x2b : [Instruction31t, [ "packed-switch" ] ],
  0x2c : [Instruction31t, [ "sparse-switch" ] ],

  0x2d : [Instruction23x, [ "cmpl-float"  ] ],
  0x2e : [Instruction23x, [ "cmpg-float" ] ],
  0x2f : [Instruction23x, [ "cmpl-double" ] ],
  0x30 : [Instruction23x, [ "cmpg-double" ] ],
  0x31 : [Instruction23x, [ "cmp-long" ] ],

  0x32 : [Instruction22t, [ "if-eq" ] ],
  0x33 : [Instruction22t, [ "if-ne" ] ],
  0x34 : [Instruction22t, [ "if-lt" ] ],
  0x35 : [Instruction22t, [ "if-ge" ] ],
  0x36 : [Instruction22t, [ "if-gt" ] ],
  0x37 : [Instruction22t, [ "if-le" ] ],

  0x38 : [Instruction21t, [ "if-eqz" ] ],
  0x39 : [Instruction21t, [ "if-nez" ] ],
  0x3a : [Instruction21t, [ "if-ltz" ] ],
  0x3b : [Instruction21t, [ "if-gez" ] ],
  0x3c : [Instruction21t, [ "if-gtz" ] ],
  0x3d : [Instruction21t, [ "if-lez" ] ],

  #unused
  0x3e : [Instruction10x, [ "nop" ] ],
  0x3f : [Instruction10x, [ "nop" ] ],
  0x40 : [Instruction10x, [ "nop" ] ],
  0x41 : [Instruction10x, [ "nop" ] ],
  0x42 : [Instruction10x, [ "nop" ] ],
  0x43 : [Instruction10x, [ "nop" ] ],

  0x44 : [Instruction23x, [ "aget" ] ],
  0x45 : [Instruction23x, [ "aget-wide" ] ],
  0x46 : [Instruction23x, [ "aget-object" ] ],
  0x47 : [Instruction23x, [ "aget-boolean" ] ],
  0x48 : [Instruction23x, [ "aget-byte" ] ],
  0x49 : [Instruction23x, [ "aget-char" ] ],
  0x4a : [Instruction23x, [ "aget-short" ] ],
  0x4b : [Instruction23x, [ "aput" ] ],
  0x4c : [Instruction23x, [ "aput-wide" ] ],
  0x4d : [Instruction23x, [ "aput-object" ] ],
  0x4e : [Instruction23x, [ "aput-boolean" ] ],
  0x4f : [Instruction23x, [ "aput-byte" ] ],
  0x50 : [Instruction23x, [ "aput-char" ] ],
  0x51 : [Instruction23x, [ "aput-short" ] ],

  0x52 : [Instruction22c, [ "iget", KIND_FIELD ] ],
  0x53 : [Instruction22c, [ "iget-wide", KIND_FIELD ] ],
  0x54 : [Instruction22c, [ "iget-object", KIND_FIELD ] ],
  0x55 : [Instruction22c, [ "iget-boolean", KIND_FIELD ] ],
  0x56 : [Instruction22c, [ "iget-byte", KIND_FIELD ] ],
  0x57 : [Instruction22c, [ "iget-char", KIND_FIELD ] ],
  0x58 : [Instruction22c, [ "iget-short", KIND_FIELD ] ],
  0x59 : [Instruction22c, [ "iput", KIND_FIELD ] ],
  0x5a : [Instruction22c, [ "iput-wide", KIND_FIELD ] ],
  0x5b : [Instruction22c, [ "iput-object", KIND_FIELD ] ],
  0x5c : [Instruction22c, [ "iput-boolean", KIND_FIELD ] ],
  0x5d : [Instruction22c, [ "iput-byte", KIND_FIELD ] ],
  0x5e : [Instruction22c, [ "iput-char", KIND_FIELD ] ],
  0x5f : [Instruction22c, [ "iput-short", KIND_FIELD ] ],


  0x60 : [Instruction21c, [ "sget", KIND_FIELD ] ],
  0x61 : [Instruction21c, [ "sget-wide", KIND_FIELD ] ],
  0x62 : [Instruction21c, [ "sget-object", KIND_FIELD ] ],
  0x63 : [Instruction21c, [ "sget-boolean", KIND_FIELD ] ],
  0x64 : [Instruction21c, [ "sget-byte", KIND_FIELD ] ],
  0x65 : [Instruction21c, [ "sget-char", KIND_FIELD ] ],
  0x66 : [Instruction21c, [ "sget-short", KIND_FIELD ] ],
  0x67 : [Instruction21c, [ "sput", KIND_FIELD ] ],
  0x68 : [Instruction21c, [ "sput-wide", KIND_FIELD ] ],
  0x69 : [Instruction21c, [ "sput-object", KIND_FIELD ] ],
  0x6a : [Instruction21c, [ "sput-boolean", KIND_FIELD ] ],
  0x6b : [Instruction21c, [ "sput-byte", KIND_FIELD ] ],
  0x6c : [Instruction21c, [ "sput-char", KIND_FIELD ] ],
  0x6d : [Instruction21c, [ "sput-short", KIND_FIELD ] ],


  0x6e : [Instruction35c, [ "invoke-virtual", KIND_METH ] ],
  0x6f : [Instruction35c, [ "invoke-super", KIND_METH ] ],
  0x70 : [Instruction35c, [ "invoke-direct", KIND_METH ] ],
  0x71 : [Instruction35c, [ "invoke-static", KIND_METH ] ],
  0x72 : [Instruction35c, [ "invoke-interface", KIND_METH ] ],

  # unused
  0x73 : [Instruction10x, [ "nop" ] ],

  0x74 : [Instruction3rc, [ "invoke-virtual/range", KIND_METH ] ],
  0x75 : [Instruction3rc, [ "invoke-super/range", KIND_METH ] ],
  0x76 : [Instruction3rc, [ "invoke-direct/range", KIND_METH ] ],
  0x77 : [Instruction3rc, [ "invoke-static/range", KIND_METH ] ],
  0x78 : [Instruction3rc, [ "invoke-interface/range", KIND_METH ] ],

  # unused
  0x79 : [Instruction10x, [ "nop" ] ],
  0x7a : [Instruction10x, [ "nop" ] ],


  0x7b : [Instruction12x, [ "neg-int" ] ],
  0x7c : [Instruction12x, [ "not-int" ] ],
  0x7d : [Instruction12x, [ "neg-long" ] ],
  0x7e : [Instruction12x, [ "not-long" ] ],
  0x7f : [Instruction12x, [ "neg-float" ] ],
  0x80 : [Instruction12x, [ "neg-double" ] ],
  0x81 : [Instruction12x, [ "int-to-long" ] ],
  0x82 : [Instruction12x, [ "int-to-float" ] ],
  0x83 : [Instruction12x, [ "int-to-double" ] ],
  0x84 : [Instruction12x, [ "long-to-int" ] ],
  0x85 : [Instruction12x, [ "long-to-float" ] ],
  0x86 : [Instruction12x, [ "long-to-double" ] ],
  0x87 : [Instruction12x, [ "float-to-int" ] ],
  0x88 : [Instruction12x, [ "float-to-long" ] ],
  0x89 : [Instruction12x, [ "float-to-double" ] ],
  0x8a : [Instruction12x, [ "double-to-int" ] ],
  0x8b : [Instruction12x, [ "double-to-long" ] ],
  0x8c : [Instruction12x, [ "double-to-float" ] ],
  0x8d : [Instruction12x, [ "int-to-byte" ] ],
  0x8e : [Instruction12x, [ "int-to-char" ] ],
  0x8f : [Instruction12x, [ "int-to-short" ] ],


  0x90 : [Instruction23x, [ "add-int" ] ],
  0x91 : [Instruction23x, [ "sub-int" ] ],
  0x92 : [Instruction23x, [ "mul-int" ] ],
  0x93 : [Instruction23x, [ "div-int" ] ],
  0x94 : [Instruction23x, [ "rem-int" ] ],
  0x95 : [Instruction23x, [ "and-int" ] ],
  0x96 : [Instruction23x, [ "or-int" ] ],
  0x97 : [Instruction23x, [ "xor-int" ] ],
  0x98 : [Instruction23x, [ "shl-int" ] ],
  0x99 : [Instruction23x, [ "shr-int" ] ],
  0x9a : [Instruction23x, [ "ushr-int" ] ],
  0x9b : [Instruction23x, [ "add-long" ] ],
  0x9c : [Instruction23x, [ "sub-long" ] ],
  0x9d : [Instruction23x, [ "mul-long" ] ],
  0x9e : [Instruction23x, [ "div-long" ] ],
  0x9f : [Instruction23x, [ "rem-long" ] ],
  0xa0 : [Instruction23x, [ "and-long" ] ],
  0xa1 : [Instruction23x, [ "or-long" ] ],
  0xa2 : [Instruction23x, [ "xor-long" ] ],
  0xa3 : [Instruction23x, [ "shl-long" ] ],
  0xa4 : [Instruction23x, [ "shr-long" ] ],
  0xa5 : [Instruction23x, [ "ushr-long" ] ],
  0xa6 : [Instruction23x, [ "add-float" ] ],
  0xa7 : [Instruction23x, [ "sub-float" ] ],
  0xa8 : [Instruction23x, [ "mul-float" ] ],
  0xa9 : [Instruction23x, [ "div-float" ] ],
  0xaa : [Instruction23x, [ "rem-float" ] ],
  0xab : [Instruction23x, [ "add-double" ] ],
  0xac : [Instruction23x, [ "sub-double" ] ],
  0xad : [Instruction23x, [ "mul-double" ] ],
  0xae : [Instruction23x, [ "div-double" ] ],
  0xaf : [Instruction23x, [ "rem-double" ] ],


  0xb0 : [Instruction12x, [ "add-int/2addr" ] ],
  0xb1 : [Instruction12x, [ "sub-int/2addr" ] ],
  0xb2 : [Instruction12x, [ "mul-int/2addr" ] ],
  0xb3 : [Instruction12x, [ "div-int/2addr" ] ],
  0xb4 : [Instruction12x, [ "rem-int/2addr" ] ],
  0xb5 : [Instruction12x, [ "and-int/2addr" ] ],
  0xb6 : [Instruction12x, [ "or-int/2addr" ] ],
  0xb7 : [Instruction12x, [ "xor-int/2addr" ] ],
  0xb8 : [Instruction12x, [ "shl-int/2addr" ] ],
  0xb9 : [Instruction12x, [ "shr-int/2addr" ] ],
  0xba : [Instruction12x, [ "ushr-int/2addr" ] ],
  0xbb : [Instruction12x, [ "add-long/2addr" ] ],
  0xbc : [Instruction12x, [ "sub-long/2addr" ] ],
  0xbd : [Instruction12x, [ "mul-long/2addr" ] ],
  0xbe : [Instruction12x, [ "div-long/2addr" ] ],
  0xbf : [Instruction12x, [ "rem-long/2addr" ] ],
  0xc0 : [Instruction12x, [ "and-long/2addr" ] ],
  0xc1 : [Instruction12x, [ "or-long/2addr" ] ],
  0xc2 : [Instruction12x, [ "xor-long/2addr" ] ],
  0xc3 : [Instruction12x, [ "shl-long/2addr" ] ],
  0xc4 : [Instruction12x, [ "shr-long/2addr" ] ],
  0xc5 : [Instruction12x, [ "ushr-long/2addr" ] ],
  0xc6 : [Instruction12x, [ "add-float/2addr" ] ],
  0xc7 : [Instruction12x, [ "sub-float/2addr" ] ],
  0xc8 : [Instruction12x, [ "mul-float/2addr" ] ],
  0xc9 : [Instruction12x, [ "div-float/2addr" ] ],
  0xca : [Instruction12x, [ "rem-float/2addr" ] ],
  0xcb : [Instruction12x, [ "add-double/2addr" ] ],
  0xcc : [Instruction12x, [ "sub-double/2addr" ] ],
  0xcd : [Instruction12x, [ "mul-double/2addr" ] ],
  0xce : [Instruction12x, [ "div-double/2addr" ] ],
  0xcf : [Instruction12x, [ "rem-double/2addr" ] ],

  0xd0 : [Instruction22s, [ "add-int/lit16" ] ],
  0xd1 : [Instruction22s, [ "rsub-int" ] ],
  0xd2 : [Instruction22s, [ "mul-int/lit16" ] ],
  0xd3 : [Instruction22s, [ "div-int/lit16" ] ],
  0xd4 : [Instruction22s, [ "rem-int/lit16" ] ],
  0xd5 : [Instruction22s, [ "and-int/lit16" ] ],
  0xd6 : [Instruction22s, [ "or-int/lit16" ] ],
  0xd7 : [Instruction22s, [ "xor-int/lit16" ] ],


  0xd8 : [Instruction22b, [ "add-int/lit8" ] ],
  0xd9 : [Instruction22b, [ "rsub-int/lit8" ] ],
  0xda : [Instruction22b, [ "mul-int/lit8" ] ],
  0xdb : [Instruction22b, [ "div-int/lit8" ] ],
  0xdc : [Instruction22b, [ "rem-int/lit8" ] ],
  0xdd : [Instruction22b, [ "and-int/lit8" ] ],
  0xde : [Instruction22b, [ "or-int/lit8" ] ],
  0xdf : [Instruction22b, [ "xor-int/lit8" ] ],
  0xe0 : [Instruction22b, [ "shl-int/lit8" ] ],
  0xe1 : [Instruction22b, [ "shr-int/lit8" ] ],
  0xe2 : [Instruction22b, [ "ushr-int/lit8" ] ],


  # unused
  0xe3 : [Instruction10x, [ "nop" ] ],
  0xe4 : [Instruction10x, [ "nop" ] ],
  0xe5 : [Instruction10x, [ "nop" ] ],
  0xe6 : [Instruction10x, [ "nop" ] ],
  0xe7 : [Instruction10x, [ "nop" ] ],
  0xe8 : [Instruction10x, [ "nop" ] ],
  0xe9 : [Instruction10x, [ "nop" ] ],
  0xea : [Instruction10x, [ "nop" ] ],
  0xeb : [Instruction10x, [ "nop" ] ],
  0xec : [Instruction10x, [ "nop" ] ],
  0xed : [Instruction10x, [ "nop" ] ],
  0xee : [Instruction10x, [ "nop" ] ],
  0xef : [Instruction10x, [ "nop" ] ],
  0xf0 : [Instruction10x, [ "nop" ] ],
  0xf1 : [Instruction10x, [ "nop" ] ],
  0xf2 : [Instruction10x, [ "nop" ] ],
  0xf3 : [Instruction10x, [ "nop" ] ],
  0xf4 : [Instruction10x, [ "nop" ] ],
  0xf5 : [Instruction10x, [ "nop" ] ],
  0xf6 : [Instruction10x, [ "nop" ] ],
  0xf7 : [Instruction10x, [ "nop" ] ],
  0xf8 : [Instruction10x, [ "nop" ] ],
  0xf9 : [Instruction10x, [ "nop" ] ],
  0xfa : [Instruction10x, [ "nop" ] ],
  0xfb : [Instruction10x, [ "nop" ] ],
  0xfc : [Instruction10x, [ "nop" ] ],
  0xfd : [Instruction10x, [ "nop" ] ],
  0xfe : [Instruction10x, [ "nop" ] ],
}

def get_instruction(cm, op_value, buff) :
  #print "Parsing instruction %x" % op_value
  return DALVIK_OPCODES_FORMAT[ op_value ][0]( cm, buff )

# FIXME
def get_expanded_instruction(cm, op_value, buff) :
  return Instruction10x( cm, buff )

def get_instruction_payload(op_value, buff) :
  #print "Parsing instruction payload %x" % op_value
  return DALVIK_OPCODES_PAYLOAD[ op_value ][0]( buff )

class DCode :
    def __init__(self, class_manager, size, buff) :
        self.__CM = class_manager
        self.__insn = buff
        self.size = size

        self.bytecodes = []

    def get_instructions(self) :
        #print "New method ....", size * calcsize( '<H' )

        # Get instructions
        idx = 0
        while idx < (self.size * calcsize( '=H' )) :
          obj = None

          #print "idx = %x" % idx
          op_value = unpack( '=B', self.__insn[idx] )[0]
          #print "First %x" % op_value
          if op_value in DALVIK_OPCODES_FORMAT :
            if op_value == 0x00 or op_value == 0xff:
              op_value = unpack( '=H', self.__insn[idx:idx+2] )[0]
              #print "Second %x" % op_value
              if op_value in DALVIK_OPCODES_PAYLOAD :
                obj = get_instruction_payload( op_value, self.__insn[idx:] )
              else :
                op_value = unpack( '=B', self.__insn[idx] )[0]
                obj = get_instruction( self.__CM, op_value, self.__insn[idx:] )
            else :
              op_value = unpack( '=B', self.__insn[idx] )[0]
              obj = get_instruction( self.__CM, op_value, self.__insn[idx:] )
          else :
              op_value = unpack( '=H', self.__insn[idx:idx+2] )[0]
              #print "Second %x" % op_value
              if op_value in DALVIK_OPCODES_EXPANDED :
                pass
              obj = get_expanded_instruction( self.__CM, op_value, self.__insn[idx:] )


          yield obj
          idx = idx + obj.get_length()

    def reload(self) :
        pass

    def get(self) :
      return self.get_instructions()

    def add_inote(self, msg, idx, off=None) :
      if off != None :
        idx = self.off_to_pos(off)
      self.bytecodes[ idx ].add_note(msg)

    def get_instruction(self, idx, off=None) :
        if off != None :
          idx = self.off_to_pos(off)
        return self.bytecodes[idx]

    def off_to_pos(self, off) :
        idx = 0
        nb = 0
        for i in self.bytecodes :
            if idx == off :
                return nb
            nb += 1
            idx += i.get_length()
        return -1

    def get_ins_off(self, off) :
        idx = 0
        for i in self.get_instructions() :
            if idx == off :
                return i
            idx += i.get_length()
        return None

    def show(self) :
        nb = 0
        idx = 0
        for i in self.bytecodes :
            print nb, "0x%x" % idx,
            i.show(nb)
            print

            idx += i.get_length()
            nb += 1

    def pretty_show(self, m_a) :
        bytecode.PrettyShow( m_a.basic_blocks.gets() )
        bytecode.PrettyShowEx( m_a.exceptions.gets() )

    def get_raw(self) :
        return ''.join(i.get_raw() for i in self.bytecodes)

class TryItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.start_addr = unpack("=I", buff.read(4))[0]
        self.insn_count = unpack("=H", buff.read(2))[0]
        self.handler_off = unpack("=H", buff.read(2))[0]

    def get_start_addr(self) :
        return self.start_addr

    def get_insn_count(self) :
        return self.insn_count

    def get_handler_off(self) :
        return self.handler_off

    def get_off(self) :
        return self.__offset.off

    def get_raw(self) :
        return pack("=I", self.start_addr) + pack("=H", self.insn_count) + pack("=H", self.handler_off)

class DalvikCode :
    def __init__(self, buff, cm) :
        self.__CM = cm

        off = buff.get_idx()
        while off % 4 != 0 :
            off += 1
        buff.set_idx( off )

        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.__off = buff.get_idx()

        self.registers_size = unpack("=H", buff.read(2))[0]
        self.ins_size = unpack("=H", buff.read(2))[0]
        self.outs_size = unpack("=H", buff.read(2))[0]
        self.tries_size = unpack("=H", buff.read(2))[0]
        self.debug_info_off = unpack("=I", buff.read(4))[0]
        self.insns_size = unpack("=I", buff.read(4))[0]

        ushort = calcsize( '=H' )

        self.code = DCode( self.__CM, self.insns_size, buff.read( self.insns_size * ushort ) )

        if (self.insns_size % 2 == 1) :
            self.__padding = unpack("=H", buff.read(2))[0]

        self.tries = []
        self.handlers = None 
        if self.tries_size > 0 :
            for i in xrange(0, self.tries_size) :
                self.tries.append( TryItem( buff, self.__CM ) )

            self.handlers = EncodedCatchHandlerList( buff, self.__CM )

    def reload(self) :
        self.code.reload()

    def get_length(self) :
        return self.insns_size

    def get_bc(self) :
        return self.code

    def get_off(self) :
        return self.__off

    def _begin_show(self) :
      bytecode._PrintBanner() 

    def show(self) :
        self._begin_show()
        self.code.show()
        self._end_show()

    def _end_show(self) :
      bytecode._PrintBanner() 

    def pretty_show(self, m_a) :
        self._begin_show()
        self.code.pretty_show(m_a)
        self._end_show()

    def get_obj(self) :
        return [ i for i in self.__handlers ]

    def get_raw(self) :
        buff =  pack("=H", self.registers_size) + \
                pack("=H", self.ins_size) + \
                pack("=H", self.outs_size) + \
                pack("=H", self.tries_size) + \
                pack("=I", self.debug_info_off) + \
                pack("=I", self.insns_size) + \
                self.code.get_raw()

        if (self.insns_size % 2 == 1) :
            buff += pack("=H", self.__padding)

        if self.tries_size > 0 :
            buff += ''.join(i.get_raw() for i in self.tries)
            buff += self.handlers.get_raw()

        return bytecode.Buff( self.__offset.off,
                                     buff )

    def get_tries_size(self) :
        return self.tries_size

    def get_handlers(self) :
        return self.handlers

    def get_tries(self) :
        return self.tries

    def add_inote(self, msg, idx, off=None) :
        if self.code :
            return self.code.add_inote(msg, idx, off)

    def get_instruction(self, idx, off=None) :
        if self.code :
            return self.code.get_instruction(idx, off)

class CodeItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.code = []
        self.__code_off = {}

        for i in xrange(0, size) :
            x = DalvikCode( buff, cm )
            self.code.append( x )
            self.__code_off[ x.get_off() ] = x

    def get_code(self, off) :
        try :
            return self.__code_off[off]
        except KeyError :
            return None

    def reload(self) :
        for i in self.code :
            i.reload()

    def show(self) :
        print "CODE_ITEM"
        for i in self.code :
            i.show()

    def get_obj(self) :
        return [ i for i in self.code ]

    def get_raw(self) :
        return [ i.get_raw() for i in self.code ]

    def get_off(self) :
        return self.__offset.off

class MapItem :
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.__offset = self.__CM.add_offset( buff.get_idx(), self )

        self.type = unpack("=H", buff.read(2))[0]
        self.unused = unpack("=H", buff.read(2))[0]
        self.size = unpack("=I", buff.read(4))[0]
        self.offset = unpack("=I", buff.read(4))[0]

        self.item = None

        buff.set_idx( self.offset )

        lazy_analysis = self.__CM.get_lazy_analysis()

        if lazy_analysis :
          self.next_lazy(buff, cm)
        else :
          self.next(buff, cm)

    def next(self, buff, cm) :
#        print TYPE_MAP_ITEM[ self.type ], "@ 0x%x(%d) %d %d" % (buff.get_idx(), buff.get_idx(), self.size, self.offset)

        if TYPE_MAP_ITEM[ self.type ] == "TYPE_STRING_ID_ITEM" :
            self.item = [ StringIdItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CODE_ITEM" :
            self.item = CodeItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_TYPE_ID_ITEM" :
            self.item = TypeIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_PROTO_ID_ITEM" :
            self.item = ProtoIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_FIELD_ID_ITEM" :
            self.item = FieldIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_METHOD_ID_ITEM" :
            self.item = MethodIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CLASS_DEF_ITEM" :
            self.item = ClassDefItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_HEADER_ITEM" :
            self.item = HeaderItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ANNOTATION_ITEM" :
            self.item = [ AnnotationItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ANNOTATION_SET_ITEM" :
            self.item = [ AnnotationSetItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ANNOTATIONS_DIRECTORY_ITEM" :
            self.item = [ AnnotationsDirectoryItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ANNOTATION_SET_REF_LIST" :
            self.item = [ AnnotationSetRefList( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_TYPE_LIST" :
            self.item = [ TypeList( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_STRING_DATA_ITEM" :
            self.item = [ StringDataItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_DEBUG_INFO_ITEM" :
            #self.item = []
            #for i in range(0, self.size) :
             #   print "nb =", i
             #   self.item.append( DebugInfoItem( buff, cm ) )
            self.item = DebugInfoItem2( buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ENCODED_ARRAY_ITEM" :
            self.item = [ EncodedArrayItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CLASS_DATA_ITEM" :
            self.item = [ ClassDataItem(buff, cm) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_MAP_LIST" :
            pass # It's me I think !!!

        else :
            bytecode.Exit( "Map item %d @ 0x%x(%d) is unknown" % (self.type, buff.get_idx(), buff.get_idx()) )

    def next_lazy(self, buff, cm) :
        if TYPE_MAP_ITEM[ self.type ] == "TYPE_STRING_ID_ITEM" :
            self.item = [ StringIdItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CODE_ITEM" :
            self.item = CodeItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_TYPE_ID_ITEM" :
            self.item = TypeIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_PROTO_ID_ITEM" :
            self.item = ProtoIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_FIELD_ID_ITEM" :
            self.item = FieldIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_METHOD_ID_ITEM" :
            self.item = MethodIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CLASS_DEF_ITEM" :
            self.item = ClassDefItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_HEADER_ITEM" :
            self.item = HeaderItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_TYPE_LIST" :
            self.item = [ TypeList( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_STRING_DATA_ITEM" :
            self.item = [ StringDataItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_DEBUG_INFO_ITEM" :
            self.item = DebugInfoItem2( buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_ENCODED_ARRAY_ITEM" :
            self.item = [ EncodedArrayItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CLASS_DATA_ITEM" :
            self.item = [ ClassDataItem(buff, cm) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_MAP_LIST" :
            pass # It's me I think !!!


    def reload(self) :
        if self.item != None :
            if isinstance( self.item, list ):
                for i in self.item :
                    i.reload()
            else :
                self.item.reload()

    def show(self) :
        bytecode._Print( "\tMAP_TYPE_ITEM", TYPE_MAP_ITEM[ self.type ])

        if self.item != None :
            if isinstance( self.item, list ):
                for i in self.item :
                    i.show()
            else :
                if isinstance(self.item, CodeItem) == False :
                    self.item.show()

    def pretty_show(self) :
        bytecode._Print( "\tMAP_TYPE_ITEM", TYPE_MAP_ITEM[ self.type ])

        if self.item != None :
            if isinstance( self.item, list ):
                for i in self.item :
                    if isinstance(i, ClassDataItem) :
                        i.pretty_show()
                    elif isinstance(self.item, CodeItem) == False :
                        i.show()
            else :
                if isinstance(self.item, ClassDataItem) :
                    self.item.pretty_show()
                elif isinstance(self.item, CodeItem) == False :
                    self.item.show()

    def get_obj(self) :
        if self.item == None :
            return []

        if isinstance( self.item, list ) :
            return [ i for i in self.item ]

        return [ self.item ]

    def get_raw(self) :
        first_raw = bytecode.Buff( self.__offset.off, pack("=H", self.type) + pack("=H", self.unused) + pack("=I", self.size) + pack("=I", self.offset) )

        if self.item == None :
            return [ first_raw ]
        else :
            if isinstance( self.item, list ) :
                return [ first_raw ] + [ i.get_raw() for i in self.item ]
            else :
                return [ first_raw ] + self.item.get_raw()

    def get_length(self) :
        return calcsize( "=HHII" )

    def get_type(self) :
        return self.type

    def get_item(self) :
        return self.item

class OffObj :
    def __init__(self, o) :
        self.off = o

class ClassManager :
    def __init__(self) :
        self.decompiler_ob = None
        self.vmanalysis_ob = None
        self.gvmanalysis_ob = None

        self.__manage_item = {}
        self.__manage_item_off = []
        self.__offsets = {}

        self.__strings_off = {}

        self.__cached_type_list = {}
        self.__cached_proto = {}

        self.recode_ascii_string = CONF["RECODE_ASCII_STRING"]
        self.recode_ascii_string_meth = CONF["RECODE_ASCII_STRING_METH"]

        self.lazy_analysis = CONF["LAZY_ANALYSIS"]

        self.hook_strings = {}

        self.engine = []
        self.engine.append("python")

    def get_lazy_analysis(self) :
      return self.lazy_analysis

    def get_vmanalysis(self) :
        return self.vmanalysis_ob

    def set_vmanalysis(self, vmanalysis) :
        self.vmanalysis_ob = vmanalysis
    
    def get_gvmanalysis(self) :
        return self.gvmanalysis_ob

    def set_gvmanalysis(self, gvmanalysis) :
        self.gvmanalysis_ob = gvmanalysis

    def set_decompiler(self, decompiler) :
        self.decompiler_ob = decompiler

    def get_engine(self) :
        return self.engine[0]

    def get_all_engine(self) :
        return self.engine

    def add_offset(self, off, obj) :
        x = OffObj( off )
        self.__offsets[ obj ] = x
        return x

    def add_type_item(self, type_item, item) :
        self.__manage_item[ type_item ] = item

        sdi = False
        if type_item == "TYPE_STRING_DATA_ITEM" :
            sdi = True

        if item != None :
            if isinstance(item, list) :
                for i in item :
                    goff = i.get_off()
                    self.__manage_item_off.append( goff )
                    if sdi == True :
                      self.__strings_off[ goff ] = i
            else :
                self.__manage_item_off.append( item.get_off() )

    def get_code(self, idx) :
        try :
            return self.__manage_item[ "TYPE_CODE_ITEM" ].get_code( idx )
        except KeyError :
            return None

    def get_class_data_item(self, off) :
        for i in self.__manage_item[ "TYPE_CLASS_DATA_ITEM" ] :
            if i.get_off() == off :
                return i

        bytecode.Exit( "unknown class data item @ 0x%x" % off )

    def get_encoded_array_item(self, off) :
        for i in self.__manage_item["TYPE_ENCODED_ARRAY_ITEM" ] :
            if i.get_off() == off :
                return i

    def get_string(self, idx) :
        if idx in self.hook_strings :
            return self.hook_strings[ idx ]

        off = self.__manage_item[ "TYPE_STRING_ID_ITEM" ][idx].get_data_off()
        try :
            if self.recode_ascii_string :
                return self.recode_ascii_string_meth( self.__strings_off[off].get() )
            return self.__strings_off[off].get()
        except KeyError :
            bytecode.Warning( "unknown string item @ 0x%x(%d)" % (off,idx) )
            return ""

    def get_raw_string(self, idx) :
        off = self.__manage_item[ "TYPE_STRING_ID_ITEM" ][idx].get_data_off()
        try :
            return self.__strings_off[off].get()
        except KeyError :
            bytecode.Warning( "unknown string item @ 0x%x(%d)" % (off,idx) )
            return ""

    def get_type_list(self, off) :
        if off == 0 :
            return "()"

        if off in self.__cached_type_list :
            return self.__cached_type_list[ off ]

        for i in self.__manage_item[ "TYPE_TYPE_LIST" ] :
            if i.get_type_list_off() == off :
                ret =  "(" + i.get_string() + ")"
                self.__cached_type_list[ off ] = ret
                return ret

        return None

    def get_type(self, idx) :
        _type = self.__manage_item[ "TYPE_TYPE_ID_ITEM" ].get( idx )
        return self.get_string( _type )

    def get_type_ref(self, idx) :
        return self.__manage_item[ "TYPE_TYPE_ID_ITEM" ].get( idx )

    def get_proto(self, idx) :
        try :
            proto = self.__cached_proto[ idx ]
        except KeyError :
            proto = self.__manage_item[ "TYPE_PROTO_ID_ITEM" ].get( idx )
            self.__cached_proto[ idx ] = proto

        return [ proto.get_params(), proto.get_return_type() ]

    def get_field(self, idx) :
        field = self.__manage_item[ "TYPE_FIELD_ID_ITEM"].get( idx )
        return [ field.get_class(), field.get_type(), field.get_name() ]

    def get_field_ref(self, idx) :
        return self.__manage_item[ "TYPE_FIELD_ID_ITEM"].get( idx )

    def get_method(self, idx) :
        method = self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )
        return method.get_list()

    def get_method_ref(self, idx) :
        return self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )

    def set_hook_method_class_name(self, idx, value) :
        method = self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )
        _type = self.__manage_item[ "TYPE_TYPE_ID_ITEM" ].get( method.class_idx )
        self.set_hook_string( _type, value )
        method.reload()

    def set_hook_method_name(self, idx, value) :
        method = self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )
        self.set_hook_string( method.name_idx, value )
        method.reload()

    def set_hook_string(self, idx, value) :
        self.hook_strings[ idx ] = value

    def get_next_offset_item(self, idx) :
        for i in self.__manage_item_off :
            if i > idx :
                return i
        return idx

class MapList :
    def __init__(self, cm, off, buff) :
        self.CM = cm
        buff.set_idx( off )

        self.__offset = self.CM.add_offset( buff.get_idx(), self )

        self.size = unpack("=I", buff.read( 4 ) )[0]

        self.map_item = []
        for i in xrange(0, self.size) :
            idx = buff.get_idx()

            mi = MapItem( buff, self.CM )
            self.map_item.append( mi )

            buff.set_idx( idx + mi.get_length() )

            self.CM.add_type_item( TYPE_MAP_ITEM[ mi.get_type() ], mi.get_item() )

        for i in self.map_item :
            i.reload()

    def get_item_type(self, ttype) :
        for i in self.map_item :
            if TYPE_MAP_ITEM[ i.get_type() ] == ttype :
                return i.get_item()
        return None

    def show(self) :
        bytecode._Print("MAP_LIST SIZE", self.size)
        for i in self.map_item :
            i.show()

    def pretty_show(self) :
        bytecode._Print("MAP_LIST SIZE", self.size)
        for i in self.map_item :
            i.pretty_show()

    def get_obj(self) :
        return [ x for x in self.map_item ]

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset.off, pack("=I", self.size)) ] + \
                 [ x.get_raw() for x in self.map_item ]

    def get_class_manager(self) :
        return self.CM

class DalvikVMFormat(bytecode._Bytecode) :
    def __init__(self, buff, decompiler=None) :
        super(DalvikVMFormat, self).__init__( buff )

        self.CM = ClassManager()
        self.CM.set_decompiler( decompiler )

        self.__header = HeaderItem( 0, self, ClassManager() )

        if self.__header.map_off == 0 :
            bytecode.Warning( "no map list ..." )
        else :
            self.map_list = MapList( self.CM, self.__header.map_off, self )

            self.classes = self.map_list.get_item_type( "TYPE_CLASS_DEF_ITEM" )
            self.methods = self.map_list.get_item_type( "TYPE_METHOD_ID_ITEM" )
            self.fields = self.map_list.get_item_type( "TYPE_FIELD_ID_ITEM" )
            self.codes = self.map_list.get_item_type( "TYPE_CODE_ITEM" )
            self.strings = self.map_list.get_item_type( "TYPE_STRING_DATA_ITEM" )
            self.debug = self.map_list.get_item_type( "TYPE_DEBUG_INFO_ITEM" )
            self.header = self.map_list.get_item_type( "TYPE_HEADER_ITEM" )

        self.classes_names = None
        self.__cache_methods = None

    def get_class_manager(self) :
        return self.CM

    def show(self) :
        """Show the .class format into a human readable format"""
        self.map_list.show()

    def save(self) :
        """
            Return the dex (with the modifications) into raw format

            @rtype: string
        """
        l = self.map_list.get_raw()

        result = list(self._iterFlatten( l ))
        result = sorted(result, key=lambda x: x.offset)

        idx = 0
        buff = ""
        for i in result :
#            print idx, i.offset, "--->", i.offset + i.size
            if idx == i.offset :
                buff += i.buff
            else :
#                print "PATCH @ 0x%x %d" % (idx, (i.offset - idx))
                buff += '\x00' * (i.offset - idx)
                buff += i.buff
                idx += (i.offset - idx)

            idx += i.size

        return self.fix_checksums(buff)

    def fix_checksums(self, buff) :
      import zlib, hashlib
      checksum = zlib.adler32(buff[12:])
      buff = buff[:8] + pack("=i", checksum) + buff[12:]

      signature = hashlib.sha1(buff[32:]).digest()

      buff = buff[:12] + signature + buff[32:]

      return buff

    def dotbuff(self, ins, idx) :
        return dot_buff(ins, idx)

    def pretty_show(self) :
        self.map_list.pretty_show()

    def _iterFlatten(self, root):
        if isinstance(root, (list, tuple)):
            for element in root :
                for e in self._iterFlatten(element) :
                    yield e
        else:
            yield root

    def _Exp(self, x) :
        l = []
        for i in x :
            l.append(i)
            l.append( self._Exp( i.get_obj() ) )
        return l

    def get_cm_field(self, idx) :
        return self.CM.get_field(idx)

    def get_cm_method(self, idx) :
        return self.CM.get_method(idx)

    def get_cm_string(self, idx) :
        return self.CM.get_raw_string( idx )

    def get_cm_type(self, idx) :
        return self.CM.get_type( idx )

    def get_classes_names(self) :
        """
            Return the names of classes
        """
        if self.classes_names == None :
            self.classes_names = [ i.get_name() for i in self.classes.class_def ]
        return self.classes_names

    def get_classes(self) :
        return self.classes.class_def

    def get_method(self, name) :
        """Return into a list all methods which corresponds to the regexp

            @param name : the name of the method (a regexp)
        """
        prog = re.compile(name)
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                if prog.match( j.get_name() ) :
                    l.append( j )
        return l

    def get_field(self, name) :
        """Return into a list all fields which corresponds to the regexp

            @param name : the name of the field (a regexp)
        """
        prog = re.compile(name)
        l = []
        for i in self.classes.class_def :
            for j in i.get_fields() :
                if prog.match( j.get_name() ) :
                    l.append( j )
        return l

    def get_all_fields(self) :
        try :
            return self.fields.gets()
        except AttributeError :
            return []

    def get_fields(self) :
        """Return all objects fields"""
        l = []
        for i in self.classes.class_def :
            for j in i.get_fields() :
                l.append( j )
        return l


    def get_methods(self) :
        """Return all objects methods"""
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                l.append( j )
        return l

    def get_len_methods(self) :
        return len( self.get_methods() )

    def get_method_by_idx(self, idx) :
        for i in self.classes.class_def :
          for j in i.get_methods() :
            if j.get_idx() == idx :
              return j
        return None

    def get_method_descriptor(self, class_name, method_name, descriptor) :
        """
            Return the specific method

            @param class_name : the class name of the method
            @param method_name : the name of the method
            @param descriptor : the descriptor of the method

        """
        key = class_name + method_name + descriptor

        if self.__cache_methods == None :
            self.__cache_methods = {}
            for i in self.classes.class_def :
                for j in i.get_methods() :
                    self.__cache_methods[ j.get_class_name() + j.get_name() + j.get_descriptor() ] = j

        try : 
            return self.__cache_methods[ key ]
        except KeyError :
            return None

    def get_methods_class(self, class_name) :
        """
            Return methods of a class

            @param class_name : the class name
        """
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                if class_name == j.get_class_name() :
                    l.append( j )

        return l

    def get_fields_class(self, class_name) :
        """
            Return fields of a class

            @param class_name : the class name
        """
        l = []
        for i in self.classes.class_def :
            for j in i.get_fields() :
                if class_name == j.get_class_name() :
                    l.append( j )

        return l

    def get_field_descriptor(self, class_name, field_name, descriptor) :
        """
            Return the specific field

            @param class_name : the class name of the field
            @param field_name : the name of the field
            @param descriptor : the descriptor of the field

        """
        for i in self.classes.class_def :
            if class_name == i.get_name() :
                for j in i.get_fields() :
                    if field_name == j.get_name() and descriptor == j.get_descriptor() :
                        return j
        return None

    def get_class_manager(self) :
        """
            Return directly the class manager

            @rtype : L{ClassManager}
        """
        return self.map_list.get_class_manager()

    def get_strings(self) :
        """
            Return all strings
        """
        return [i.get() for i in self.strings]

    def get_regex_strings(self, regular_expressions) :
        """
            Return all taget strings matched the regex in input
        """
        str_list = []
        if regular_expressions.count is None :
            return None
        for i in self.get_strings() :
            if re.match(regular_expressions, i) :
                str_list.append(i)
        return str_list


    def get_type(self) :
        return "DVM"
    
    def get_BRANCH_DVM_OPCODES(self) :
        return BRANCH_DVM_OPCODES

    def get_determineNext(self) :
        return determineNext

    def get_determineException(self) :
        return determineException

    def get_DVM_TOSTRING(self) :
        return DVM_TOSTRING()

    def set_decompiler(self, decompiler) :
        self.CM.set_decompiler( decompiler )

    def set_vmanalysis(self, vmanalysis) :
        self.CM.set_vmanalysis( vmanalysis )

    def set_gvmanalysis(self, gvmanalysis) :
        self.CM.set_gvmanalysis( gvmanalysis )

    def create_xref(self, python_export=True) :
        gvm = self.CM.get_gvmanalysis()

        for _class in self.get_classes() :
            for method in _class.get_methods() :
                method.XREFfrom = XREF()
                method.XREFto = XREF()

                key = "%s %s %s" % (method.get_class_name(), method.get_name(), method.get_descriptor())

                if key in gvm.nodes :
                    for i in gvm.G.predecessors( gvm.nodes[ key ].id ) :
                        xref = gvm.nodes_id[ i ]
                        xref_meth = self.get_method_descriptor( xref.class_name, xref.method_name, xref.descriptor)
                        if xref_meth != None :
                            name = FormatClassToPython( xref_meth.get_class_name() ) + "__" + FormatNameToPython( xref_meth.get_name() ) + "__" + FormatDescriptorToPython( xref_meth.get_descriptor() )
                            if python_export == True :
                                setattr( method.XREFfrom, name, xref_meth )
                            method.XREFfrom.add( xref_meth, xref.edges[ gvm.nodes[ key ] ] )

                    for i in gvm.G.successors( gvm.nodes[ key ].id ) :
                        xref = gvm.nodes_id[ i ]
                        xref_meth = self.get_method_descriptor( xref.class_name, xref.method_name, xref.descriptor)
                        if xref_meth != None :
                            name = FormatClassToPython( xref_meth.get_class_name() ) + "__" + FormatNameToPython( xref_meth.get_name() ) + "__" + FormatDescriptorToPython( xref_meth.get_descriptor() )
                            if python_export == True :
                                setattr( method.XREFto, name, xref_meth )
                            method.XREFto.add( xref_meth, gvm.nodes[ key ].edges[ xref ] )

    def create_dref(self, python_export=True) :
        vmx = self.CM.get_vmanalysis()

        for _class in self.get_classes() :
            for field in _class.get_fields() :
                field.DREFr = DREF()
                field.DREFw = DREF()

                paths = vmx.tainted_variables.get_field( field.get_class_name(), field.get_name(), field.get_descriptor() )

                if paths != None :
                    access = {}
                    access["R"] = {}
                    access["W"] = {}

                    for path in paths.get_paths() :
                        access_val, idx = path[0]
                        m_idx = path[1]

                        if access_val == 'R' :
                            dref_meth = self.get_method_by_idx( m_idx )
                            name = FormatClassToPython( dref_meth.get_class_name() ) + "__" + FormatNameToPython( dref_meth.get_name() ) + "__" + FormatDescriptorToPython( dref_meth.get_descriptor() )
                            if python_export == True :
                                setattr( field.DREFr, name, dref_meth )

                            try :
                                access["R"][ dref_meth ].append( idx )
                            except KeyError :
                                access["R"][ dref_meth ] = []
                                access["R"][ dref_meth ].append( idx )

                        else :
                            dref_meth = self.get_method_by_idx( m_idx )
                            name = FormatClassToPython( dref_meth.get_class_name() ) + "__" + FormatNameToPython( dref_meth.get_name() ) + "__" + FormatDescriptorToPython( dref_meth.get_descriptor() )
                            if python_export == True :
                                setattr( field.DREFw, name, dref_meth )

                            try :
                                access["W"][ dref_meth ].append( idx )
                            except KeyError :
                                access["W"][ dref_meth ] = [] 
                                access["W"][ dref_meth ].append( idx )

                    for i in access["R"] :
                        field.DREFr.add( i, access["R"][i] )
                    for i in access["W"] :
                        field.DREFw.add( i, access["W"][i] )

class XREF : 
    def __init__(self) :
        self.items = []

    def add(self, x, y):
        self.items.append((x, y))

class DREF : 
    def __init__(self) :
        self.items = []

    def add(self, x, y):
        self.items.append((x, y))
