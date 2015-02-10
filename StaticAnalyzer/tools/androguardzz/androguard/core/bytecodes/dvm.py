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

from androguard.core import bytecode
from androguard.core.androconf import CONF, debug, is_android_raw

import sys
import re
from struct import pack, unpack, calcsize

DEX_FILE_MAGIC = 'dex\n035\x00'
ODEX_FILE_MAGIC_35 = 'dey\n035\x00'
ODEX_FILE_MAGIC_36 = 'dey\n036\x00'


TYPE_MAP_ITEM = {
                        0x0  :      "TYPE_HEADER_ITEM",
                        0x1  :      "TYPE_STRING_ID_ITEM",
                        0x2  :      "TYPE_TYPE_ID_ITEM",
                        0x3  :      "TYPE_PROTO_ID_ITEM",
                        0x4  :      "TYPE_FIELD_ID_ITEM",
                        0x5  :      "TYPE_METHOD_ID_ITEM",
                        0x6  :      "TYPE_CLASS_DEF_ITEM",
                        0x1000 :    "TYPE_MAP_LIST",
                        0x1001 :    "TYPE_TYPE_LIST",
                        0x1002 :    "TYPE_ANNOTATION_SET_REF_LIST",
                        0x1003 :    "TYPE_ANNOTATION_SET_ITEM",
                        0x2000 :    "TYPE_CLASS_DATA_ITEM",
                        0x2001 :    "TYPE_CODE_ITEM",
                        0x2002 :    "TYPE_STRING_DATA_ITEM",
                        0x2003 :    "TYPE_DEBUG_INFO_ITEM",
                        0x2004 :    "TYPE_ANNOTATION_ITEM",
                        0x2005 :    "TYPE_ENCODED_ARRAY_ITEM",
                        0x2006 :    "TYPE_ANNOTATIONS_DIRECTORY_ITEM",
                     }

ACCESS_FLAGS = [ 
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
    (0x10000, 'constructor'),
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

def get_access_flags_string(value) :
  """
      Transform an access flags to the corresponding string

      :param value: the value of the access flags
      :type value: int

      :rtype: string
  """
  buff = ""
  for i in ACCESS_FLAGS :
    if (i[0] & value) == i[0] :
      buff += i[1] + " "

  if buff != "" :
    return buff[:-1]
  return buff


def get_type(atype, size=None):
    """
      Retrieve the type of a descriptor (e.g : I)
    """
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

FIELD_READ_DVM_OPCODES = [ ".get" ]
FIELD_WRITE_DVM_OPCODES = [ ".put" ]

BREAK_DVM_OPCODES = [ "invoke.", "move.", ".put", "if." ]

BRANCH_DVM_OPCODES = [ "throw", "throw.", "if.", "goto", "goto.", "return", "return.", "packed-switch$",  "sparse-switch$" ]

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

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
}

def dot_buff(ins, idx) :
  op_value = ins.get_op_value()

  if op_value == 0x300 :
    return ins.get_name() + " " + ins.get_output(idx).replace("\"", "")
  elif op_value == 0x1a :
    return ins.get_name() + " " + ins.get_output(idx).replace("\"", "") #"".join(html_escape_table.get(c,c) for c in ins.get_output())

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

    # throw + return*
    if (op_value == 0x27) or (0x0e <= op_value <= 0x11) :
        return [ -1 ]
    # goto
    elif 0x28 <= op_value <= 0x2a :
        off = i.get_ref_off() * 2
        return [ off + end ]
    # if
    elif 0x32 <= op_value <= 0x3d :
        off = i.get_ref_off() * 2
        return [ end + i.get_length(), off + (end) ]
    # sparse/packed
    elif op_value in (0x2b, 0x2c) :
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
        offset_handler = try_item.get_handler_off() + handler_catch_list.get_off()
        if offset_handler in h_off :
          h_off[ offset_handler ].append( [ try_item ] )
        else :
          h_off[ offset_handler ] = []
          h_off[ offset_handler ].append( [ try_item ] )

    #print m.get_name(), "\t HANDLER_CATCH_LIST SIZE", handler_catch_list.size, handler_catch_list.get_offset()
    for handler_catch in handler_catch_list.get_list() :
        if handler_catch.get_off() not in h_off :
            continue

        for i in h_off[ handler_catch.get_off() ] :
          i.append( handler_catch )

    exceptions = []
    #print m.get_name(), h_off
    for i in h_off :
      for value in h_off[ i ] :
        try_value = value[0]

        z = [ try_value.get_start_addr() * 2, (try_value.get_start_addr() * 2) + (try_value.get_insn_count() * 2) - 1 ]

        handler_catch = value[1]
        if handler_catch.get_size() <= 0 :
            z.append( [ "any", handler_catch.get_catch_all_addr() * 2 ] )

        for handler in handler_catch.get_handlers() :
            z.append( [ vm.get_cm_type( handler.get_type_idx() ), handler.get_addr() * 2 ] )

        exceptions.append( z )

    #print m.get_name(), exceptions 
    return exceptions

class HeaderItem :
    """
        This class can parse an header_item of a dex file

        :param buff: a string which represents a Buff object of the header_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

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

        self.map_off_obj = None
        self.string_off_obj = None
        self.type_off_obj = None
        self.proto_off_obj = None
        self.field_off_obj = None
        self.method_off_obj = None
        self.class_off_obj = None
        self.data_off_obj = None

    def reload(self) :
      pass

    def get_obj(self) :
      if self.map_off_obj == None :
        self.map_off_obj = self.__CM.get_item_by_offset( self.map_off )

      if self.string_off_obj == None :
        self.string_off_obj = self.__CM.get_item_by_offset( self.string_ids_off )

      if self.type_off_obj == None :
        self.type_off_obj = self.__CM.get_item_by_offset( self.type_ids_off )

      if self.proto_off_obj == None :
        self.proto_off_obj = self.__CM.get_item_by_offset( self.proto_ids_off )

      if self.field_off_obj == None :
        self.field_off_obj = self.__CM.get_item_by_offset( self.field_ids_off )

      if self.method_off_obj == None :
        self.method_off_obj = self.__CM.get_item_by_offset( self.method_ids_off )

      if self.class_off_obj == None :
        self.class_off_obj = self.__CM.get_item_by_offset( self.class_defs_off )

      if self.data_off_obj == None :
        self.data_off_obj = self.__CM.get_item_by_offset( self.data_off )

      self.map_off = self.map_off_obj.get_off()

      self.string_ids_size = len(self.string_off_obj)
      self.string_ids_off = self.string_off_obj[0].get_off()

      self.type_ids_size = len(self.type_off_obj.type)
      self.type_ids_off = self.type_off_obj.get_off()

      self.proto_ids_size = len(self.proto_off_obj.proto)
      self.proto_ids_off = self.proto_off_obj.get_off()

      self.field_ids_size = len(self.field_off_obj.elem)
      self.field_ids_off = self.field_off_obj.get_off()

      self.method_ids_size = len(self.method_off_obj.methods)
      self.method_ids_off = self.method_off_obj.get_off()

      self.class_defs_size = len(self.class_off_obj.class_def)
      self.class_defs_off = self.class_off_obj.get_off()

      #self.data_size = len(self.data_off_obj)
      self.data_off = self.data_off_obj[0].get_off()

      return pack("=Q", self.magic) +                                 \
             pack("=I", self.checksum) +                              \
             pack("=20s", self.signature) +                           \
             pack("=I", self.file_size) +                             \
             pack("=I", self.header_size) +                           \
             pack("=I", self.endian_tag) +                            \
             pack("=I", self.link_size) +                             \
             pack("=I", self.link_off) +                              \
             pack("=I", self.map_off) +              \
             pack("=I", self.string_ids_size) +      \
             pack("=I", self.string_ids_off) +       \
             pack("=I", self.type_ids_size) +        \
             pack("=I", self.type_ids_off) +         \
             pack("=I", self.proto_ids_size) +       \
             pack("=I", self.proto_ids_off) +        \
             pack("=I", self.field_ids_size) +       \
             pack("=I", self.field_ids_off) +        \
             pack("=I", self.method_ids_size) +      \
             pack("=I", self.method_ids_off) +       \
             pack("=I", self.class_defs_size) +      \
             pack("=I", self.class_defs_off) +       \
             pack("=I", self.data_size) +            \
             pack("=I", self.data_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_raw())

    def show(self) :
        bytecode._PrintSubBanner("Header Item")
        bytecode._PrintDefault("magic=%s, checksum=%s, signature=%s\n" % (self.magic, self.checksum, self.signature))
        bytecode._PrintDefault("file_size=%x, header_size=%x, endian_tag=%x\n" % (self.file_size, self.header_size, self.endian_tag))
        bytecode._PrintDefault("link_size=%x, link_off=%x\n" % (self.link_size, self.link_off))
        bytecode._PrintDefault("map_off=%x\n" % (self.map_off))
        bytecode._PrintDefault("string_ids_size=%x, string_ids_off=%x\n" % (self.string_ids_size, self.string_ids_off))
        bytecode._PrintDefault("type_ids_size=%x, type_ids_off=%x\n" % (self.type_ids_size, self.type_ids_off))
        bytecode._PrintDefault("proto_ids_size=%x, proto_ids_off=%x\n" % (self.proto_ids_size, self.proto_ids_off))
        bytecode._PrintDefault("field_ids_size=%x, field_ids_off=%x\n" % (self.field_ids_size, self.field_ids_off))
        bytecode._PrintDefault("method_ids_size=%x, method_ids_off=%x\n" % (self.method_ids_size, self.method_ids_off))
        bytecode._PrintDefault("class_defs_size=%x, class_defs_off=%x\n" % (self.class_defs_size, self.class_defs_off))
        bytecode._PrintDefault("data_size=%x, data_off=%x\n" % (self.data_size, self.data_off))

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

class AnnotationOffItem :
    """
        This class can parse an annotation_off_item of a dex file

        :param buff: a string which represents a Buff object of the annotation_off_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self,  buff, cm) :
        self.__CM = cm
        self.annotation_off = unpack("=I", buff.read( 4 ) )[0]

    def show(self) :
        bytecode._PrintSubBanner("Annotation Off Item")
        bytecode._PrintDefault("annotation_off=0x%x\n" % self.annotation_off)

    def get_obj(self) :
        if self.annotation_off != 0 :
          self.annotation_off = self.__CM.get_obj_by_offset( self.annotation_off ).get_off()

        return pack("=I", self.annotation_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class AnnotationSetItem :
    """
        This class can parse an annotation_set_item of a dex file

        :param buff: a string which represents a Buff object of the annotation_set_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.offset = buff.get_idx()
        self.annotation_off_item = []

        self.size = unpack("=I", buff.read( 4 ) )[0]
        for i in xrange(0, self.size) :
            self.annotation_off_item.append( AnnotationOffItem(buff, cm) )

    def get_annotation_off_item(self) :
        """ 
            Return the offset from the start of the file to an annotation

            :rtype: a list of :class:`AnnotationOffItem`
        """
        return self.annotation_off_item

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        pass

    def show(self) :
        bytecode._PrintSubBanner("Annotation Set Item")
        for i in self.annotation_off_item :
            i.show()

    def get_obj(self) :
        return pack("=I", self.size)

    def get_raw(self) :
        return self.get_obj() + ''.join(i.get_raw() for i in self.annotation_off_item)

    def get_length(self) :
      length = len(self.get_obj())

      for i in self.annotation_off_item :
        length += i.get_length()

      return length

class AnnotationSetRefItem :
    """
        This class can parse an annotation_set_ref_item of a dex file

        :param buff: a string which represents a Buff object of the annotation_set_ref_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self,  buff, cm) :
        self.__CM = cm
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def get_annotations_off(self) :
      """
          Return the offset from the start of the file to the referenced annotation set or 
          0 if there are no annotations for this element.

          :rtype: int
      """
      return self.annotations_off

    def show(self) :
        bytecode._PrintSubBanner("Annotation Set Ref Item")
        bytecode._PrintDefault("annotation_off=0x%x\n" % self.annotation_off)

    def get_obj(self) :
        if self.annotations_off != 0 :
          self.annotations_off = self.__CM.get_obj_by_offset( self.annotations_off ).get_off()

        return pack("=I", self.annotations_off)

    def get_raw(self) :
        return self.get_obj()

class AnnotationSetRefList :
    """
        This class can parse an annotation_set_ref_list_item of a dex file

        :param buff: a string which represents a Buff object of the annotation_set_ref_list_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()

        self.__CM = cm
        self.list = []

        self.size = unpack("=I", buff.read( 4 ) )[0]
        for i in xrange(0, self.size) :
            self.list.append( AnnotationSetRefItem(buff, cm) )

    def get_list(self) :
      """
          Return elements of the list

          :rtype: :class:`AnnotationSetRefItem`
      """
      return self.list

    def get_off(self) :
      return self.offset

    def set_off(self, off) :
      self.offset = off

    def reload(self) :
        pass

    def show(self) :
        bytecode._PrintSubBanner("Annotation Set Ref List Item")
        for i in self.list :
            i.show()

    def get_obj(self) :
        return [ i for i in self.list ]

    def get_raw(self) :
        return pack("=I", self.size) + ''.join(i.get_raw() for i in self.list)

class FieldAnnotation :
    """
        This class can parse a field_annotation of a dex file

        :param buff: a string which represents a Buff object of the field_annotation
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()
        
        self.__CM = cm
        self.field_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def get_field_idx(self) :
      """
          Return the index into the field_ids list for the identity of the field being annotated

          :rtype: int
      """
      return self.get_field_idx

    def get_annotations_off(self) :
      """
          Return the offset from the start of the file to the list of annotations for the field

          :rtype: int
      """
      return self.annotations_off

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def show(self) :
        bytecode._PrintSubBanner("Field Annotation")
        bytecode._PrintDefault( "field_idx=0x%x annotations_off=0x%x\n" % (self.field_idx, self.annotations_off) )

    def get_obj(self) :
        if self.annotations_off != 0 :
          self.annotations_off = self.__CM.get_obj_by_offset( self.annotations_off ).get_off()

        return pack("=I", self.field_idx) + pack("=I", self.annotations_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
        return len(self.get_raw())

class MethodAnnotation :
    """
        This class can parse a method_annotation of a dex file

        :param buff: a string which represents a Buff object of the method_annotation
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()

        self.__CM = cm
        self.method_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def get_method_idx(self) :
      """
          Return the index into the method_ids list for the identity of the method being annotated

          :rtype: int
      """
      return self.get_method_idx

    def get_annotations_off(self) :
      """
          Return the offset from the start of the file to the list of annotations for the method

          :rtype: int
      """
      return self.annotations_off

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def show(self) :
        bytecode._PrintSubBanner("Method Annotation")
        bytecode._PrintDefault( "method_idx=0x%x annotations_off=0x%x\n" % (self.method_idx, self.annotations_off) )

    def get_obj(self) :
        if self.annotations_off != 0 :
          self.annotations_off = self.__CM.get_obj_by_offset( self.annotations_off ).get_off()

        return pack("=I", self.method_idx) + pack("=I", self.annotations_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_raw())

class ParameterAnnotation :
    """
        This class can parse a parameter_annotation of a dex file

        :param buff: a string which represents a Buff object of the parameter_annotation
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()
        
        self.__CM = cm
        self.method_idx = unpack("=I", buff.read( 4 ) )[0]
        self.annotations_off = unpack("=I", buff.read( 4 ) )[0]

    def get_method_idx(self) :
      """
          Return the index into the method_ids list for the identity of the method whose parameters are being annotated

          :rtype: int
      """
      return self.get_method_idx

    def get_annotations_off(self) :
      """
          Return the offset from the start of the file to the list of annotations for the method parameters

          :rtype: int
      """
      return self.annotations_off

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def show(self) :
        bytecode._PrintSubBanner("Parameter Annotation")
        bytecode._PrintDefault( "method_idx=0x%x annotations_off=0x%x\n" % (self.method_idx, self.annotations_off) )

    def get_obj(self) :
        if self.annotations_off != 0 :
          self.annotations_off = self.__CM.get_obj_by_offset( self.annotations_off ).get_off()

        return pack("=I", self.method_idx) + pack("=I", self.annotations_off)

    def get_raw(self) :
        return self.get_obj()

class AnnotationsDirectoryItem :
    """
        This class can parse an annotations_directory_item of a dex file

        :param buff: a string which represents a Buff object of the annotations_directory_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.class_annotations_off = unpack("=I", buff.read(4))[0]
        self.annotated_fields_size = unpack("=I", buff.read(4))[0]
        self.annotated_methods_size = unpack("=I", buff.read(4))[0]
        self.annotated_parameters_size = unpack("=I", buff.read(4))[0]

        self.field_annotations = []
        for i in xrange(0, self.annotated_fields_size) :
            self.field_annotations.append( FieldAnnotation( buff, cm ) )

        self.method_annotations = []
        for i in xrange(0, self.annotated_methods_size) :
            self.method_annotations.append( MethodAnnotation( buff, cm ) )

        self.parameter_annotations = []
        for i in xrange(0, self.annotated_parameters_size) :
            self.parameter_annotations.append( ParameterAnnotation( buff, cm ) )

    def get_class_annotations_off(self) :
      """
          Return the offset from the start of the file to the annotations made directly on the class, 
          or 0 if the class has no direct annotations

          :rtype: int
      """
      return self.class_annotations_off


    def get_annotated_fields_size(self) :
      """
          Return the count of fields annotated by this item

          :rtype: int
      """
      return self.annotated_fields_size

    def get_annotated_methods_size(self) :
      """
          Return the count of methods annotated by this item

          :rtype: int
      """
      return self.annotated_methods_size

    def get_annotated_parameters_size(self) :
      """
          Return the count of method parameter lists annotated by this item

          :rtype: int
      """
      return self.annotated_parameters_size

    def get_field_annotations(self) :
      """
          Return the list of associated field annotations

          :rtype: a list of :class:`FieldAnnotation`
      """
      return self.field_annotations

    def get_method_annotations(self) :
      """
          Return the list of associated method annotations

          :rtype: a list of :class:`MethodAnnotation`
      """
      return self.method_annotations


    def get_parameter_annotations(self) :
      """
          Return the list of associated method parameter annotations

          :rtype: a list of :class:`ParameterAnnotation`
      """
      return self.parameter_annotations

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        pass

    def show(self) :
        bytecode._PrintSubBanner("Annotations Directory Item")
        bytecode._PrintDefault("class_annotations_off=0x%x annotated_fields_size=%d annotated_methods_size=%d annotated_parameters_size=%d\n" % 
                              ( self.class_annotations_off, 
                                self.annotated_fields_size,
                                self.annotated_methods_size,
                                self.annotated_parameters_size))

        for i in self.field_annotations :
            i.show()

        for i in self.method_annotations :
            i.show()

        for i in self.parameter_annotations :
            i.show()

    def get_obj(self) :
        if self.class_annotations_off != 0 :
          self.class_annotations_off = self.__CM.get_obj_by_offset( self.class_annotations_off ).get_off() 

        return pack("=I", self.class_annotations_off) +     \
               pack("=I", self.annotated_fields_size) +               \
               pack("=I", self.annotated_methods_size) +    \
               pack("=I", self.annotated_parameters_size)

    def get_raw(self) :
        return self.get_obj() + \
               ''.join(i.get_raw() for i in self.field_annotations)  +      \
               ''.join(i.get_raw() for i in self.method_annotations) +     \
               ''.join(i.get_raw() for i in self.parameter_annotations)

    def get_length(self) :
      length = len( self.get_obj() )
      for i in self.field_annotations :
        length += i.get_length()

      for i in self.method_annotations :
        length += i.get_length()

      for i in self.parameter_annotations :
        length += i.get_length()

      return length

class TypeItem :
    """
        This class can parse a type_item of a dex file

        :param buff: a string which represents a Buff object of the type_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.type_idx = unpack("=H", buff.read(2))[0]

    def get_type_idx(self) :
      """
          Return the index into the type_ids list

          :rtype: int
      """
      return self.type_idx

    def get_string(self) :
        """
          Return the type string

          :rtype: string
        """
        return self.__CM.get_type( self.type_idx )

    def show(self) :
        bytecode._PrintSubBanner("Type Item")
        bytecode._PrintDefault("type_idx=%d\n" % self.type_idx)

    def get_obj(self) :
        return pack("=H", self.type_idx)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class TypeList :
    """
        This class can parse a type_list of a dex file

        :param buff: a string which represents a Buff object of the type_list
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.pad = ""
        if self.offset % 4 != 0 :
            self.pad = buff.read( self.offset % 4 )

        self.len_pad = len(self.pad)

        self.size = unpack("=I", buff.read( 4 ) )[0]

        self.list = []
        for i in xrange(0, self.size) :
            self.list.append( TypeItem( buff, cm ) )

    def get_pad(self) :
      """
          Return the alignment string

          :rtype: string
      """
      return self.pad

    def get_type_list_off(self) :
        """
            Return the offset of the item

            :rtype: int
        """
        return self.offset + self.len_pad

    def get_string(self) :
        """
            Return the concatenation of all strings

            :rtype: string
        """
        return ' '.join(i.get_string() for i in self.list)

    def get_size(self) :
      """
          Return the size of the list, in entries

          :rtype: int
      """
      return self.size

    def get_list(self) :
      """
          Return the list of TypeItem

          :rtype: a list of :class:`TypeItem` objects
      """
      return self.list

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset + self.len_pad

    def reload(self) :
        pass

    def show(self) :
        bytecode._PrintSubBanner("Type List")
        bytecode._PrintDefault("size=%d\n" % self.size)

        for i in self.list :
            i.show()

    def get_obj(self) :
        return self.pad + pack("=I", self.size)

    def get_raw(self) :
        return self.get_obj() + ''.join(i.get_raw() for i in self.list)

    def get_length(self) :
      length = len(self.get_obj())

      for i in self.list :
        length += i.get_length()

      return length

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
        return self.op_value

    def add(self, value, ttype) :
        self.format.append( (value, ttype) )

    def get_value(self) :
        if self.get_op_value() == DBG_START_LOCAL :
            return self.CM.get_string(self.format[1][0])
        elif self.get_op_value() == DBG_START_LOCAL_EXTENDED :
            return self.CM.get_string(self.format[1][0])

        return None

    def show(self) :
      bytecode._PrintSubBanner("DBGBytecode")
      bytecode._PrintDefault("op_value=%x format=%s value=%s\n" % (self.op_value, str(self.format), self.get_value()))

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

class DebugInfoItem :
    def __init__(self, buff, cm) :
        self.CM = cm

        self.offset = buff.get_idx()

        self.line_start = readuleb128( buff )
        self.parameters_size = readuleb128( buff )

        #print "line", self.line_start, "params", self.parameters_size

        self.parameter_names = []
        for i in xrange(0, self.parameters_size) :
            self.parameter_names.append( readuleb128p1( buff ) )

        self.bytecodes = []
        bcode = DBGBytecode( self.CM, unpack("=B", buff.read(1))[0] )
        self.bytecodes.append( bcode )

        while bcode.get_op_value() != DBG_END_SEQUENCE :
            bcode_value = bcode.get_op_value()

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

    def reload(self) :
        pass

    def get_parameters_size(self) :
        return self.parameters_size

    def get_line_start(self) :
        return self.line_start

    def get_parameter_names(self) :
        return self.parameter_names

    def get_translated_parameter_names(self) :
        l = []
        for i in self.parameter_names :
            if i == -1 :
                l.append( None )
            else :
                l.append( self.CM.get_string( i ) )
        return l

    def get_bytecodes(self) :
        return self.bytecodes

    def show(self) :
        bytecode._PrintSubBanner("Debug Info Item")
        bytecode._PrintDefault("line_start=%d parameters_size=%d\n" % (self.line_start, self.parameters_size))
        nb = 0
        for i in self.parameter_names :
          bytecode._PrintDefault("parameter_names[%d]=%s\n" % (nb, self.CM.get_string( i )))
          nb += 1

        for i in self.bytecodes :
          i.show()

    def get_raw(self) :
        return [ bytecode.Buff( self.__offset, writeuleb128( self.line_start ) + \
                                                            writeuleb128( self.parameters_size ) + \
                                                            ''.join(writeuleb128(i) for i in self.parameter_names) + \
                                                            ''.join(i.get_raw() for i in self.bytecodes) ) ]

    def get_off(self) :
        return self.offset

VALUE_BYTE      = 0x00    # (none; must be 0)      ubyte[1]         signed one-byte integer value
VALUE_SHORT     = 0x02    # size - 1 (0..1)  ubyte[size]    signed two-byte integer value, sign-extended
VALUE_CHAR      = 0x03    # size - 1 (0..1)  ubyte[size]    unsigned two-byte integer value, zero-extended
VALUE_INT       = 0x04    # size - 1 (0..3)  ubyte[size]    signed four-byte integer value, sign-extended
VALUE_LONG      = 0x06    # size - 1 (0..7)  ubyte[size]    signed eight-byte integer value, sign-extended
VALUE_FLOAT     = 0x10    # size - 1 (0..3)  ubyte[size]    four-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 32-bit floating point value
VALUE_DOUBLE    = 0x11    # size - 1 (0..7)  ubyte[size]    eight-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 64-bit floating point value
VALUE_STRING    = 0x17    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the string_ids section and representing a string value
VALUE_TYPE      = 0x18    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the type_ids section and representing a reflective type/class value
VALUE_FIELD     = 0x19    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing a reflective field value
VALUE_METHOD    = 0x1a    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the method_ids section and representing a reflective method value
VALUE_ENUM      = 0x1b    # size - 1 (0..3)  ubyte[size]    unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing the value of an enumerated type constant
VALUE_ARRAY     = 0x1c    # (none; must be 0)      encoded_array  an array of values, in the format specified by "encoded_array Format" below. The size of the value is implicit in the encoding.
VALUE_ANNOTATION  = 0x1d  # (none; must be 0)      encoded_annotation     a sub-annotation, in the format specified by "encoded_annotation Format" below. The size of the value is implicit in the encoding.
VALUE_NULL      = 0x1e    # (none; must be 0)      (none)  null reference value
VALUE_BOOLEAN   = 0x1f    # boolean (0..1) (none)  one-bit value; 0 for false and 1 for true. The bit is represented in the value_arg.


class DebugInfoItemEmpty :
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()
        self.__buff = buff
        self.__raw = ""

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        offset = self.offset

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
        return self.__raw

    def get_length(self) :
      return len(self.__raw)

class EncodedArray :
    """
        This class can parse an encoded_array of a dex file

        :param buff: a string which represents a Buff object of the encoded_array
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.offset = buff.get_idx()

        self.size = readuleb128( buff )

        self.values = []
        for i in xrange(0, self.size) :
            self.values.append( EncodedValue(buff, cm) )

    def get_size(self) :
      """
          Return the number of elements in the array

          :rtype: int
      """
      return self.size

    def get_values(self) :
        """
            Return a series of size encoded_value byte sequences in the format specified by this section, 
            concatenated sequentially

            :rtype: a list of :class:`EncodedValue` objects
        """
        return self.values

    def show(self) :
        bytecode._PrintSubBanner("Encoded Array")
        bytecode._PrintDefault("size=%d\n" % self.size)

        for i in self.values :
            i.show()

    def get_obj(self) :
        return writeuleb128( self.size )

    def get_raw(self) :
        return self.get_obj() + ''.join(i.get_raw() for i in self.values)

    def get_length(self) :
      length = len(self.get_obj())
      for i in self.values :
        length += i.get_length()

      return length

class EncodedValue :
    """
        This class can parse an encoded_value of a dex file

        :param buff: a string which represents a Buff object of the encoded_value
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.val = unpack("=B", buff.read(1))[0]
        self.value_arg = self.val >> 5
        self.value_type = self.val & 0x1f

        self.raw_value = None
        self.value = ""

        #  TODO: parse floats/doubles correctly
        if self.value_type >= VALUE_SHORT and self.value_type < VALUE_STRING :
            self.value, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
        elif self.value_type == VALUE_STRING :
            id, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
            self.value = cm.get_raw_string(id)
        elif self.value_type == VALUE_TYPE :
            id, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
            self.value = cm.get_type(id)
        elif self.value_type == VALUE_FIELD :
            id, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
            self.value = cm.get_field(id)
        elif self.value_type == VALUE_METHOD :
            id, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
            self.value = cm.get_method(id)
        elif self.value_type == VALUE_ENUM :
            id, self.raw_value = self._getintvalue(buff.read( self.value_arg + 1 ))
            self.value = cm.get_field(id)
        elif self.value_type == VALUE_ARRAY :
            self.value = EncodedArray( buff, cm )
        elif self.value_type == VALUE_ANNOTATION :
            self.value = EncodedAnnotation( buff, cm )
        elif self.value_type == VALUE_BYTE :
            self.value = buff.read( 1 )
        elif self.value_type == VALUE_NULL :
            self.value = None
        elif self.value_type == VALUE_BOOLEAN :
            if self.value_arg:
                self.value = True
            else:
                self.value = False
        else :
            bytecode.Exit( "Unknown value 0x%x" % self.value_type )

    def get_value(self) :
      """
          Return the bytes representing the value, variable in length and interpreted differently for different value_type bytes, 
          though always little-endian

          :rtype: an object representing the value
      """
      return self.value

    def get_value_type(self) :
      return self.value_type
    
    def get_value_arg(self) :
      return self.value_arg

    def _getintvalue(self, buf):
        ret = 0
        shift = 0
        for b in buf:
            ret |= ord(b) << shift
            shift += 8

        return ret, buf

    def show(self) :
        bytecode._PrintSubBanner("Encoded Value")
        bytecode._PrintDefault("val=%x value_arg=%x value_type=%x\n" % (self.val, self.value_arg, self.value_type))

    def get_obj(self) :
        if isinstance(self.value, str) == False :
            return [ self.value ]
        return []

    def get_raw(self) :
        if self.raw_value == None :
            return pack("=B", self.val) + bytecode.object_to_str( self.value )
        else :
            return pack("=B", self.val) + bytecode.object_to_str( self.raw_value )

    def get_length(self) :
      if self.raw_value == None :
        return len(pack("=B", self.val)) + len(bytecode.object_to_str( self.value ))
      else :
        return len(pack("=B", self.val)) + len(bytecode.object_to_str( self.raw_value ))

class AnnotationElement :
    """
        This class can parse an annotation_element of a dex file

        :param buff: a string which represents a Buff object of the annotation_element
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.name_idx = readuleb128( buff )
        self.value = EncodedValue( buff, cm )

    def get_name_idx(self) :
      """
          Return the element name, represented as an index into the string_ids section
          
          :rtype: int
      """
      return self.name_idx

    def get_value(self) :
      """
          Return the element value (EncodedValue)

          :rtype: a :class:`EncodedValue` object
      """
      return self.value

    def show(self) :
        bytecode._PrintSubBanner("Annotation Element")
        bytecode._PrintDefault("name_idx=%d\n" % self.name_idx)
        self.value.show()

    def get_obj(self) :
        return writeuleb128(self.name_idx)

    def get_raw(self) :
        return self.get_obj() + self.value.get_raw()

    def get_length(self) :
      return len(self.get_obj()) + self.value.get_length()

class EncodedAnnotation :
    """
        This class can parse an encoded_annotation of a dex file

        :param buff: a string which represents a Buff object of the encoded_annotation
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.type_idx = readuleb128( buff )
        self.size = readuleb128( buff )

        self.elements = []
        for i in xrange(0, self.size) :
            self.elements.append( AnnotationElement( buff, cm ) )

    def get_type_idx(self) :
      """
          Return the type of the annotation. This must be a class (not array or primitive) type

          :rtype: int
      """
      return self.type_idx

    def get_size(self) :
      """
          Return the number of name-value mappings in this annotation

          :rtype:int
      """
      return self.size

    def get_elements(self) :
      """
          Return the elements of the annotation, represented directly in-line (not as offsets)

          :rtype: a list of :class:`AnnotationElement` objects
      """
      return self.elements

    def show(self) :
        bytecode._PrintSubBanner("Encoded Annotation")
        bytecode._PrintDefault("type_idx=%d size=%d\n" % (self.type_idx, self.size))

        for i in self.elements :
            i.show()

    def get_obj(self) :
        return [ i for i in self.elements ]

    def get_raw(self) :
        return writeuleb128(self.type_idx) + writeuleb128(self.size) + ''.join(i.get_raw() for i in self.elements)

    def get_length(self) :
      length = len(writeuleb128(self.type_idx) + writeuleb128(self.size))

      for i in self.elements :
        length += i.get_length()

      return length

class AnnotationItem :
    """
        This class can parse an annotation_item of a dex file

        :param buff: a string which represents a Buff object of the annotation_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.visibility = unpack("=B", buff.read(1))[0]
        self.annotation = EncodedAnnotation(buff, cm)

    def get_visibility(self) :
      """
          Return the intended visibility of this annotation

          :rtype: int
      """
      return self.visibility

    def get_annotation(self) :
      """
          Return the encoded annotation contents

          :rtype: a :class:`EncodedAnnotation` object
      """
      return self.annotation

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        pass

    def show(self) :
        bytecode._PrintSubBanner("Annotation Item")
        bytecode._PrintDefault("visibility=%d\n" % self.visibility)
        self.annotation.show()

    def get_obj(self) :
        return [ self.annotation ]

    def get_raw(self) :
        return pack("=B", self.visibility) + self.annotation.get_raw()

    def get_length(self) :
      length = len(pack("=B", self.visibility))

      length += self.annotation.get_length()

      return length

class EncodedArrayItem :
    """
        This class can parse an encoded_array_item of a dex file

        :param buff: a string which represents a Buff object of the encoded_array_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()
        self.value = EncodedArray( buff, cm )

    def get_value(self) :
      """
          Return the bytes representing the encoded array value

          :rtype: a :class:`EncodedArray` object
      """
      return self.value

    def set_off(self, off) :
      self.offset = off

    def reload(self) :
        pass

    def get_value(self) :
      return self.value

    def show(self) :
        bytecode._PrintSubBanner("Encoded Array Item")
        self.value.show()

    def get_obj(self) :
        return [ self.value ]

    def get_raw(self) :
        return self.value.get_raw()

    def get_length(self) :
      return self.value.get_length()

    def get_off(self) :
      return self.offset

class StringDataItem :
    """
        This class can parse a string_data_item of a dex file

        :param buff: a string which represents a Buff object of the string_data_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

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

    def get_utf16_size(self) :
      """
          Return the size of this string, in UTF-16 code units

          :rtype:int 
      """
      return self.utf16_size

    def get_data(self) :
      """
          Return a series of MUTF-8 code units (a.k.a. octets, a.k.a. bytes) followed by a byte of value 0

          :rtype: string
      """
      return self.data

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        pass

    def get(self) :
        return self.data[:-1]

    def show(self) :
        bytecode._PrintSubBanner("String Data Item")
        bytecode._PrintDefault("utf16_size=%d data=%s\n" % (self.utf16_size, repr( self.data )))

    def get_obj(self) :
        return []

    def get_raw(self) :
        return writeuleb128( self.utf16_size ) + self.data

    def get_length(self) :
      return len(writeuleb128( self.utf16_size )) + len(self.data)

class StringIdItem :
    """
        This class can parse a string_id_item of a dex file

        :param buff: a string which represents a Buff object of the string_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm
        self.offset = buff.get_idx()

        self.string_data_off = unpack("=I", buff.read(4))[0]

    def get_string_data_off(self) :
        """
            Return the offset from the start of the file to the string data for this item

            :rtype: int
        """
        return self.string_data_off

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
      pass

    def show(self) :
        bytecode._PrintSubBanner("String Id Item")
        bytecode._PrintDefault("string_data_off=%x\n" % self.string_data_off)

    def get_obj(self) :
        if self.string_data_off != 0 :
          self.string_data_off = self.__CM.get_string_by_offset( self.string_data_off ).get_off()
        
        return pack("=I", self.string_data_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class TypeIdItem :
    """
        This class can parse a type_id_item of a dex file

        :param buff: a string which represents a Buff object of the type_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.descriptor_idx = unpack("=I", buff.read( 4 ) )[0]
        self.descriptor_idx_value = None

    def get_descriptor_idx(self) :
        """
            Return the index into the string_ids list for the descriptor string of this type

            :rtype: int
        """
        return self.descriptor_idx

    def get_descriptor_idx_value(self) :
      """
          Return the string associated to the descriptor

          :rtype: string
      """
      return self.descriptor_idx_value

    def reload(self) :
        self.descriptor_idx_value = self.__CM.get_string( self.descriptor_idx )

    def show(self) :
        bytecode._PrintSubBanner("Type Id Item")
        bytecode._PrintDefault("descriptor_idx=%d descriptor_idx_value=%s\n" % (self.descriptor_idx, self.descriptor_idx_value))

    def get_obj(self) :
        return pack("=I", self.descriptor_idx)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class TypeHIdItem :
    """
        This class can parse a list of type_id_item of a dex file

        :param buff: a string which represents a Buff object of the list of type_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.type = []
        for i in xrange(0, size) :
            self.type.append( TypeIdItem( buff, cm ) )

    def get_type(self) :
      """
          Return the list of type_id_item

          :rtype: a list of :class:`TypeIdItem` objects
      """
      return self.type

    def get(self, idx) :
        try :
            return self.type[ idx ].get_descriptor_idx()
        except IndexError :
            return -1

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def reload(self) :
        for i in self.type :
            i.reload()

    def show(self) :
        bytecode._PrintSubBanner("Type List Item")
        for i in self.type :
            i.show()

    def get_obj(self) :
        return [ i for i in self.type ]

    def get_raw(self) :
        return ''.join(i.get_raw() for i in self.type)

    def get_length(self) :
      length = 0
      for i in self.type :
        length += i.get_length()
      return length

class ProtoIdItem :
    """
        This class can parse a proto_id_item of a dex file

        :param buff: a string which represents a Buff object of the proto_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.shorty_idx = unpack("=I", buff.read(4))[0]
        self.return_type_idx = unpack("=I", buff.read(4))[0]
        self.parameters_off = unpack("=I", buff.read(4))[0]


        self.shorty_idx_value = None
        self.return_type_idx_value = None
        self.parameters_off_value = None

    def reload(self) :
        self.shorty_idx_value = self.__CM.get_string( self.shorty_idx )
        self.return_type_idx_value = self.__CM.get_type( self.return_type_idx )
        self.parameters_off_value = self.__CM.get_type_list( self.parameters_off )

    def get_shorty_idx(self) :
        """
            Return the index into the string_ids list for the short-form descriptor string of this prototype

            :rtype: int
        """
        return self.shorty_idx

    def get_return_type_idx(self) :
        """
            Return the index into the type_ids list for the return type of this prototype

            :rtype: int
        """
        return self.return_type_idx

    def get_parameters_off(self) :
        """
            Return the offset from the start of the file to the list of parameter types for this prototype, or 0 if this prototype has no parameters

            :rtype: int
        """
        return self.parameters_off

    def get_shorty_idx_value(self) :
        """
            Return the string associated to the shorty_idx

            :rtype: string
        """
        return self.shorty_idx_value

    def get_return_type_idx_value(self) :
        """
            Return the string associated to the return_type_idx

            :rtype: string
        """
        return self.return_type_idx_value

    def get_parameters_off_value(self) :
        """
            Return the string associated to the parameters_off

            :rtype: string
        """
        return self.parameters_off_value

    def show(self) :
        bytecode._PrintSubBanner("Proto Item")
        bytecode._PrintDefault("shorty_idx=%d return_type_idx=%d parameters_off=%d\n" % (self.shorty_idx, self.return_type_idx, self.parameters_off))
        bytecode._PrintDefault("shorty_idx_value=%s return_type_idx_value=%s parameters_off_value=%s\n" % 
                                (self.shorty_idx_value, self.return_type_idx_value, self.parameters_off_value))

        
    def get_obj(self) :
        if self.parameters_off != 0 :
          self.parameters_off = self.__CM.get_obj_by_offset( self.parameters_off ).get_off()

        return pack("=I", self.shorty_idx) + pack("=I", self.return_type_idx) + pack("=I", self.parameters_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class ProtoHIdItem :
    """
        This class can parse a list of proto_id_item of a dex file

        :param buff: a string which represents a Buff object of the list of proto_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.proto = []

        for i in xrange(0, size) :
            self.proto.append( ProtoIdItem(buff, cm) )

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def get(self, idx) :
        try :
            return self.proto[ idx ]
        except IndexError :
            return ProtoIdItemInvalid()

    def reload(self) :
        for i in self.proto :
            i.reload()

    def show(self) :
        bytecode._PrintSubBanner("Proto List Item")
        for i in self.proto :
            i.show()

    def get_obj(self) :
        return [ i for i in self.proto ]

    def get_raw(self) :
        return ''.join(i.get_raw() for i in self.proto)

    def get_length(self) :
      length = 0
      for i in self.proto :
        length += i.get_length()
      return length

class FieldIdItem :
    """
        This class can parse a field_id_item of a dex file

        :param buff: a string which represents a Buff object of the field_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.class_idx = unpack("=H", buff.read(2))[0]
        self.type_idx = unpack("=H", buff.read(2))[0]
        self.name_idx = unpack("=I", buff.read(4))[0]

        self.class_idx_value = None
        self.type_idx_value = None
        self.name_idx_value = None

    def reload(self) :
        self.class_idx_value = self.__CM.get_type( self.class_idx )
        self.type_idx_value = self.__CM.get_type( self.type_idx )
        self.name_idx_value = self.__CM.get_string( self.name_idx )

    def get_class_idx(self) :
      """
          Return the index into the type_ids list for the definer of this field

          :rtype: int
      """
      return self.class_idx

    def get_type_idx(self) :
      """
          Return the index into the type_ids list for the type of this field

          :rtype: int
      """
      return self.type_idx

    def get_name_idx(self) :
      """
          Return the index into the string_ids list for the name of this field

          :rtype: int
      """
      return self.name_idx

    def get_class_name(self) :
        """
            Return the class name of the field

            :rtype: string
        """
        return self.class_idx_value

    def get_type(self) :
        """
            Return the type of the field

            :rtype: string
        """
        return self.type_idx_value

    def get_descriptor(self) :
        """
            Return the descriptor of the field

            :rtype: string
        """
        return self.type_idx_value

    def get_name(self) :
        """
            Return the name of the field

            :rtype: string
        """
        return self.name_idx_value

    def get_list(self) :
        return [ self.get_class_name(), self.get_type(), self.get_name() ]

    def show(self) :
        bytecode._PrintSubBanner("Field Id Item")
        bytecode._PrintDefault("class_idx=%d type_idx=%d name_idx=%d\n" % (self.class_idx, self.type_idx, self.name_idx))
        bytecode._PrintDefault("class_idx_value=%s type_idx_value=%s name_idx_value=%s\n" % (self.class_idx_value, self.type_idx_value, self.name_idx_value))

    def get_obj(self) :
      return  pack("=H", self.class_idx) + \
              pack("=H", self.type_idx) + \
              pack("=I", self.name_idx)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class FieldHIdItem :
    """
        This class can parse a list of field_id_item of a dex file

        :param buff: a string which represents a Buff object of the list of field_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.offset = buff.get_idx()

        self.elem = []
        for i in xrange(0, size) :
            self.elem.append( FieldIdItem(buff, cm) )

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def gets(self) :
        return self.elem

    def get(self, idx) :
        try :
            return self.elem[ idx ]
        except IndexError :
            return FieldIdItemInvalid()

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
        return ''.join(i.get_raw() for i in self.elem)

    def get_length(self) :
      length = 0
      for i in self.elem :
        length += i.get_length()
      return length


class MethodIdItem :
    """
        This class can parse a method_id_item of a dex file

        :param buff: a string which represents a Buff object of the method_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.class_idx = unpack("=H", buff.read(2))[0]
        self.proto_idx = unpack("=H", buff.read(2))[0]
        self.name_idx = unpack("=I", buff.read(4))[0]

        self.class_idx_value = None
        self.proto_idx_value = None
        self.name_idx_value = None

    def reload(self) :
        self.class_idx_value = self.__CM.get_type( self.class_idx )
        self.proto_idx_value = self.__CM.get_proto( self.proto_idx )
        self.name_idx_value = self.__CM.get_string( self.name_idx )

    def get_class_idx(self) :
        """
            Return the index into the type_ids list for the definer of this method

            :rtype: int
        """
        return self.class_idx

    def get_proto_idx(self) :
        """
            Return the index into the proto_ids list for the prototype of this method

            :rtype: int
        """
        return self.proto_idx

    def get_name_idx(self) :
        """
            Return the index into the string_ids list for the name of this method

            :rtype: int
        """
        return self.name_idx

    def get_class_name(self) :
      """
          Return the class name of the method

          :rtype: string
      """      
      return self.class_idx_value

    def get_proto(self) :
        """
            Return the prototype of the method

            :rtype: string
        """      
        return self.proto_idx_value

    def get_descriptor(self) :
      """
          Return the descriptor

          :rtype: string
      """
      proto = self.get_proto()
      return proto[0] + proto[1]

    def get_name(self) :
        """
            Return the name of the method

            :rtype: string
        """
        return self.name_idx_value

    def get_list(self) :
        return [ self.get_class_name(), self.get_name(), self.get_proto() ]

    def show(self) :
        bytecode._PrintSubBanner("Method Id Item")
        bytecode._PrintDefault("class_idx=%d proto_idx=%d name_idx=%d\n" % (self.class_idx, self.proto_idx, self.name_idx))
        bytecode._PrintDefault("class_idx_value=%s proto_idx_value=%s name_idx_value=%s\n" % (self.class_idx_value, self.proto_idx_value, self.name_idx_value))

    def get_obj(self) :
        return pack("H", self.class_idx) + pack("H", self.proto_idx) + pack("I", self.name_idx)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class MethodHIdItem :
    """
        This class can parse a list of method_id_item of a dex file

        :param buff: a string which represents a Buff object of the list of method_id_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.methods = []
        for i in xrange(0, size) :
            self.methods.append( MethodIdItem(buff, cm) )

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def get(self, idx) :
        try :
            return self.methods[ idx ]
        except IndexError :
            return MethodIdItemInvalid()

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
        return ''.join(i.get_raw() for i in self.methods)

    def get_length(self) :
      length = 0
      for i in self.methods :
        length += i.get_length()
      return length

class ProtoIdItemInvalid :
    def get_params(self) :
        return "AG:IPI:invalid_params;"

    def get_shorty(self) :
        return "(AG:IPI:invalid_shorty)"

    def get_return_type(self) :
        return "(AG:IPI:invalid_return_type)"

    def show(self) :
        print "AG:IPI:invalid_proto_item", self.get_shorty(), self.get_return_type(), self.get_params()

class FieldIdItemInvalid :
    def get_class_name(self) :
        return "AG:IFI:invalid_class_name;"

    def get_type(self) :
        return "(AG:IFI:invalid_type)"

    def get_descriptor(self) :
        return "(AG:IFI:invalid_descriptor)"

    def get_name(self) :
        return "AG:IFI:invalid_name"

    def get_list(self) :
        return [ self.get_class_name(), self.get_type(), self.get_name() ]

    def show(self) :
        print "AG:IFI:invalid_field_item"

class MethodIdItemInvalid :
    def get_class_name(self) :
        return "AG:IMI:invalid_class_name;"

    def get_descriptor(self) :
      return "(AG:IMI:invalid_descriptor)"

    def get_proto(self) :
        return "()AG:IMI:invalid_proto"

    def get_name(self) :
        return "AG:IMI:invalid_name"

    def get_list(self) :
        return [ self.get_class_name(), self.get_name(), self.get_proto() ]

    def show(self) :
        print "AG:IMI:invalid_method_item"

class EncodedField :
    """
        This class can parse an encoded_field of a dex file

        :param buff: a string which represents a Buff object of the encoded field
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.CM = cm

        self.field_idx_diff = readuleb128( buff )
        self.access_flags = readuleb128( buff )

        self.field_idx = 0

        self.name = None
        self.proto = None
        self.class_name = None

        self.init_value = None
        self.access_flags_string = None

    def reload(self) :
        name = self.CM.get_field( self.field_idx )
        self.class_name = name[0]
        self.name = name[2]
        self.proto = ''.join(i for i in name[1])

    def set_init_value(self, value) :
        """
            Setup the init value object of the field
          
            :param value: the init value
            :type value: :class:`EncodedValue`
        """
        self.init_value = value

    def get_init_value(self) :
      """
          Return the init value object of the field

          :rtype: :class:`EncodedValue`
      """
      return self.init_value

    def adjust_idx(self, val) :
        self.field_idx = self.field_idx_diff + val


    def get_field_idx_diff(self) :
        """
            Return the index into the field_ids list for the identity of this field (includes the name and descriptor), 
            represented as a difference from the index of previous element in the list

            :rtype: int
        """
        return self.field_idx_diff

    def get_field_idx(self) :
        """
            Return the real index of the method

            :rtype: int
        """
        return self.field_idx

    def get_access_flags(self) :
        """
          Return the access flags of the field

          :rtype: int
        """
        return self.access_flags

    def get_class_name(self) :
        """
            Return the class name of the field

            :rtype: string
        """
        return self.class_name

    def get_descriptor(self) :
        """
            Return the descriptor of the field

            :rtype: string
        """
        return self.proto

    def get_name(self) :
        """
            Return the name of the field

            :rtype: string
        """
        return self.name

    def get_access_flags_string(self) :
        """
            Return the access flags string of the field

            :rtype: string
        """
        if self.access_flags_string == None :
            self.access_flags_string = get_access_flags_string( self.get_access_flags() )

            if self.access_flags_string == "" :
                self.access_flags_string = "0x%x" % self.get_access_flags()
        return self.access_flags_string

    def set_name(self, value) :
        self.CM.set_hook_field_name( self, value )
        self.reload()

    def get_obj(self) :
        return []

    def get_raw(self) :
        return writeuleb128( self.field_idx_diff ) + writeuleb128( self.access_flags )

    def get_size(self) :
      return len(self.get_raw())

    def show(self) :
        """
            Display the information about the field
        """
        colors = bytecode.disable_print_colors()
        self.pretty_show()
        bytecode.enable_print_colors(colors)

    def pretty_show(self) :
        """
            Display the information (with a pretty print) about the field
        """
        bytecode._PrintSubBanner("Field Information") 
        bytecode._PrintDefault("%s->%s %s [access_flags=%s]\n" % ( self.get_class_name(), self.get_name(), self.get_descriptor(), self.get_access_flags_string() ))

        init_value = self.get_init_value()
        if init_value != None :
            bytecode._PrintDefault( "\tinit value: %s\n" % str( init_value.get_value() ) )

        self.show_dref()

    def show_dref(self) :
        """
            Display where this field is read or written
        """
        try :
            bytecode._PrintSubBanner("DREF") 
            bytecode._PrintDRef("R", self.DREFr.items)
            bytecode._PrintDRef("W", self.DREFw.items)
            bytecode._PrintSubBanner() 
        except AttributeError:
            pass

class EncodedMethod :
    """
        This class can parse an encoded_method of a dex file

        :param buff: a string which represents a Buff object of the encoded_method
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.CM = cm

        self.method_idx_diff = readuleb128( buff )  #: method index diff in the corresponding section
        self.access_flags = readuleb128( buff )     #: access flags of the method
        self.code_off = readuleb128( buff )         #: offset of the code section

        self.method_idx = 0

        self.name = None
        self.proto = None
        self.class_name = None

        self.code = None

        self.access_flags_string = None

        self.notes = []

    def adjust_idx(self, val) :
        self.method_idx = self.method_idx_diff + val

    def get_method_idx(self) :
        """
            Return the real index of the method

            :rtype: int
        """
        return self.method_idx

    def get_method_idx_diff(self) :
      """
          Return index into the method_ids list for the identity of this method (includes the name and descriptor), 
          represented as a difference from the index of previous element in the lis
          
          :rtype: int
      """
      return self.method_idx_diff

    def get_access_flags(self) :
        """
          Return the access flags of the method

          :rtype: int
        """
        return self.access_flags

    def get_code_off(self) :
      """
          Return the offset from the start of the file to the code structure for this method, 
          or 0 if this method is either abstract or native

          :rtype: int
      """
      return self.code_off

    def get_access_flags_string(self) :
        """
            Return the access flags string of the method

            :rtype: string
        """
        if self.access_flags_string == None :
            self.access_flags_string = get_access_flags_string( self.get_access_flags() )

            if self.access_flags_string == "" :
                self.access_flags_string = "0x%x" % self.get_access_flags()
        return self.access_flags_string

    def reload(self) :
        v = self.CM.get_method( self.method_idx )

        self.class_name = v[0]
        self.name = v[1]
        self.proto = ''.join(i for i in v[2])

        self.code = self.CM.get_code( self.code_off )

    def get_locals(self):
        ret = self.proto.split(')')
        params = ret[0][1:].split()

        return self.code.get_registers_size() - len(params) - 1

    def each_params_by_register(self, nb, proto):
        bytecode._PrintSubBanner("Params")

        ret = proto.split(')')
        params = ret[0][1:].split()
        if params:
            bytecode._PrintDefault("- local registers: v%d...v%d\n" % (0, nb - len(params) - 1))
            j = 0
            for i in xrange(nb - len(params), nb):
                bytecode._PrintDefault("- v%d:%s\n" % (i, get_type(params[j])))
                j += 1
        else :
            bytecode._PrintDefault("local registers: v%d...v%d\n" % (0, nb-1))

        bytecode._PrintDefault("- return:%s\n" % get_type(ret[1]))
        bytecode._PrintSubBanner() 

    def show_info(self) :
        """
            Display the basic information about the method
        """
        bytecode._PrintSubBanner("Method Information") 
        bytecode._PrintDefault("%s->%s%s [access_flags=%s]\n" % ( self.get_class_name(), self.get_name(), self.get_descriptor(), self.get_access_flags_string() ))
 
    def show(self) :
        """
            Display the information about the method
        """
        colors = bytecode.disable_print_colors()
        self.pretty_show()
        bytecode.enable_print_colors(colors)

    def pretty_show(self) :
        """
            Display the information (with a pretty print) about the method
        """
        self.show_info()
        self.show_notes()
        if self.code != None :
            self.each_params_by_register( self.code.get_registers_size(), self.get_descriptor() )
            if self.CM.get_vmanalysis() == None :
                self.code.show()
            else :
                self.code.pretty_show( self.CM.get_vmanalysis().get_method( self ) )
                self.show_xref()

    def show_xref(self) :
        """
            Display where the method is called or which method is called
        """
        try :
            bytecode._PrintSubBanner("XREF") 
            bytecode._PrintXRef("F", self.XREFfrom.items)
            bytecode._PrintXRef("T", self.XREFto.items)
            bytecode._PrintSubBanner() 
        except AttributeError:
            pass

    def show_notes(self) :
      """
          Display the notes about the method
      """
      if self.notes != [] :
        bytecode._PrintSubBanner("Notes") 
        for i in self.notes :
          bytecode._PrintNote(i)
        bytecode._PrintSubBanner() 

    def source(self):
        """
            Return the source code of this method

            :rtype: string
        """
        self.CM.decompiler_ob.display_source(self)

    def get_source(self):
      return self.CM.decompiler_ob.get_source_method(self)

    def get_length(self) :
        """
          Return the length of the associated code of the method

          :rtype: int
        """
        if self.code != None :
            return self.code.get_length()
        return 0

    def get_code(self) :
        """
          Return the code object associated to the method

          :rtype: :class:`DalvikCode` object
        """
        return self.code

    def get_instructions(self) :
        """
            Get the instructions

            :rtype: a generator of each :class:`Instruction` (or a cached list of instructions if you have setup instructions)
        """
        if self.code == None :
          return []
        return self.code.get_bc().get_instructions()

    def set_instructions(self, instructions) :
        """
            Set the instructions

            :param instructions: the list of instructions
            :type instructions: a list of :class:`Instruction`
        """
        if self.code == None :
          return []
        return self.code.get_bc().set_instructions(instructions)

    def get_instruction(self, idx, off=None) :
        """
            Get a particular instruction by using (default) the index of the address if specified

            :param idx: index of the instruction (the position in the list of the instruction)
            :type idx: int
            :param off: address of the instruction
            :type off: int

            :rtype: an :class:`Instruction` object
        """
        if self._code != None :
            return self.code.get_bc().get_instruction(idx, off)
        return None

    def get_debug(self) :
        """
          Return the debug object associated to this method

          :rtype: :class:`DebugInfoItem`
        """
        if self.code == None :
            return None
        return self.code.get_debug()

    def get_descriptor(self) :
        """
          Return the descriptor of the method

          :rtype: string
        """
        return self.proto

    def get_class_name(self) :
        """
          Return the class name of the method

          :rtype: string
        """
        return self.class_name

    def get_name(self) :
        """
          Return the name of the method

          :rtype: string
        """
        return self.name

    def add_inote(self, msg, idx, off=None) :
        """
            Add a message to a specific instruction by using (default) the index of the address if specified

            :param msg: the message
            :type msg: string
            :param idx: index of the instruction (the position in the list of the instruction)
            :type idx: int
            :param off: address of the instruction
            :type off: int
        """
        if self.code != None :  
            self.code.add_inote(msg, idx, off)

    def add_note(self, msg) :
        """
            Add a message to this method

            :param msg: the message
            :type msg: string
        """
        self.notes.append( msg )

    def set_code_idx(self, idx) :
        """
            Set the start address of the buffer to disassemble

            :param idx: the index
            :type idx: int
        """
        if self.code != None :
            self.code.set_idx( idx )

    def set_name(self, value) :
        self.CM.set_hook_method_name( self, value )
        self.reload()

    def get_raw(self) :
        if self.code != None :
          self.code_off = self.code.get_off()

        return writeuleb128( self.method_idx_diff ) + writeuleb128( self.access_flags ) + writeuleb128( self.code_off )

    def get_size(self) :
      return len(self.get_raw())

class ClassDataItem :
    """
        This class can parse a class_data_item of a dex file

        :param buff: a string which represents a Buff object of the class_data_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.static_fields_size = readuleb128( buff )
        self.instance_fields_size = readuleb128( buff )
        self.direct_methods_size = readuleb128( buff )
        self.virtual_methods_size = readuleb128( buff )

        self.static_fields = []
        self.instance_fields = []
        self.direct_methods = []
        self.virtual_methods = []

        self._load_elements( self.static_fields_size, self.static_fields, EncodedField, buff, cm )
        self._load_elements( self.instance_fields_size, self.instance_fields, EncodedField, buff, cm )
        self._load_elements( self.direct_methods_size, self.direct_methods, EncodedMethod, buff, cm )
        self._load_elements( self.virtual_methods_size, self.virtual_methods, EncodedMethod, buff, cm )

    def get_static_fields_size(self) :
      """
          Return the number of static fields defined in this item

          :rtype: int
      """
      return self.static_fields_size

    def get_instance_fields_size(self) :
      """
          Return the number of instance fields defined in this item

          :rtype: int
      """
      return self.instance_fields_size

    def get_direct_methods_size(self) :
      """
          Return the number of direct methods defined in this item

          :rtype: int
      """
      return self.direct_methods_size

    def get_virtual_methods_size(self) :
      """
          Return the number of virtual methods defined in this item

          :rtype: int
      """
      return self.virtual_methods_size

    def get_static_fields(self) :
      """
          Return the defined static fields, represented as a sequence of encoded elements

          :rtype: a list of :class:`EncodedField` objects
      """
      return self.static_fields

    def get_instance_fields(self) :
      """
          Return the defined instance fields, represented as a sequence of encoded elements

          :rtype: a list of :class:`EncodedField` objects
      """
      return self.instance_fields

    def get_direct_methods(self) :
      """
          Return the defined direct (any of static, private, or constructor) methods, represented as a sequence of encoded elements

          :rtype: a list of :class:`EncodedMethod` objects
      """
      return self.direct_methods

    def get_virtual_methods(self) :
      """
          Return the defined virtual (none of static, private, or constructor) methods, represented as a sequence of encoded elements

          :rtype: a list of :class:`EncodedMethod` objects
      """
      return self.virtual_methods

    def get_methods(self) :
        """
            Return direct and virtual methods

            :rtype: a list of :class:`EncodedMethod` objects
        """
        return [ x for x in self.direct_methods ] + [ x for x in self.virtual_methods ]

    def get_fields(self) :
        """
            Return static and instance fields

            :rtype: a list of :class:`EncodedField` objects
        """
        return [ x for x in self.static_fields ] + [ x for x in self.instance_fields ]


    def set_off(self, off) :
      self.offset = off

    def set_static_fields(self, value) :
        if value != None :
            values = value.get_values()
            if len(values) <= len(self.static_fields) :
                for i in xrange(0, len(values)) :
                    self.static_fields[i].set_init_value( values[i] )

    def _load_elements(self, size, l, Type, buff, cm) :
        prev = 0
        for i in xrange(0, size) :
            el = Type(buff, cm)
            el.adjust_idx( prev )

            if isinstance(el, EncodedField) :
              prev = el.get_field_idx()
            else :
              prev = el.get_method_idx()

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
        self.pretty_show()

    def pretty_show(self) :
        bytecode._PrintSubBanner("Class Data Item")
        bytecode._PrintDefault("static_fields_size=%d instance_fields_size=%d direct_methods_size=%d virtual_methods_size=%d\n" % \
                (self.static_fields_size, self.instance_fields_size, self.direct_methods_size, self.virtual_methods_size))

        bytecode._PrintSubBanner("Static Fields")
        for i in self.static_fields :
            i.show()

        bytecode._PrintSubBanner("Instance Fields")
        for i in self.instance_fields :
            i.show()

        bytecode._PrintSubBanner("Direct Methods")
        for i in self.direct_methods :
            i.pretty_show()

        bytecode._PrintSubBanner("Virtual Methods")
        for i in self.virtual_methods :
            i.pretty_show()

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

        return buff

    def get_length(self) :
      length = len(writeuleb128( self.static_fields_size )) +   \
              len(writeuleb128( self.instance_fields_size )) +  \
              len(writeuleb128( self.direct_methods_size )) +   \
              len(writeuleb128( self.virtual_methods_size ))

      for i in self.static_fields :
        length += i.get_size()

      for i in self.instance_fields :
        length += i.get_size()

      for i in self.direct_methods :
        length += i.get_size()

      for i in self.virtual_methods :
        length += i.get_size()

      return length

    def get_off(self) :
      return self.offset

class ClassDefItem :
    """
        This class can parse a class_def_item of a dex file

        :param buff: a string which represents a Buff object of the class_def_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.class_idx = unpack("=I", buff.read(4))[0]
        self.access_flags = unpack("=I", buff.read(4))[0]
        self.superclass_idx = unpack("=I", buff.read(4))[0]
        self.interfaces_off = unpack("=I", buff.read(4))[0]
        self.source_file_idx = unpack("=I", buff.read(4))[0]
        self.annotations_off = unpack("=I", buff.read(4))[0]
        self.class_data_off = unpack("=I", buff.read(4))[0]
        self.static_values_off = unpack("=I", buff.read(4))[0]

        self.interfaces = None
        self.class_data_item = None
        self.static_values = None

        self.name = None
        self.sname = None
        self.access_flags_string = None

    def reload(self) :
        self.name = self.__CM.get_type( self.class_idx )
        self.sname = self.__CM.get_type( self.superclass_idx )

        if self.interfaces_off != 0 :
            self.interfaces = self.__CM.get_type_list( self.interfaces_off )

        if self.class_data_off != 0 :
            self.class_data_item = self.__CM.get_class_data_item( self.class_data_off )
            self.class_data_item.reload()

        if self.static_values_off != 0 :
            self.static_values = self.__CM.get_encoded_array_item ( self.static_values_off )

            if self.class_data_item != None :
                self.class_data_item.set_static_fields( self.static_values.get_value() )

    def get_methods(self) :
        """
            Return all methods of this class

            :rtype: a list of :class:`EncodedMethod` objects
        """
        if self.class_data_item != None :
            return self.class_data_item.get_methods()
        return []

    def get_fields(self) :
        """
            Return all fields of this class

            :rtype: a list of :class:`EncodedField` objects
        """
        if self.class_data_item != None :
            return self.class_data_item.get_fields()
        return []

    def get_class_idx(self) :
        """
            Return the index into the type_ids list for this class

            :rtype: int
        """
        return self.class_idx

    def get_access_flags(self) :
        """
            Return the access flags for the class (public, final, etc.)

            :rtype: int
        """
        return self.access_flags

    def get_superclass_idx(self) :
        """
            Return the index into the type_ids list for the superclass

            :rtype: int
        """
        return self.superclass_idx

    def get_interfaces_off(self) :
        """
            Return the offset from the start of the file to the list of interfaces, or 0 if there are none

            :rtype: int
        """
        return self.interfaces_off

    def get_source_file_idx(self) :
        """
            Return the index into the string_ids list for the name of the file containing the original 
            source for (at least most of) this class, or the special value NO_INDEX to represent a lack of this information

            :rtype: int
        """
        return self.source_file_idx

    def get_annotations_off(self) :
        """
            Return the offset from the start of the file to the annotations structure for this class, 
            or 0 if there are no annotations on this class.

            :rtype: int
        """
        return self.annotations_off

    def get_class_data_off(self) :
        """
            Return the offset from the start of the file to the associated class data for this item,
            or 0 if there is no class data for this class

            :rtype: int
        """
        return self.class_data_off

    def get_static_values_off(self) :
        """
            Return the offset from the start of the file to the list of initial values for static fields,
            or 0 if there are none (and all static fields are to be initialized with 0 or null)

            :rtype: int 
        """
        return self.static_values_off


    def get_class_data(self) :
        """
            Return the associated class_data_item

            :rtype: a :class:`ClassDataItem` object
        """
        return self.class_data_item

    def get_name(self) :
        """
            Return the name of this class

            :rtype: int
        """
        return self.name

    def get_superclassname(self) :
        """
            Return the name of the super class

            :rtype: string
        """
        return self.sname

    def get_interfaces(self) :
      """
          Return the name of the interface

          :rtype: string
      """
      return self.interfaces

    def get_access_flags_string(self) :
        """
            Return the access flags string of the class

            :rtype: string
        """
        if self.access_flags_string == None :
            self.access_flags_string = get_access_flags_string( self.get_access_flags() )

            if self.access_flags_string == "" :
                self.access_flags_string = "0x%x" % self.get_access_flags()
        return self.access_flags_string

    def show(self) :
        bytecode._PrintSubBanner("Class Def Item")
        bytecode._PrintDefault("name=%s, sname=%s, interfaces=%s, access_flags=%s\n" %
                              ( self.name,
                                self.sname,
                                self.interfaces,
                                self.get_access_flags_string()))
        bytecode._PrintDefault("class_idx=%d, superclass_idx=%d, interfaces_off=%x, source_file_idx=%d, annotations_off=%x, class_data_off=%x, static_values_off=%x\n" %
                              ( self.class_idx,
                                self.superclass_idx,
                                self.interfaces_off,
                                self.source_file_idx,
                                self.annotations_off,
                                self.class_data_off,
                                self.static_values_off))

    def source(self) :
        """
            Return the source code of the entire class

            :rtype: string
        """
        self.__CM.decompiler_ob.display_all(self)

    def get_source(self):
      return self.__CM.decompiler_ob.get_source_class(self)

    def set_name(self, value) :
        self.__CM.set_hook_class_name( self, value )

    def get_obj(self) :
      if self.interfaces_off != 0 :
        self.interfaces_off = self.__CM.get_obj_by_offset( self.interfaces_off ).get_off()

      if self.annotations_off != 0 :
        self.annotations_off = self.__CM.get_obj_by_offset( self.annotations_off ).get_off()

      if self.class_data_off != 0 :
        self.class_data_off = self.__CM.get_obj_by_offset( self.class_data_off ).get_off()

      if self.static_values_off != 0 :
        self.static_values_off = self.__CM.get_obj_by_offset( self.static_values_off ).get_off()

      return  pack("=I", self.class_idx) +          \
              pack("=I", self.access_flags) +       \
              pack("=I", self.superclass_idx) +     \
              pack("=I", self.interfaces_off) +     \
              pack("=I", self.source_file_idx) +    \
              pack("=I", self.annotations_off) +    \
              pack("=I", self.class_data_off) +     \
              pack("=I", self.static_values_off)

    def get_raw(self) :
        return self.get_obj()

    def get_length(self) :
      return len(self.get_obj())

class ClassHDefItem :
    """
        This class can parse a list of class_def_item of a dex file

        :param buff: a string which represents a Buff object of the list of class_def_item
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.class_def = []

        for i in xrange(0, size) :
            idx = buff.get_idx()

            class_def = ClassDefItem( buff, cm )
            self.class_def.append( class_def )

            buff.set_idx( idx + calcsize("=IIIIIIII") )

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def get_class_idx(self, idx) :
      for i in self.class_def :
          if i.get_class_idx() == idx :
            return i 
      return None

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
        for i in self.class_def :
            i.show()

    def get_obj(self) :
        return [ i for i in self.class_def ]

    def get_raw(self) :
        return ''.join(i.get_raw() for i in self.class_def)

    def get_length(self) :
      length = 0
      for i in self.class_def :
        length += i.get_length()
      return length

class EncodedTypeAddrPair :
    """
        This class can parse an encoded_type_addr_pair of a dex file

        :param buff: a string which represents a Buff object of the encoded_type_addr_pair
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff) :
        self.type_idx = readuleb128( buff )
        self.addr = readuleb128( buff )

    def get_type_idx(self) :
        """
            Return the index into the type_ids list for the type of the exception to catch

            :rtype: int
        """
        return self.type_idx

    def get_addr(self) :
        """
            Return the bytecode address of the associated exception handler

            :rtype: int
        """
        return self.addr

    def get_obj(self) :
        return []

    def show(self) :
        bytecode._PrintSubBanner("Encoded Type Addr Pair")
        bytecode._PrintDefault("type_idx=%d addr=%x\n" % (self.type_idx, self.addr))

    def get_raw(self) :
        return writeuleb128( self.type_idx ) + writeuleb128( self.addr )

    def get_length(self) :
      return len(self.get_raw())

class EncodedCatchHandler :
    """
        This class can parse an encoded_catch_handler of a dex file

        :param buff: a string which represents a Buff object of the encoded_catch_handler
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()

        self.size = readsleb128( buff )

        self.handlers = []

        for i in xrange(0, abs(self.size)) :
            self.handlers.append( EncodedTypeAddrPair(buff) )

        if self.size <= 0 :
            self.catch_all_addr = readuleb128( buff )

    def get_size(self) :
        """
            Return the number of catch types in this list

            :rtype: int
        """
        return self.size

    def get_handlers(self) :
        """
            Return the stream of abs(size) encoded items, one for each caught type, in the order that the types should be tested.

            :rtype: a list of :class:`EncodedTypeAddrPair` objects
        """
        return self.handlers

    def get_catch_all_addr(self) :
        """
            Return the bytecode address of the catch-all handler. This element is only present if size is non-positive.

            :rtype: int
        """
        return self.catch_all_addr

    def get_off(self) :
      return self.offset

    def set_off(self, off) :
      self.offset = off

    def show(self) :
        bytecode._PrintSubBanner("Encoded Catch Handler")
        bytecode._PrintDefault("size=%d\n" % self.size)

        for i in self.handlers :
            i.show()

        if self.size <= 0 :
            bytecode._PrintDefault("catch_all_addr=%x\n" % self.catch_all_addr)

    def get_raw(self) :
        buff = writesleb128( self.size ) + ''.join(i.get_raw() for i in self.handlers)

        if self.size <= 0 :
            buff += writeuleb128( self.catch_all_addr )

        return buff

    def get_length(self) :
      length = len(writesleb128( self.size ))

      for i in self.handlers :
        length += i.get_length()

      if self.size <= 0 :
        length += len(writeuleb128( self.catch_all_addr ))

      return length

class EncodedCatchHandlerList :
    """
        This class can parse an encoded_catch_handler_list of a dex file

        :param buff: a string which represents a Buff object of the encoded_catch_handler_list
        :type buff: Buff object
        :param cm: a ClassManager object
        :type cm: :class:`ClassManager`
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()

        self.size = readuleb128( buff )
        self.list = []

        for i in xrange(0, self.size) :
            self.list.append( EncodedCatchHandler(buff, cm) )


    def get_size(self) :
      """
          Return the size of this list, in entries

          :rtype: int
      """
      return self.size

    def get_list(self) :
        """
            Return the actual list of handler lists, represented directly (not as offsets), and concatenated sequentially

            :rtype: a list of :class:`EncodedCatchHandler` objects
        """
        return self.list

    def show(self) :
        bytecode._PrintSubBanner("Encoded Catch Handler List")
        bytecode._PrintDefault("size=%d\n" % self.size)

        for i in self.list :
            i.show()

    def get_off(self) :
      return self.offset

    def set_off(self, off) :
      self.offset = off

    def get_obj(self) :
        return writeuleb128( self.size )

    def get_raw(self) :
        return self.get_obj() + ''.join(i.get_raw() for i in self.list)

    def get_length(self) :
      length = len(self.get_obj())

      for i in self.list :
        length += i.get_length()
      return length


KIND_METH           = 0
KIND_STRING         = 1
KIND_FIELD          = 2
KIND_TYPE           = 3
VARIES              = 4
INLINE_METHOD       = 5
VTABLE_OFFSET       = 6
FIELD_OFFSET        = 7
KIND_RAW_STRING     = 8

def get_kind(cm, kind, value) :
  """
    Return the value of the 'kind' argument

    :param cm: a ClassManager object
    :type cm: :class:`ClassManager`
    :param kind: the type of the 'kind' argument
    :type kind: int
    :param value: the value of the 'kind' argument
    :type value: int

    :rtype: string
  """ 
  if kind == KIND_METH:
    method = cm.get_method_ref(value)
    class_name = method.get_class_name()
    name = method.get_name()
    descriptor = method.get_descriptor()

    return "%s->%s%s" % (class_name, name, descriptor)

  elif kind == KIND_STRING:
    return repr(cm.get_string(value))

  elif kind == KIND_RAW_STRING:
    return cm.get_string(value)

  elif kind == KIND_FIELD:
    class_name, proto, field_name = cm.get_field(value)
    return "%s->%s %s" % (class_name, field_name, proto)

  elif kind == KIND_TYPE:
    return cm.get_type(value)

  elif kind == VTABLE_OFFSET:
    return "vtable[0x%x]" % value

  elif kind == FIELD_OFFSET:
    return "field[0x%x]" % value

  elif kind == INLINE_METHOD:
    buff = "inline[0x%x]" % value

    # FIXME: depends of the android version ...
    if len(INLINE_METHODS) > value:
        elem = INLINE_METHODS[value]
        buff += " %s->%s%s" % (elem[0], elem[1], elem[2])

    return buff

  return None

class Instruction(object) :
    """
        This class represents a dalvik instruction
    """
    def get_kind(self) :
        """
            Return the 'kind' argument of the instruction

            :rtype: int
        """
        if self.OP > 0xff :
          if self.OP >= 0xf2ff :
            return DALVIK_OPCODES_OPTIMIZED[ self.OP ][1][1]
          return DALVIK_OPCODES_EXTENDED_WIDTH[ self.OP ][1][1]
        return DALVIK_OPCODES_FORMAT[ self.OP ][1][1]

    def get_name(self) :
        """
            Return the name of the instruction

            :rtype: string
        """
        if self.OP > 0xff :
          if self.OP >= 0xf2ff :
            return DALVIK_OPCODES_OPTIMIZED[ self.OP ][1][0]
          return DALVIK_OPCODES_EXTENDED_WIDTH[ self.OP ][1][0]
        return DALVIK_OPCODES_FORMAT[ self.OP ][1][0]

    def get_op_value(self) :
        """
            Return the value of the opcode

            :rtype: int
        """
        return self.OP

    def get_literals(self) :
        """
            Return the associated literals

            :rtype: list of int
        """
        return []

    def show(self, idx) :
        """
            Print the instruction
        """    
        print self.get_name() + " " + self.get_output(idx),

    def show_buff(self, idx) :
        """
            Return the display of the instruction

            :rtype: string
        """    
        return self.get_output(idx)

    def get_translated_kind(self) :
        """
            Return the translated value of the 'kind' argument

            :rtype: string
        """    
        return get_kind(self.cm, self.get_kind(), self.get_ref_kind())

    def get_output(self, idx=-1) :
      """
          Return an additional output of the instruction

          :rtype: string
      """ 
      raise("not implemented")

    def get_length(self) :
      """
          Return the length of the instruction

          :rtype: int
      """   
      raise("not implemented")

    def get_raw(self) :
      """
          Return the object in a raw format

          :rtype: string
      """ 
      raise("not implemented")

    def get_ref_kind(self) :
      """
          Return the value of the 'kind' argument

          :rtype: value
      """
      raise("not implemented")

class InstructionInvalid(Instruction) :
    """
        This class represents an invalid instruction
    """
    def __init__(self, cm, buff) :
      super(InstructionInvalid, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff

      #debug("OP:%x" % (self.OP))

    def get_name(self) :
        """
            Return the name of the instruction

            :rtype: string
        """
        return "invalid"

    def get_output(self, idx=-1) :
      return "(OP:%x)" % self.OP

    def get_length(self) :
      return 2

    def get_raw(self) :
      return pack("=H", self.OP)


class FillArrayData :
    """
        This class can parse a FillArrayData instruction

        :param buff: a Buff object which represents a buffer where the instruction is stored
    """
    def __init__(self, buff) :
        self.notes = []

        self.format_general_size = calcsize("=HHI")
        self.ident = unpack("=H", buff[0:2])[0]
        self.element_width = unpack("=H", buff[2:4])[0]
        self.size = unpack("=I", buff[4:8])[0]

        self.data = buff[ self.format_general_size : self.format_general_size + (self.size * self.element_width) +1 ]

    def add_note(self, msg) :
      """
        Add a note to this instruction

        :param msg: the message
        :type msg: objects (string)
      """
      self.notes.append( msg )

    def get_notes(self) :
      """
        Get all notes from this instruction

        :rtype: a list of objects
      """
      return self.notes

    def get_op_value(self) :
      """
        Get the value of the opcode

        :rtype: int
      """      
      return self.ident

    def get_data(self) :
        """
            Return the data of this instruction (the payload)

            :rtype: string
        """
        return self.data

    def get_output(self, idx=-1) :
        """
            Return an additional output of the instruction

            :rtype: string
        """ 
        buff = ""

        data = self.get_data()

        buff += repr(data) + " | "
        for i in xrange(0, len(data)) :
          buff += "\\x%02x" % ord( data[i] )

        return buff

    def get_name(self) :
        """
            Return the name of the instruction

            :rtype: string
        """
        return "fill-array-data-payload"

    def show_buff(self, pos) :
        """
            Return the display of the instruction

            :rtype: string
        """     
        buff = self.get_name() + " "

        for i in xrange(0, len(self.data)) :
            buff += "\\x%02x" % ord( self.data[i] )
        return buff

    def show(self, pos) :
        """
            Print the instruction
        """   
        print self.show_buff(pos),

    def get_length(self) :
        """
            Return the length of the instruction

            :rtype: int
        """   
        return ((self.size * self.element_width + 1) / 2 + 4) * 2

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.element_width) + pack("=I", self.size) + self.data

class SparseSwitch :
    """
        This class can parse a SparseSwitch instruction

        :param buff: a Buff object which represents a buffer where the instruction is stored
    """
    def __init__(self, buff) :
        self.notes = []

        self.format_general_size = calcsize("=HH")
        self.ident = unpack("=H", buff[0:2])[0]
        self.size = unpack("=H", buff[2:4])[0]

        self.keys = []
        self.targets = []

        idx = self.format_general_size
        for i in xrange(0, self.size) :
            self.keys.append( unpack('=l', buff[idx:idx+4])[0] )
            idx += 4

        for i in xrange(0, self.size) :
            self.targets.append( unpack('=l', buff[idx:idx+4])[0] )
            idx += 4

    def add_note(self, msg) :
      """
        Add a note to this instruction

        :param msg: the message
        :type msg: objects (string)
      """
      self.notes.append( msg )

    def get_notes(self) :
      """
        Get all notes from this instruction

        :rtype: a list of objects
      """
      return self.notes

    def get_op_value(self) :
        """
          Get the value of the opcode

          :rtype: int
        """    
        return self.ident

    def get_keys(self) :
        """
            Return the keys of the instruction

            :rtype: a list of long
        """
        return self.keys

    def get_values(self) :
      return self.get_keys()

    def get_targets(self) :
        """
            Return the targets (address) of the instruction

            :rtype: a list of long
        """
        return self.targets

    def get_output(self, idx=-1) :
      """
          Return an additional output of the instruction

          :rtype: string
      """ 
      return " ".join("%x" % i for i in self.keys)

    def get_name(self) :
        """
            Return the name of the instruction

            :rtype: string
        """
        return "sparse-switch-payload"

    def show_buff(self, pos) :
        """
            Return the display of the instruction

            :rtype: string
        """   
        buff = self.get_name() + " "
        for i in xrange(0, len(self.keys)) :
            buff += "%x:%x " % (self.keys[i], self.targets[i])

        return buff

    def show(self, pos) :
        """
            Print the instruction
        """ 
        print self.show_buff( pos ),

    def get_length(self) :
        return self.format_general_size + (self.size * calcsize('<L')) * 2

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.size) + ''.join(pack("=l", i) for i in self.keys) + ''.join(pack("=l", i) for i in self.targets)

class PackedSwitch :
    """
        This class can parse a PackedSwitch instruction

        :param buff: a Buff object which represents a buffer where the instruction is stored
    """
    def __init__(self, buff) :
        self.notes = []

        self.format_general_size = calcsize( "=HHI" )

        self.ident = unpack("=H", buff[0:2])[0]
        self.size = unpack("=H", buff[2:4])[0]
        self.first_key = unpack("=i", buff[4:8])[0]

        self.targets = []

        idx = self.format_general_size

        max_size = self.size
        if (max_size * 4) > len(buff) :
            max_size = len(buff) - idx - 8

        for i in xrange(0, max_size) :
            self.targets.append( unpack('=l', buff[idx:idx+4])[0] )
            idx += 4

    def add_note(self, msg) :
      """
        Add a note to this instruction

        :param msg: the message
        :type msg: objects (string)
      """
      self.notes.append( msg )

    def get_notes(self) :
      """
        Get all notes from this instruction

        :rtype: a list of objects
      """
      return self.notes

    def get_op_value(self) :
        """
          Get the value of the opcode

          :rtype: int
        """    
        return self.ident

    def get_keys(self) :
        """
            Return the keys of the instruction

            :rtype: a list of long
        """
        return [(self.first_key+i) for i in range(0, len(self.targets))]

    def get_values(self) :
        return self.get_keys()

    def get_targets(self) :
        """
            Return the targets (address) of the instruction

            :rtype: a list of long
        """
        return self.targets

    def get_output(self, idx=-1) :
      """
          Return an additional output of the instruction

          :rtype: string
      """ 
      return " ".join("%x" % (self.first_key+i) for i in range(0, len(self.targets)))

    def get_name(self) :
        """
            Return the name of the instruction

            :rtype: string
        """
        return "packed-switch-payload"

    def show_buff(self, pos) :
        """
            Return the display of the instruction

            :rtype: string
        """ 
        buff = self.get_name() + " "
        buff += "%x:" % self.first_key

        for i in self.targets :
            buff += " %x" % i

        return buff

    def show(self, pos) :
        """
            Print the instruction
        """ 
        print self.show_buff( pos ),

    def get_length(self) :
        return self.format_general_size + (self.size * calcsize('=L'))

    def get_raw(self) :
        return pack("=H", self.ident) + pack("=H", self.size) + pack("=i", self.first_key) + ''.join(pack("=l", i) for i in self.targets)


class Instruction35c(Instruction) :
    """
        This class represents all instructions which have the 35c format
    """
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
    """
        This class represents all instructions which have the 10x format
    """
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
    """
        This class represents all instructions which have the 21h format
    """
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
     
      buff += "v%d, %d" % (self.AA, self.BBBB)

      if self.formatted_operands != [] :
        buff += " # %s" % (str(self.formatted_operands))

      return buff

    def get_literals(self) :
      return [ self.BBBB ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction11n(Instruction) :
    """
        This class represents all instructions which have the 11n format
    """
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
      buff += "v%d, %d" % (self.A, self.B)
      return buff

    def get_literals(self) :
      return [ self.B ]

    def get_raw(self) :
      return pack("=H", (self.B << 12) | (self.A << 8) | self.OP)

class Instruction21c(Instruction) :
    """
        This class represents all instructions which have the 21c format
    """
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
   
    def get_raw_string(self) :
      return get_kind(self.cm, KIND_RAW_STRING, self.BBBB)

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction21s(Instruction) :
    """
        This class represents all instructions which have the 21s format
    """
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
      buff += "v%d, %d" % (self.AA, self.BBBB)

      if self.formatted_operands != [] :
        buff += " # %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBB ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction22c(Instruction) :
    """
        This class represents all instructions which have the 22c format
    """
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

class Instruction22cs(Instruction) :
    """
        This class represents all instructions which have the 22cs format
    """
    def __init__(self, cm, buff) :
      super(Instruction22cs, self).__init__()
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
    """
        This class represents all instructions which have the 31t format
    """
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
    """
        This class represents all instructions which have the 31c format
    """
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
      """
          Return the string associated to the 'kind' argument

          :rtype: string
      """
      return get_kind(self.cm, self.get_kind(), self.BBBBBBBB)

    def get_raw(self) :
      return pack("=Hi", (self.AA << 8) | self.OP, self.BBBBBBBB)

class Instruction12x(Instruction) :
    """
        This class represents all instructions which have the 12x format
    """
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
    """
        This class represents all instructions which have the 11x format
    """
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
    """
        This class represents all instructions which have the 51l format
    """
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

      buff += "v%d, %d" % (self.AA, self.BBBBBBBBBBBBBBBB)

      if self.formatted_operands != [] :
        buff += " # %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBBBBBBBBBBBBBB ]

    def get_raw(self) :
      return pack("=Hq", (self.AA << 8) | self.OP, self.BBBBBBBBBBBBBBBB)

class Instruction31i(Instruction) :
    """
        This class represents all instructions which have the 3li format
    """
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
      buff += "v%d, %d" % (self.AA, self.BBBBBBBB)

      if self.formatted_operands != [] :
        buff += " # %s" % str(self.formatted_operands)

      return buff

    def get_literals(self) :
      return [ self.BBBBBBBB ]

    def get_raw(self) :
      return pack("=Hi", (self.AA << 8) | self.OP, self.BBBBBBBB)

class Instruction22x(Instruction) :
    """
        This class represents all instructions which have the 22x format
    """
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
    """
        This class represents all instructions which have the 23x format
    """
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
    """
        This class represents all instructions which have the 20t format
    """
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
      buff += "%+x" % (self.AAAA)
      return buff

    def get_ref_off(self) :
      return self.AAAA

    def get_raw(self) :
      return pack("=Hh", self.OP, self.AAAA)

class Instruction21t(Instruction) :
    """
        This class represents all instructions which have the 21t format
    """
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
      buff += "v%d, %+x" % (self.AA, self.BBBB)
      return buff

    def get_ref_off(self) :
      return self.BBBB

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, self.BBBB)

class Instruction10t(Instruction) :
    """
        This class represents all instructions which have the 10t format
    """
    def __init__(self, cm, buff) :
      super(Instruction10t, self).__init__()

      self.OP = unpack("=B", buff[0:1])[0]
      self.AA = unpack("=b", buff[1:2])[0]

      #log_andro.debug("OP:%x %s AA:%x" % (self.OP, args[0], self.AA))

    def get_length(self) :
      return 2

    def get_output(self, idx=-1):
      buff = ""
      buff += "%+x" % (self.AA)
      return buff

    def get_ref_off(self) :
      return self.AA

    def get_raw(self) :
      return pack("=Bb", self.OP, self.AA)

class Instruction22t(Instruction) :
    """
        This class represents all instructions which have the 22t format
    """
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
      buff += "v%d, v%d, %+x" % (self.A, self.B, self.CCCC)
      return buff

    def get_ref_off(self) :
      return self.CCCC

    def get_raw(self) :
      return pack("=Hh", (self.B << 12) | (self.A << 8) | self.OP, self.CCCC)

class Instruction22s(Instruction) :
    """
        This class represents all instructions which have the 22s format
    """
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
      buff += "v%d, v%d, %d" % (self.A, self.B, self.CCCC)
      return buff

    def get_literals(self) :
      return [ self.CCCC ]

    def get_raw(self) :
      return pack("=Hh", (self.B << 12) | (self.A << 8) | self.OP, self.CCCC)

class Instruction22b(Instruction) :
    """
        This class represents all instructions which have the 22b format
    """
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
      buff += "v%d, v%d, %d" % (self.AA, self.BB, self.CC)
      return buff

    def get_literals(self) :
      return [ self.CC ]

    def get_raw(self) :
      return pack("=Hh", (self.AA << 8) | self.OP, (self.CC << 8) | self.BB)

class Instruction30t(Instruction) :
    """
        This class represents all instructions which have the 30t format
    """
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
      buff += "%+x" % (self.AAAAAAAA)
      return buff

    def get_ref_off(self) :
      return self.AAAAAAAA

    def get_raw(self) :
      return pack("=Hi", self.OP, self.AAAAAAAA)

class Instruction3rc(Instruction) :
    """
        This class represents all instructions which have the 3rc format
    """
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
    """
        This class represents all instructions which have the 32x format
    """
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
      buff += "v%d, v%d" % (self.AAAA, self.BBBB)
      return buff

    def get_raw(self) :
      return pack("=HHH", self.OP, self.AAAA, self.BBBB)

class Instruction20bc(Instruction) :
    """
        This class represents all instructions which have the 20bc format
    """
    def __init__(self, cm, buff) :
      super(Instruction20bc, self).__init__()

      i16 = unpack("=H", buff[0:2])[0]
      self.OP = i16 & 0xff
      self.AA = (i16 >> 8) & 0xff

      self.BBBB = unpack("=H", buff[2:4])[0]

      #log_andro.debug("OP:%x %s AA:%x BBBBB:%x" % (self.OP, args[0], self.AA, self.BBBB))

    def get_length(self) :
      return 4

    def get_output(self, idx=-1) :
      buff = ""
      buff += "%d, %d" % (self.AA, self.BBBB)
      return buff

    def get_raw(self) :
      return pack("=HH", (self.AA << 8) | self.OP, self.BBBB)

class Instruction35mi(Instruction) :
    """
        This class represents all instructions which have the 35mi format
    """
    def __init__(self, cm, buff) :
      super(Instruction35mi, self).__init__()
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

      if self.A == 1 :
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

class Instruction35ms(Instruction) :
    """
        This class represents all instructions which have the 35ms format
    """
    def __init__(self, cm, buff) :
      super(Instruction35ms, self).__init__()
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

      if self.A == 1 :
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

class Instruction3rmi(Instruction) :
    """
        This class represents all instructions which have the 3rmi format
    """
    def __init__(self, cm, buff) :
      super(Instruction3rmi, self).__init__()
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

class Instruction3rms(Instruction) :
    """
        This class represents all instructions which have the 3rms format
    """
    def __init__(self, cm, buff) :
      super(Instruction3rms, self).__init__()
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

class Instruction41c(Instruction) :
    """
        This class represents all instructions which have the 41c format
    """
    def __init__(self, cm, buff) :
      super(Instruction41c, self).__init__()
      self.cm = cm

      self.OP = unpack("=H", buff[0:2])[0]
      self.BBBBBBBB =  unpack("=I", buff[2:6])[0]
      self.AAAA =  unpack("=H", buff[6:8])[0]

      #log_andro.debug("OP:%x %s AAAAA:%x BBBBB:%x" % (self.OP, args[0], self.AAAA, self.BBBBBBBB))

    def get_length(self) :
      return 8

    def get_output(self, idx=-1) :
      kind = get_kind(self.cm, self.get_kind(), self.BBBBBBBB)

      buff = ""
      buff += "v%d, %s" % (self.AAAA, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBBBBBB

    def get_raw(self) :
      return pack("=HIH", self.OP, self.BBBBBBBB, self.AAAA)

class Instruction40sc(Instruction) :
    """
        This class represents all instructions which have the 40sc format
    """
    def __init__(self, cm, buff) :
      super(Instruction40sc, self).__init__()
      self.cm = cm

      self.OP = unpack("=H", buff[0:2])[0]
      self.BBBBBBBB =  unpack("=I", buff[2:6])[0]
      self.AAAA =  unpack("=H", buff[6:8])[0]

      #log_andro.debug("OP:%x %s AAAAA:%x BBBBB:%x" % (self.OP, args[0], self.AAAA, self.BBBBBBBB))

    def get_length(self) :
      return 8

    def get_output(self, idx=-1) :
      kind = get_kind(self.cm, self.get_kind(), self.BBBBBBBB)

      buff = ""
      buff += "%d, %s" % (self.AAAA, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBBBBBB

    def get_raw(self) :
      return pack("=HIH", self.OP, self.BBBBBBBB, self.AAAA)

class Instruction52c(Instruction) :
    """
        This class represents all instructions which have the 52c format
    """
    def __init__(self, cm, buff) :
      super(Instruction52c, self).__init__()
      self.cm = cm

      self.OP = unpack("=H", buff[0:2])[0]
      self.CCCCCCCC =  unpack("=I", buff[2:6])[0]
      self.AAAA =  unpack("=H", buff[6:8])[0]
      self.BBBB =  unpack("=H", buff[8:10])[0]
      
      #log_andro.debug("OP:%x %s AAAAA:%x BBBBB:%x" % (self.OP, args[0], self.AAAA, self.BBBB))

    def get_length(self) :
      return 10

    def get_output(self, idx=-1) :
      kind = get_kind(self.cm, self.get_kind(), self.CCCCCCCC)

      buff = ""
      buff += "v%d, v%d, %s" % (self.AAAA, self.BBBB, kind)
      return buff

    def get_ref_kind(self) :
      return self.CCCCCCCC

    def get_raw(self) :
      return pack("=HIHH", self.OP, self.CCCCCCCC, self.AAAA, self.BBBB)

class Instruction5rc(Instruction) :
    """
        This class represents all instructions which have the 5rc format
    """
    def __init__(self, cm, buff) :
      super(Instruction5rc, self).__init__()
      self.cm = cm

      self.OP = unpack("=H", buff[0:2])[0]
      self.BBBBBBBB = unpack("=I", buff[2:6])[0]
      self.AAAA = unpack("=H", buff[6:8])[0]
      self.CCCC = unpack("=H", buff[8:10])[0]

      self.NNNN = self.CCCC + self.AAAA - 1

      #log_andro.debug("OP:%x %s AA:%x BBBB:%x CCCC:%x NNNN:%d" % (self.OP, args[0], self.AAAA, self.BBBBBBBB, self.CCCC, self.NNNN))

    def get_length(self) :
      return 10

    def get_output(self, idx=-1) :
      buff = ""

      kind = get_kind(self.cm, self.get_kind(), self.BBBBBBBB)

      if self.CCCC == self.NNNN :
        buff += "v%d, %s" % (self.CCCC, kind)
      else :
        buff += "v%d ... v%d, %s" % (self.CCCC, self.NNNN, kind)
      return buff

    def get_ref_kind(self) :
      return self.BBBBBBBB

    def get_raw(self) :
      return pack("=HIHH", self.OP, self.BBBBBBBB, self.AAAA, self.CCCC)


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


  # expanded opcodes
  0xe3 : [Instruction22c, [ "iget-volatile", KIND_FIELD ] ],
  0xe4 : [Instruction22c, [ "iput-volatile", KIND_FIELD ] ],
  0xe5 : [Instruction21c, [ "sget-volatile", KIND_FIELD ] ],
  0xe6 : [Instruction21c, [ "sput-volatile", KIND_FIELD ] ],
  0xe7 : [Instruction22c, [ "iget-object-volatile", KIND_FIELD ] ],
  0xe8 : [Instruction22c, [ "iget-wide-volatile", KIND_FIELD ] ],
  0xe9 : [Instruction22c, [ "iput-wide-volatile", KIND_FIELD ] ],
  0xea : [Instruction21c, [ "sget-wide-volatile", KIND_FIELD ] ],
  0xeb : [Instruction21c, [ "sput-wide-volatile", KIND_FIELD ] ],

  0xec : [Instruction10x,   [ "breakpoint" ] ],
  0xed : [Instruction20bc,  [ "throw-verification-error", VARIES ] ],
  0xee : [Instruction35mi,  [ "execute-inline", INLINE_METHOD ] ],
  0xef : [Instruction3rmi,  [ "execute-inline/range", INLINE_METHOD ] ],
  0xf0 : [Instruction35c,   [ "invoke-object-init/range", KIND_METH ] ],
  0xf1 : [Instruction10x,   [ "return-void-barrier" ] ],

  0xf2 : [Instruction22cs,  [ "iget-quick", FIELD_OFFSET ] ],
  0xf3 : [Instruction22cs,  [ "iget-wide-quick", FIELD_OFFSET ] ],
  0xf4 : [Instruction22cs,  [ "iget-object-quick", FIELD_OFFSET ] ],
  0xf5 : [Instruction22cs,  [ "iput-quick", FIELD_OFFSET ] ],
  0xf6 : [Instruction22cs,  [ "iput-wide-quick", FIELD_OFFSET ] ],
  0xf7 : [Instruction22cs,  [ "iput-object-quick", FIELD_OFFSET ] ],
  0xf8 : [Instruction35ms,  [ "invoke-virtual-quick", VTABLE_OFFSET ] ],
  0xf9 : [Instruction3rms,  [ "invoke-virtual-quick/range", VTABLE_OFFSET ] ],
  0xfa : [Instruction35ms,  [ "invoke-super-quick", VTABLE_OFFSET ] ],
  0xfb : [Instruction3rms,  [ "invoke-super-quick/range", VTABLE_OFFSET ] ],
  0xfc : [Instruction22c,   [ "iput-object-volatile", KIND_FIELD ] ],
  0xfd : [Instruction21c,   [ "sget-object-volatile", KIND_FIELD ] ],
  0xfe : [Instruction21c,   [ "sput-object-volatile", KIND_FIELD ] ],
}

DALVIK_OPCODES_PAYLOAD = {
    0x0100 : [PackedSwitch],
    0x0200 : [SparseSwitch],
    0x0300 : [FillArrayData],
}

INLINE_METHODS = [ 
    [ "Lorg/apache/harmony/dalvik/NativeTestTarget;", "emptyInlineMethod", "()V" ],

    [ "Ljava/lang/String;", "charAt", "(I)C" ],
    [ "Ljava/lang/String;", "compareTo", "(Ljava/lang/String;)I" ],
    [ "Ljava/lang/String;", "equals", "(Ljava/lang/Object;)Z" ],
    [ "Ljava/lang/String;", "fastIndexOf", "(II)I" ],
    [ "Ljava/lang/String;", "isEmpty", "()Z" ],
    [ "Ljava/lang/String;", "length", "()I" ],

    [ "Ljava/lang/Math;", "abs", "(I)I" ],
    [ "Ljava/lang/Math;", "abs", "(J)J" ],
    [ "Ljava/lang/Math;", "abs", "(F)F" ],
    [ "Ljava/lang/Math;", "abs", "(D)D" ],
    [ "Ljava/lang/Math;", "min", "(II)I" ],
    [ "Ljava/lang/Math;", "max", "(II)I" ],
    [ "Ljava/lang/Math;", "sqrt", "(D)D" ],
    [ "Ljava/lang/Math;", "cos", "(D)D" ],
    [ "Ljava/lang/Math;", "sin", "(D)D" ],

    [ "Ljava/lang/Float;", "floatToIntBits", "(F)I" ],
    [ "Ljava/lang/Float;", "floatToRawIntBits", "(F)I" ],
    [ "Ljava/lang/Float;", "intBitsToFloat", "(I)F" ],
    [ "Ljava/lang/Double;", "doubleToLongBits", "(D)J" ],
    [ "Ljava/lang/Double;", "doubleToRawLongBits", "(D)J" ],
    [ "Ljava/lang/Double;", "longBitsToDouble", "(J)D" ],
]

DALVIK_OPCODES_EXTENDED_WIDTH = {
    0x00ff: [ Instruction41c, ["const-class/jumbo", KIND_TYPE ] ],
    0x01ff: [ Instruction41c, ["check-cast/jumbo", KIND_TYPE ] ],

    0x02ff: [ Instruction52c, ["instance-of/jumbo", KIND_TYPE ] ],

    0x03ff: [ Instruction41c, ["new-instance/jumbo", KIND_TYPE ] ],

    0x04ff: [ Instruction52c, ["new-array/jumbo", KIND_TYPE ] ],

    0x05ff: [ Instruction5rc, ["filled-new-array/jumbo", KIND_TYPE ] ],

    0x06ff: [ Instruction52c, ["iget/jumbo", KIND_FIELD ] ],
    0x07ff: [ Instruction52c, ["iget-wide/jumbo", KIND_FIELD ] ],
    0x08ff: [ Instruction52c, ["iget-object/jumbo", KIND_FIELD ] ],
    0x09ff: [ Instruction52c, ["iget-boolean/jumbo", KIND_FIELD ] ],
    0x0aff: [ Instruction52c, ["iget-byte/jumbo", KIND_FIELD ] ],
    0x0bff: [ Instruction52c, ["iget-char/jumbo", KIND_FIELD ] ],
    0x0cff: [ Instruction52c, ["iget-short/jumbo", KIND_FIELD ] ],
    0x0dff: [ Instruction52c, ["iput/jumbo", KIND_FIELD ] ],
    0x0eff: [ Instruction52c, ["iput-wide/jumbo", KIND_FIELD ] ],
    0x0fff: [ Instruction52c, ["iput-object/jumbo", KIND_FIELD ] ],
    0x10ff: [ Instruction52c, ["iput-boolean/jumbo", KIND_FIELD ] ],
    0x11ff: [ Instruction52c, ["iput-byte/jumbo", KIND_FIELD ] ],
    0x12ff: [ Instruction52c, ["iput-char/jumbo", KIND_FIELD ] ],
    0x13ff: [ Instruction52c, ["iput-short/jumbo", KIND_FIELD ] ],

    0x14ff: [ Instruction41c, ["sget/jumbo", KIND_FIELD ] ],
    0x15ff: [ Instruction41c, ["sget-wide/jumbo", KIND_FIELD ] ],
    0x16ff: [ Instruction41c, ["sget-object/jumbo", KIND_FIELD ] ],
    0x17ff: [ Instruction41c, ["sget-boolean/jumbo", KIND_FIELD ] ],
    0x18ff: [ Instruction41c, ["sget-byte/jumbo", KIND_FIELD ] ],
    0x19ff: [ Instruction41c, ["sget-char/jumbo", KIND_FIELD ] ],
    0x1aff: [ Instruction41c, ["sget-short/jumbo", KIND_FIELD ] ],
    0x1bff: [ Instruction41c, ["sput/jumbo", KIND_FIELD ] ],
    0x1cff: [ Instruction41c, ["sput-wide/jumbo", KIND_FIELD ] ],
    0x1dff: [ Instruction41c, ["sput-object/jumbo", KIND_FIELD ] ],
    0x1eff: [ Instruction41c, ["sput-boolean/jumbo", KIND_FIELD ] ],
    0x1fff: [ Instruction41c, ["sput-byte/jumbo", KIND_FIELD ] ],
    0x20ff: [ Instruction41c, ["sput-char/jumbo", KIND_FIELD ] ],
    0x21ff: [ Instruction41c, ["sput-short/jumbo", KIND_FIELD ] ],

    0x22ff: [ Instruction5rc, ["invoke-virtual/jumbo", KIND_METH ] ],
    0x23ff: [ Instruction5rc, ["invoke-super/jumbo", KIND_METH ] ],
    0x24ff: [ Instruction5rc, ["invoke-direct/jumbo", KIND_METH ] ],
    0x25ff: [ Instruction5rc, ["invoke-static/jumbo", KIND_METH ] ],
    0x26ff: [ Instruction5rc, ["invoke-interface/jumbo", KIND_METH ] ],
}

DALVIK_OPCODES_OPTIMIZED = {
    0xf2ff : [ Instruction5rc, ["invoke-object-init/jumbo", KIND_METH ] ],

    0xf3ff : [ Instruction52c, ["iget-volatile/jumbo", KIND_FIELD ] ],
    0xf4ff : [ Instruction52c, ["iget-wide-volatile/jumbo", KIND_FIELD ] ],
    0xf5ff : [ Instruction52c, ["iget-object-volatile/jumbo ", KIND_FIELD ] ],
    0xf6ff : [ Instruction52c, ["iput-volatile/jumbo", KIND_FIELD ] ],
    0xf7ff : [ Instruction52c, ["iput-wide-volatile/jumbo", KIND_FIELD ] ],
    0xf8ff : [ Instruction52c, ["iput-object-volatile/jumbo", KIND_FIELD ] ],
    0xf9ff : [ Instruction41c, ["sget-volatile/jumbo", KIND_FIELD ] ],
    0xfaff : [ Instruction41c, ["sget-wide-volatile/jumbo", KIND_FIELD ] ],
    0xfbff : [ Instruction41c, ["sget-object-volatile/jumbo", KIND_FIELD ] ],
    0xfcff : [ Instruction41c, ["sput-volatile/jumbo", KIND_FIELD ] ],
    0xfdff : [ Instruction41c, ["sput-wide-volatile/jumbo", KIND_FIELD ] ],
    0xfeff : [ Instruction41c, ["sput-object-volatile/jumbo", KIND_FIELD ] ],

    0xffff : [ Instruction40sc, ["throw-verification-error/jumbo", VARIES ] ],
}

class Unresolved(Instruction) :
  def __init__(self, data) :
    self.data = data

  def get_name(self) :
    return "unresolved"

  def get_op_value(self) :
    return ord(self.data[0])

  def get_output(self, idx=-1) :
    return repr(self.data)

  def get_length(self) :
    return len(self.data)

  def get_raw(self) :
    return self.buff

def get_instruction(cm, op_value, buff, odex=False) :
  try :
    if not odex and (op_value >= 0xe3 and op_value <= 0xfe) :
      return InstructionInvalid( cm, buff )

    try :
      return DALVIK_OPCODES_FORMAT[ op_value ][0]( cm, buff )
    except KeyError :
      return InstructionInvalid( cm, buff )
  except :
      return Unresolved( buff )

def get_extented_instruction(cm, op_value, buff) :
  return DALVIK_OPCODES_EXTENDED_WIDTH[ op_value ][0]( cm, buff )

def get_optimize_instruction(cm, op_value, buff) :
  return DALVIK_OPCODES_OPTIMIZED[ op_value ][0]( cm, buff )

def get_instruction_payload(op_value, buff) :
  return DALVIK_OPCODES_PAYLOAD[ op_value ][0]( buff )

class LinearSweepAlgorithm :
    """
        This class is used to disassemble a method. The algorithm used by this class is linear sweep.
    """
    def get_instructions(self, cm, size, insn, idx) :
        """
            :param cm: a ClassManager object
            :type cm: :class:`ClassManager` object
            :param size: the total size of the buffer
            :type size: int
            :param insn: a raw buffer where are the instructions
            :type insn: string
            :param idx: a start address in the buffer
            :type idx: int

            :rtype: a generator of :class:`Instruction` objects
        """
        self.odex = cm.get_odex_format()

        max_idx = size * calcsize('=H')
        if max_idx > len(insn):
          max_idx = len(insn)

        # Get instructions
        while idx < max_idx:
          obj = None
          classic_instruction = True

          op_value = unpack( '=B', insn[idx] )[0]

          #print "%x %x" % (op_value, idx)

          #payload instructions or extented/optimized instructions
          if (op_value == 0x00 or op_value == 0xff) and ((idx + 2) < max_idx) :
            op_value = unpack( '=H', insn[idx:idx+2] )[0]

            # payload instructions ?
            if op_value in DALVIK_OPCODES_PAYLOAD :
              obj = get_instruction_payload( op_value, insn[idx:] )
              classic_instruction = False

            elif op_value in DALVIK_OPCODES_EXTENDED_WIDTH :
              obj = get_extented_instruction( cm, op_value, insn[idx:] )
              classic_instruction = False

            # optimized instructions ?
            elif self.odex and (op_value in DALVIK_OPCODES_OPTIMIZED) :
              obj = get_optimized_instruction( cm, op_value, insn[idx:] )
              classic_instruction = False
          
          # classical instructions
          if classic_instruction :
            op_value = unpack( '=B', insn[idx] )[0]
            obj = get_instruction( cm, op_value, insn[idx:], self.odex)

          # emit instruction
          yield obj
          idx = idx + obj.get_length()

class DCode:
    """
        This class represents the instructions of a method

        :param class_manager: the ClassManager
        :type class_manager: :class:`ClassManager` object
        :param size: the total size of the buffer
        :type size: int
        :param buff: a raw buffer where are the instructions
        :type buff: string
    """
    def __init__(self, class_manager, size, buff) :
        self.CM = class_manager
        self.insn = buff
        self.size = size

        self.notes = {}
        self.cached_instructions = []
        self.idx = 0

    def get_insn(self) :
      """
          Get the insn buffer

          :rtype: string
      """
      return self.insn

    def set_insn(self, insn) :
      """
          Set a new raw buffer to disassemble

          :param insn: the buffer
          :type insn: string
      """
      self.insn = insn
      self.size = len(self.insn)

    def set_idx(self, idx) :
        """
            Set the start address of the buffer

            :param idx: the index
            :type idx: int
        """
        self.idx = idx

    def set_instructions(self, instructions) :
      """
          Set the instructions

          :param instructions: the list of instructions
          :type instructions: a list of :class:`Instruction`
      """
      self.cached_instructions = instructions

    def get_instructions(self) :
        """
            Get the instructions

            :rtype: a generator of each :class:`Instruction` (or a cached list of instructions if you have setup instructions)
        """
        # it is possible to a cache for instructions (avoid a new disasm)
        if self.cached_instructions != [] :
          for i in self.cached_instructions :
            yield i
          return

        lsa = LinearSweepAlgorithm()
        for i in lsa.get_instructions( self.CM, self.size, self.insn, self.idx ) :
            yield i

    def reload(self) :
        pass

    def add_inote(self, msg, idx, off=None) :
      """
          Add a message to a specific instruction by using (default) the index of the address if specified

          :param msg: the message
          :type msg: string
          :param idx: index of the instruction (the position in the list of the instruction)
          :type idx: int
          :param off: address of the instruction
          :type off: int
      """
      if off != None :
        idx = self.off_to_pos(off)

      if idx not in self.notes :
        self.notes[ idx ] = []

      self.notes[ idx ].append(msg)

    def get_instruction(self, idx, off=None) :
        """
            Get a particular instruction by using (default) the index of the address if specified

            :param idx: index of the instruction (the position in the list of the instruction)
            :type idx: int
            :param off: address of the instruction
            :type off: int

            :rtype: an :class:`Instruction` object
        """
        if off != None :
          idx = self.off_to_pos(off)
        return [ i for i in self.get_instructions()][idx]

    def off_to_pos(self, off) :
        """
            Get the position of an instruction by using the address

            :param off: address of the instruction
            :type off: int

            :rtype: int
        """
        idx = 0
        nb = 0
        for i in self.get_instructions() :
            if idx == off :
                return nb
            nb += 1
            idx += i.get_length()
        return -1

    def get_ins_off(self, off):
        """
            Get a particular instruction by using the address

            :param off: address of the instruction
            :type off: int

            :rtype: an :class:`Instruction` object
        """
        idx = 0
        for i in self.get_instructions() :
            if idx == off :
                return i
            idx += i.get_length()
        return None

    def show(self) :
        """
            Display this object
        """
        nb = 0
        idx = 0
        for i in self.get_instructions() :
            print "%-8d(%08x)" % (nb, idx),
            i.show(nb)
            print

            idx += i.get_length()
            nb += 1

    def pretty_show(self, m_a) :
        """
            Display (with a pretty print) this object

            :param m_a: :class:`MethodAnalysis` object
        """
        bytecode.PrettyShow( m_a.basic_blocks.gets(), self.notes )
        bytecode.PrettyShowEx( m_a.exceptions.gets() )

    def get_raw(self) :
        """
            Return the raw buffer of this object

            :rtype: string
        """ 
        return ''.join(i.get_raw() for i in self.get_instructions())

    def get_length(self) :
      """
          Return the length of this object

          :rtype: int
      """ 
      return len(self.get_raw())

class TryItem :
    """
        This class represents the try_item format

        :param buff: a raw buffer where are the try_item format
        :type buff: string
        :param cm: the ClassManager
        :type cm: :class:`ClassManager` object
    """
    def __init__(self, buff, cm) :
        self.offset = buff.get_idx()

        self.__CM = cm

        self.start_addr = unpack("=I", buff.read(4))[0]
        self.insn_count = unpack("=H", buff.read(2))[0]
        self.handler_off = unpack("=H", buff.read(2))[0]

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

    def get_start_addr(self) :
        """
            Get the start address of the block of code covered by this entry. The address is a count of 16-bit code units to the start of the first covered instruction.

            :rtype: int
        """
        return self.start_addr

    def get_insn_count(self) :
        """
            Get the number of 16-bit code units covered by this entry

            :rtype: int
        """
        return self.insn_count

    def get_handler_off(self) :
        """
            Get the offset in bytes from the start of the associated :class:`EncodedCatchHandlerList` to the :class:`EncodedCatchHandler` for this entry.

            :rtype: int
        """
        return self.handler_off

    def get_raw(self) :
        return pack("=I", self.start_addr) + pack("=H", self.insn_count) + pack("=H", self.handler_off)

    def get_length(self) :
      return len(self.get_raw())

class DalvikCode :
    """
        This class represents the instructions of a method

        :param buff: a raw buffer where are the instructions
        :type buff: string
        :param cm: the ClassManager
        :type cm: :class:`ClassManager` object
    """
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.int_padding = ""
        off = buff.get_idx()
        while off % 4 != 0 :
            self.int_padding += '\00'
            off += 1
        buff.set_idx( off )

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
            self.padding = unpack("=H", buff.read(2))[0]

        self.tries = []
        self.handlers = None 
        if self.tries_size > 0 :
            for i in xrange(0, self.tries_size) :
                self.tries.append( TryItem( buff, self.__CM ) )

            self.handlers = EncodedCatchHandlerList( buff, self.__CM )

    def get_registers_size(self) :
        """
            Get the number of registers used by this code

            :rtype: int
        """
        return self.registers_size

    def get_ins_size(self) :
      """
          Get the number of words of incoming arguments to the method that this code is for

          :rtype: int
      """
      return self.ins_size

    def get_outs_size(self) :
      """
          Get the number of words of outgoing argument space required by this code for method invocation

          :rtype: int
      """
      return self.outs_size

    def get_tries_size(self) :
        """
            Get the number of :class:`TryItem` for this instance

            :rtype: int
        """
        return self.tries_size

    def get_debug_info_off(self) :
      """
          Get the offset from the start of the file to the debug info (line numbers + local variable info) sequence for this code, or 0 if there simply is no information
          
          :rtype: int
      """
      return self.debug_info_off

    def get_insns_size(self) :
      """
          Get the size of the instructions list, in 16-bit code units

          :rtype: int
      """
      return self.insns_size

    def get_handlers(self) :
        """
            Get the bytes representing a list of lists of catch types and associated handler addresses. 

            :rtype: :class:`EncodedCatchHandlerList`
        """
        return self.handlers

    def get_tries(self) :
        """
            Get the array indicating where in the code exceptions are caught and how to handle them

            :rtype: a list of :class:`TryItem` objects
        """
        return self.tries

    def get_debug(self) :
        """
            Return the associated debug object

            :rtype: :class:`DebugInfoItem`
        """
        return self.__CM.get_debug_off( self.debug_info_off )

    def get_bc(self) :
        """
            Return the associated code object

            :rtype: :class:`DCode`
        """
        return self.code

    def set_idx(self, idx) :
        self.code.set_idx(idx)

    def reload(self) :
        self.code.reload()

    def get_length(self) :
        return self.insns_size

    def _begin_show(self) :
      debug("registers_size: %d" % self.registers_size)
      debug("ins_size: %d" % self.ins_size)
      debug("outs_size: %d" % self.outs_size)
      debug("tries_size: %d" % self.tries_size)
      debug("debug_info_off: %d" % self.debug_info_off)
      debug("insns_size: %d" % self.insns_size)

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
        return [ i for i in self.handlers ]

    def get_raw(self) :
        code_raw = self.code.get_raw()
        self.insns_size = (len(code_raw) / 2) + (len(code_raw) % 2)


        buff = self.int_padding
        buff += pack("=H", self.registers_size) + \
                pack("=H", self.ins_size) + \
                pack("=H", self.outs_size) + \
                pack("=H", self.tries_size) + \
                pack("=I", self.debug_info_off) + \
                pack("=I", self.insns_size) + \
                code_raw

        if (self.insns_size % 2 == 1) :
            buff += pack("=H", self.padding)

        if self.tries_size > 0 :
            buff += ''.join(i.get_raw() for i in self.tries)
            buff += self.handlers.get_raw()

        return buff

    def add_inote(self, msg, idx, off=None) :
        """
            Add a message to a specific instruction by using (default) the index of the address if specified

            :param msg: the message
            :type msg: string
            :param idx: index of the instruction (the position in the list of the instruction)
            :type idx: int
            :param off: address of the instruction
            :type off: int
        """
        if self.code :
            return self.code.add_inote(msg, idx, off)

    def get_instruction(self, idx, off=None) :
        if self.code :
            return self.code.get_instruction(idx, off)

    def get_size(self) :
      length = len(self.int_padding)

      length += len( pack("=H", self.registers_size) + \
                     pack("=H", self.ins_size) + \
                     pack("=H", self.outs_size) + \
                     pack("=H", self.tries_size) + \
                     pack("=I", self.debug_info_off) + \
                     pack("=I", self.insns_size) )
      length += self.code.get_length()

      if (self.insns_size % 2 == 1) :
           length += len(pack("=H", self.padding))

      if self.tries_size > 0 :
        for i in self.tries :
          length += i.get_length()

        length += self.handlers.get_length()

      return length

    def get_off(self) :
        return self.__off

class CodeItem :
    def __init__(self, size, buff, cm) :
        self.__CM = cm

        self.offset = buff.get_idx()

        self.code = []
        self.__code_off = {}

        for i in xrange(0, size) :
            x = DalvikCode( buff, cm )
            self.code.append( x )
            self.__code_off[ x.get_off() ] = x

    def set_off(self, off) :
      self.offset = off

    def get_off(self) :
      return self.offset

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
        return ''.join(i.get_raw() for i in self.code)

    def get_length(self) :
      length = 0
      for i in self.code :
        length += i.get_size()
      return length

class MapItem :
    def __init__(self, buff, cm) :
        self.__CM = cm

        self.off = buff.get_idx()

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

    def get_off(self) :
      return self.off

    def get_offset(self) :
      return self.offset

    def get_type(self) :
        return self.type

    def get_size(self) :
      return self.size

    def next(self, buff, cm) :
        debug("%s @ 0x%x(%d) %d %x" % (TYPE_MAP_ITEM[ self.type ], buff.get_idx(), buff.get_idx(), self.size, self.offset))

        if TYPE_MAP_ITEM[ self.type ] == "TYPE_STRING_ID_ITEM" :
            self.item = [ StringIdItem( buff, cm ) for i in xrange(0, self.size) ]

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CODE_ITEM" :
            self.item = CodeItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_TYPE_ID_ITEM" :
            self.item = TypeHIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_PROTO_ID_ITEM" :
            self.item = ProtoHIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_FIELD_ID_ITEM" :
            self.item = FieldHIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_METHOD_ID_ITEM" :
            self.item = MethodHIdItem( self.size, buff, cm )

        elif TYPE_MAP_ITEM[ self.type ] == "TYPE_CLASS_DEF_ITEM" :
            self.item = ClassHDefItem( self.size, buff, cm )

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
            self.item = DebugInfoItemEmpty( buff, cm )

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
            self.item = DebugInfoItemEmpty( buff, cm )

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
                self.item.show()

    def pretty_show(self) :
        bytecode._Print( "\tMAP_TYPE_ITEM", TYPE_MAP_ITEM[ self.type ])

        if self.item != None :
            if isinstance( self.item, list ):
                for i in self.item :
                    if isinstance(i, ClassDataItem) :
                        i.pretty_show()
                    else :
                        i.show()
            else :
                self.item.show()
                
    def get_obj(self) :
        return self.item

    def get_raw(self) :
      if isinstance(self.item, list) :
        self.offset = self.item[0].get_off()
      else :
        self.offset = self.item.get_off()

      return pack("=H", self.type) + pack("=H", self.unused) + pack("=I", self.size) + pack("=I", self.offset)

    def get_length(self) :
        return calcsize( "=HHII" )

    def get_item(self) :
        return self.item

    def set_item(self, item) :
      self.item = item

class OffObj :
    def __init__(self, o) :
        self.off = o

class ClassManager :
    """
       This class is used to access to all elements (strings, type, proto ...) of the dex format
    """
    def __init__(self, vm) :
        self.vm = vm
        self.buff = vm

        self.decompiler_ob = None
        self.vmanalysis_ob = None
        self.gvmanalysis_ob = None

        self.__manage_item = {}
        self.__manage_item_off = []

        self.__strings_off = {}

        self.__obj_offset = {}
        self.__item_offset = {}

        self.__cached_type_list = {}
        self.__cached_proto = {}

        self.recode_ascii_string = CONF["RECODE_ASCII_STRING"]
        self.recode_ascii_string_meth = CONF["RECODE_ASCII_STRING_METH"]

        self.lazy_analysis = CONF["LAZY_ANALYSIS"]

        self.hook_strings = {}

        self.engine = []
        self.engine.append("python")

        if self.vm != None :
            self.odex_format = self.vm.get_format_type() == "ODEX"

    def get_odex_format(self) :
        return self.odex_format

    def get_obj_by_offset(self, offset) :
      return self.__obj_offset[ offset ]

    def get_item_by_offset(self, offset) :
      return self.__item_offset[ offset ]

    def get_string_by_offset(self, offset) :
      return self.__strings_off[ offset ]

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

    def add_type_item(self, type_item, c_item, item) :
        self.__manage_item[ type_item ] = item

        self.__obj_offset[ c_item.get_off() ] = c_item
        self.__item_offset[ c_item.get_offset() ] = item

        sdi = False
        if type_item == "TYPE_STRING_DATA_ITEM" :
            sdi = True

        if item != None :
            if isinstance(item, list) :
                for i in item :
                    goff = i.offset
                    self.__manage_item_off.append( goff )

                    self.__obj_offset[ i.get_off() ] = i

                    if sdi == True :
                      self.__strings_off[ goff ] = i
            else :
                self.__manage_item_off.append( c_item.get_offset() )

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

        try :
            off = self.__manage_item[ "TYPE_STRING_ID_ITEM" ][idx].get_string_data_off()
        except IndexError :
            bytecode.Warning( "unknown string item @ %d" % (idx) )
            return "AG:IS: invalid string"

        try :
            if self.recode_ascii_string :
                return self.recode_ascii_string_meth( self.__strings_off[off].get() )
            return self.__strings_off[off].get()
        except KeyError :
            bytecode.Warning( "unknown string item @ 0x%x(%d)" % (off,idx) )
            return "AG:IS: invalid string"

    def get_raw_string(self, idx) :
        try :
            off = self.__manage_item[ "TYPE_STRING_ID_ITEM" ][idx].get_string_data_off()
        except IndexError :
            bytecode.Warning( "unknown string item @ %d" % (idx) )
            return "AG:IS: invalid string"

        try :
            return self.__strings_off[off].get()
        except KeyError :
            bytecode.Warning( "unknown string item @ 0x%x(%d)" % (off,idx) )
            return "AG:IS: invalid string"

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
        if _type == -1 :
            return "AG:ITI: invalid type"
        return self.get_string( _type )

    def get_type_ref(self, idx) :
        return self.__manage_item[ "TYPE_TYPE_ID_ITEM" ].get( idx )

    def get_proto(self, idx) :
        try :
            proto = self.__cached_proto[ idx ]
        except KeyError :
            proto = self.__manage_item[ "TYPE_PROTO_ID_ITEM" ].get( idx )
            self.__cached_proto[ idx ] = proto

        return [ proto.get_parameters_off_value(), proto.get_return_type_idx_value() ]

    def get_field(self, idx) :
        field = self.__manage_item[ "TYPE_FIELD_ID_ITEM" ].get( idx )
        return [ field.get_class_name(), field.get_type(), field.get_name() ]

    def get_field_ref(self, idx) :
        return self.__manage_item[ "TYPE_FIELD_ID_ITEM" ].get( idx )

    def get_method(self, idx) :
        method = self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )
        return method.get_list()

    def get_method_ref(self, idx) :
        return self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( idx )

    def set_hook_class_name(self, class_def, value) :
        _type = self.__manage_item[ "TYPE_TYPE_ID_ITEM" ].get( class_def.get_class_idx() )
        self.set_hook_string( _type, value )

        self.vm._delete_python_export_class( class_def )

        class_def.reload()

        # FIXME
        self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].reload()

        for i in class_def.get_methods() :
          i.reload()

        for i in class_def.get_fields() :
          i.reload()

        self.vm._create_python_export_class( class_def )

    def set_hook_method_name(self, encoded_method, value) :
        method = self.__manage_item[ "TYPE_METHOD_ID_ITEM" ].get( encoded_method.get_method_idx() )
        self.set_hook_string( method.get_name_idx(), value )

        class_def = self.__manage_item[ "TYPE_CLASS_DEF_ITEM" ].get_class_idx( method.get_class_idx() )
        if class_def != None :
          try :
            name = "METHOD_" + bytecode.FormatNameToPython( encoded_method.get_name() )
            delattr( class_def, name )
          except AttributeError:
            name += "_" + bytecode.FormatDescriptorToPython( encoded_method.get_descriptor() )
            delattr( class_def, name )

          name = "METHOD_" + bytecode.FormatNameToPython( value )
          setattr( class_def, name, encoded_method )

        method.reload()

    def set_hook_field_name(self, encoded_field, value) :
        field = self.__manage_item[ "TYPE_FIELD_ID_ITEM" ].get( encoded_field.get_field_idx() )
        self.set_hook_string( field.get_name_idx(), value )

        class_def = self.__manage_item[ "TYPE_CLASS_DEF_ITEM" ].get_class_idx( field.get_class_idx() )
        if class_def != None :
          try :
            name = "FIELD_" + bytecode.FormatNameToPython( encoded_field.get_name() )
            delattr( class_def, name )
          except AttributeError:
            name += "_" + bytecode.FormatDescriptorToPython( encoded_field.get_descriptor() )
            delattr( class_def, name )

          name = "FIELD_" + bytecode.FormatNameToPython( value )
          setattr( class_def, name, encoded_field )

        field.reload()


    def set_hook_string(self, idx, value) :
        self.hook_strings[ idx ] = value

    def get_next_offset_item(self, idx) :
        for i in self.__manage_item_off :
            if i > idx :
                return i
        return idx

    def get_debug_off(self, off) :
        self.buff.set_idx( off )

        return DebugInfoItem( self.buff, self ) 

class MapList :
    """
       This class can parse the "map_list" of the dex format
    """
    def __init__(self, cm, off, buff) :
        self.CM = cm

        buff.set_idx( off )

        self.offset = off

        self.size = unpack("=I", buff.read( 4 ) )[0]

        self.map_item = []
        for i in xrange(0, self.size) :
            idx = buff.get_idx()

            mi = MapItem( buff, self.CM )
            self.map_item.append( mi )

            buff.set_idx( idx + mi.get_length() )

            c_item = mi.get_item()
            if c_item == None :
              mi.set_item( self )
              c_item = mi.get_item()

            self.CM.add_type_item( TYPE_MAP_ITEM[ mi.get_type() ], mi, c_item )

        for i in self.map_item :
            i.reload()

    def reload(self) :
      pass

    def get_off(self) :
      return self.offset

    def set_off(self, off) :
      self.offset = off

    def get_item_type(self, ttype) :
        """
            Get a particular item type

            :param ttype: a string which represents the desired type

            :rtype: None or the item object
        """
        for i in self.map_item :
            if TYPE_MAP_ITEM[ i.get_type() ] == ttype :
                return i.get_item()
        return None

    def show(self) :
        """
            Print the MapList object
        """
        bytecode._Print("MAP_LIST SIZE", self.size)
        for i in self.map_item :
            if i.item != self :
                i.show()

    def pretty_show(self) :
        """
            Print with a pretty display the MapList object
        """
        bytecode._Print("MAP_LIST SIZE", self.size)
        for i in self.map_item :
            if i.item != self :
                i.pretty_show()

    def get_obj(self) :
      return [ x.get_obj() for x in self.map_item ]

    def get_raw(self) :
        return pack("=I", self.size) + ''.join(x.get_raw() for x in self.map_item)

    def get_class_manager(self) :
        return self.CM

    def get_length(self) :
      return len(self.get_raw())

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

class DalvikVMFormat(bytecode._Bytecode) :
    """
        This class can parse a classes.dex file of an Android application (APK).

        :param buff: a string which represents the classes.dex file
        :param decompiler: associate a decompiler object to display the java source code
        :type buff: string
        :type decompiler: object

        :Example:
          DalvikVMFormat( open("classes.dex", "rb").read() )
    """
    def __init__(self, buff, decompiler=None) :
        super(DalvikVMFormat, self).__init__( buff )

        self.CM = ClassManager(self)
        self.CM.set_decompiler( decompiler )


        self._preload(buff)
        self._load(buff)

    def _preload(self, buff) :
        pass

    def _load(self, buff) :
        self.__header = HeaderItem( 0, self, ClassManager(None) )

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
        self.__cached_methods_idx = None

    def get_classes_def_item(self) :
        """
            This function returns the class def item

            :rtype: :class:`ClassDefItem` object
        """
        return self.classes

    def get_methods_id_item(self) :
        """
            This function returns the method id item

            :rtype: :class:`MethodIdItem` object
        """
        return self.methods

    def get_fields_id_item(self) :
        """
            This function returns the field id item

            :rtype: :class:`FieldIdItem` object
        """
        return self.fields

    def get_codes_item(self) :
        """
            This function returns the code item

            :rtype: :class:`CodeItem` object
        """
        return self.codes

    def get_string_data_item(self) :
        """
            This function returns the string data item

            :rtype: :class:`StringDataItem` object
        """
        return self.strings

    def get_debug_info_item(self) :
        """
            This function returns the debug info item

            :rtype: :class:`DebugInfoItem` object
        """
        return self.debug

    def get_header_item(self) :
        """
            This function returns the header item

            :rtype: :class:`HeaderItem` object
        """
        return self.header

    def get_class_manager(self) :
        """
            This function returns a ClassManager object which allow you to get
            access to all index references (strings, methods, fields, ....)

            :rtype: :class:`ClassManager` object
        """
        return self.CM

    def show(self) :
        """
          Show the all information in the object
        """
        self.map_list.show()

    def pretty_show(self) :
        """
          Show (but pretty !) the all information in the object
        """
        self.map_list.pretty_show()

    def save(self) :
      """
          Return the dex (with the modifications) into raw format (fix checksums)

          :rtype: string
      """
      l = []
      h = {}
      s = {}
      h_r = {}

      idx = 0
      for i in self.map_list.get_obj() :
        length = 0

        if isinstance(i, list) :
          for j in i :
            if isinstance(j, AnnotationsDirectoryItem) :
              if idx % 4 != 0 :
                idx = idx + (4 - (idx % 4))

            l.append( j )

            c_length = j.get_length()
            h[ j ] = idx + length
            h_r[ idx + length ] = j
            s[ idx + length ] = c_length

            length += c_length

            #debug("SAVE" + str(j) + " @ 0x%x" % (idx+length))

          debug("SAVE " + str(i[0]) + " @ 0x%x" % idx)

        else :
          if isinstance(i, MapList) :
            if idx % 4 != 0 :
              idx = idx + (4 - (idx % 4))

          l.append( i )
          h[ i ] = idx
          h_r[ idx ] = i

          length = i.get_length()

          s[ idx ] = length

          debug("SAVE " + str(i) + " @ 0x%x" % idx)

        idx += length

      self.header.file_size = idx

      last_idx = 0
      for i in l :
        idx = h[ i ]
        i.set_off( h[ i ] )

#        print i, hex(h[ i ])

        last_idx = idx + s[ idx ]

      last_idx = 0
      buff = ""
      for i in l :
        idx = h[ i ]

        if idx != last_idx :
          debug( "Adjust alignment @%x with 00 %x" % (idx, idx - last_idx) )
          buff += "\x00" * (idx - last_idx)

        buff += i.get_raw()
        last_idx = idx + s[ idx ]

      debug( "GLOBAL SIZE %d" % len(buff))

      return self.fix_checksums(buff)

    def fix_checksums(self, buff) :
      """
          Fix a dex format buffer by setting all checksums

          :rtype: string
      """
      import zlib, hashlib
      signature = hashlib.sha1(buff[32:]).digest()

      buff = buff[:12] + signature + buff[32:]
      checksum = zlib.adler32(buff[12:])
      buff = buff[:8] + pack("=i", checksum) + buff[12:]


      debug( "NEW SIGNATURE %s" % repr(signature) )
      debug( "NEW CHECKSUM %x" % checksum )

      return buff

    def get_cm_field(self, idx) :
        """
          Get a specific field by using an index

          :param idx: index of the field
          :type idx: int
        """
        return self.CM.get_field(idx)

    def get_cm_method(self, idx) :
        """
          Get a specific method by using an index

          :param idx: index of the method
          :type idx: int
        """
        return self.CM.get_method(idx)

    def get_cm_string(self, idx) :
        """
          Get a specific string by using an index

          :param idx: index of the string
          :type idx: int
        """
        return self.CM.get_raw_string( idx )

    def get_cm_type(self, idx) :
        """
          Get a specific type by using an index

          :param idx: index of the type
          :type idx: int
        """
        return self.CM.get_type( idx )

    def get_classes_names(self) :
        """
            Return the names of classes

            :rtype: a list of string
        """
        if self.classes_names == None :
            self.classes_names = [ i.get_name() for i in self.classes.class_def ]
        return self.classes_names

    def get_classes(self) :
        """
          Return all classes

          :rtype: a list of :class:`ClassDefItem` objects
        """
        return self.classes.class_def

    def get_method(self, name) :
        """
            Return a list all methods which corresponds to the regexp

            :param name: the name of the method (a python regexp)

            :rtype: a list with all :class:`EncodedMethod` objects
        """
        prog = re.compile(name)
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                if prog.match( j.get_name() ) :
                    l.append( j )
        return l

    def get_field(self, name) :
        """
            Return a list all fields which corresponds to the regexp

            :param name: the name of the field (a python regexp)

            :rtype: a list with all :class:`EncodedField` objects
        """
        prog = re.compile(name)
        l = []
        for i in self.classes.class_def :
            for j in i.get_fields() :
                if prog.match( j.get_name() ) :
                    l.append( j )
        return l

    def get_all_fields(self) :
        """
            Return a list of field items

            :rtype: a list of :class:`FieldIdItem` objects
        """
        try :
            return self.fields.gets()
        except AttributeError :
            return []

    def get_fields(self) :
        """
          Return all field objects

          :rtype: a list of :class:`EncodedField` objects
        """
        l = []
        for i in self.classes.class_def :
            for j in i.get_fields() :
                l.append( j )
        return l


    def get_methods(self) :
        """
          Return all method objects

          :rtype: a list of :class:`EncodedMethod` objects
        """
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                l.append( j )
        return l

    def get_len_methods(self) :
        """
          Return the number of methods

          :rtype: int
        """
        return len( self.get_methods() )

    def get_method_by_idx(self, idx) :
        """
          Return a specific method by using an index
          :param idx: the index of the method
          :type idx: int

          :rtype: None or an :class:`EncodedMethod` object
        """
        if self.__cached_methods_idx == None :
          self.__cached_methods_idx = {}
          for i in self.classes.class_def :
            for j in i.get_methods() :
              self.__cached_methods_idx[ j.get_method_idx() ] = j

        try :
          return self.__cached_methods_idx[ idx ]
        except KeyError :
          return None

    def get_method_descriptor(self, class_name, method_name, descriptor) :
        """
            Return the specific method

            :param class_name: the class name of the method
            :type class_name: string
            :param method_name: the name of the method
            :type method_name: string
            :param descriptor: the descriptor of the method
            :type descriptor: string

            :rtype: None or a :class:`EncodedMethod` object
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
            Return all methods of a specific class

            :param class_name: the class name
            :type class_name: string

            :rtype: a list with :class:`EncodedMethod` objects
        """
        l = []
        for i in self.classes.class_def :
            for j in i.get_methods() :
                if class_name == j.get_class_name() :
                    l.append( j )

        return l

    def get_fields_class(self, class_name) :
        """
            Return all fields of a specific class

            :param class_name: the class name
            :type class_name: string

            :rtype: a list with :class:`EncodedField` objects
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

            :param class_name: the class name of the field
            :type class_name: string
            :param field_name: the name of the field
            :type field_name: string
            :param descriptor: the descriptor of the field
            :type descriptor: string

            :rtype: None or a :class:`EncodedField` object
        """
        for i in self.classes.class_def :
            if class_name == i.get_name() :
                for j in i.get_fields() :
                    if field_name == j.get_name() and descriptor == j.get_descriptor() :
                        return j
        return None

    def get_strings(self) :
        """
            Return all strings

            :rtype: a list with all strings used in the format (types, names ...)
        """
        return [i.get() for i in self.strings]

    def get_regex_strings(self, regular_expressions) :
        """
            Return all target strings matched the regex

            :param regular_expressions: the python regex
            :type regular_expressions: string

            :rtype: a list of strings matching the regex expression
        """
        str_list = []
        if regular_expressions.count is None :
            return None
        for i in self.get_strings() :
            if re.match(regular_expressions, i) :
                str_list.append(i)
        return str_list


    def get_format_type(self) :
        """
            Return the type

            :rtype: a string
        """
        return "DEX"

    def create_xref(self, python_export=True) :
        """
            Create XREF for this object

            :param python_export (boolean): export xref in each method
        """
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
                            name = bytecode.FormatClassToPython( xref_meth.get_class_name() ) + "__" + \
                            bytecode.FormatNameToPython( xref_meth.get_name() ) + "__" + \
                            bytecode.FormatDescriptorToPython( xref_meth.get_descriptor() )

                            if python_export == True :
                                setattr( method.XREFfrom, name, xref_meth )
                            method.XREFfrom.add( xref_meth, xref.edges[ gvm.nodes[ key ] ] )

                    for i in gvm.G.successors( gvm.nodes[ key ].id ) :
                        xref = gvm.nodes_id[ i ]
                        xref_meth = self.get_method_descriptor( xref.class_name, xref.method_name, xref.descriptor)
                        if xref_meth != None :
                            name = bytecode.FormatClassToPython( xref_meth.get_class_name() ) + "__" + \
                            bytecode.FormatNameToPython( xref_meth.get_name() ) + "__" + \
                            bytecode.FormatDescriptorToPython( xref_meth.get_descriptor() )
                            
                            if python_export == True :
                                setattr( method.XREFto, name, xref_meth )
                            method.XREFto.add( xref_meth, gvm.nodes[ key ].edges[ xref ] )

    def create_dref(self, python_export=True) :
        """
            Create DREF for this object

            :param python_export (boolean): export dref in each field
        """
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
                            name = bytecode.FormatClassToPython( dref_meth.get_class_name() ) + "__" + \
                            bytecode.FormatNameToPython( dref_meth.get_name() ) + "__" + \
                            bytecode.FormatDescriptorToPython( dref_meth.get_descriptor() )
                            
                            if python_export == True :
                                setattr( field.DREFr, name, dref_meth )

                            try :
                                access["R"][ dref_meth ].append( idx )
                            except KeyError :
                                access["R"][ dref_meth ] = []
                                access["R"][ dref_meth ].append( idx )

                        else :
                            dref_meth = self.get_method_by_idx( m_idx )
                            name = bytecode.FormatClassToPython( dref_meth.get_class_name() ) + "__" + \
                            bytecode.FormatNameToPython( dref_meth.get_name() ) + "__" + \
                            bytecode.FormatDescriptorToPython( dref_meth.get_descriptor() )
                            
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

    def create_python_export(self) :
        """
            Export classes/methods/fields' names in the python namespace
        """
        for _class in self.get_classes() :
          self._create_python_export_class(_class)

    def _delete_python_export_class(self, _class) :
      self._create_python_export_class( _class, True)

    def _create_python_export_class(self, _class, delete=False) :
        if _class != None :
            ### Class
            name = "CLASS_" + bytecode.FormatClassToPython( _class.get_name() )
            if delete :
              delattr( self, name )
              return
            else :
              setattr( self, name, _class )

            ### Methods
            m = {}
            for method in _class.get_methods() :
                if method.get_name() not in m :
                    m[ method.get_name() ] = []
                m[ method.get_name() ].append( method )

            for i in m :
                if len(m[i]) == 1 :
                    j = m[i][0]
                    name = "METHOD_" + bytecode.FormatNameToPython( j.get_name() )
                    setattr( _class, name, j )
                else :
                    for j in m[i] :
                        name = "METHOD_" + bytecode.FormatNameToPython( j.get_name() ) + "_" + bytecode.FormatDescriptorToPython( j.get_descriptor() )
                        setattr( _class, name, j )

            ### Fields
            f = {}
            for field in _class.get_fields() :
                if field.get_name() not in f :
                    f[ field.get_name() ] = []
                f[ field.get_name() ].append( field )

            for i in f :
                if len(f[i]) == 1 :
                    j = f[i][0]
                    name = "FIELD_" + bytecode.FormatNameToPython( j.get_name() )
                    setattr( _class, name, j )
                else :
                    for j in f[i] :
                        name = "FIELD_" + bytecode.FormatNameToPython( j.get_name() ) + "_" + bytecode.FormatDescriptorToPython( j.get_descriptor() )
                        setattr( _class, name, j )


    def dotbuff(self, ins, idx) :
        return dot_buff(ins, idx)

    def get_BRANCH_DVM_OPCODES(self) :
        return BRANCH_DVM_OPCODES

    def get_determineNext(self) :
        return determineNext

    def get_determineException(self) :
        return determineException

    def get_DVM_TOSTRING(self):
        return DVM_TOSTRING()

    def set_decompiler(self, decompiler):
        self.CM.set_decompiler(decompiler)

    def set_vmanalysis(self, vmanalysis):
        self.CM.set_vmanalysis(vmanalysis)

    def set_gvmanalysis(self, gvmanalysis):
        self.CM.set_gvmanalysis(gvmanalysis)

    def disassemble(self, offset, size):
      """
        Disassembles a given offset in the DEX file

        :param dex: the filename of the android dex file
        :type filename: string
        :param offset: offset to disassemble in the file (from the beginning of the file)
        :type offset: int
        :param size:
        :type size:
      """
      for i in DCode(self.CM, size, self.get_buff()[offset:offset + size]).get_instructions():
        yield i

    def get_classes_hierarchy(self):
        ids = {}
        present = {}
        r_ids = {}
        to_add = {}
        els = []

        for current_class in self.get_classes():
            s_name = current_class.get_superclassname()[1:-1]
            c_name = current_class.get_name()[1:-1]

            if s_name not in ids:
                ids[s_name] = len(ids) + 1
                r_ids[ids[s_name]] = s_name

            if c_name not in ids:
                ids[c_name] = len(ids) + 1

            els.append([ids[c_name], ids[s_name], c_name])
            present[ids[c_name]] = True

        for i in els:
            if i[1] not in present:
                to_add[i[1]] = r_ids[i[1]]

        for i in to_add:
            els.append([i, 0, to_add[i]])

        treeMap = {}
        Root = bytecode.Node(0, "Root")
        treeMap[Root.id] = Root
        for element in els:
         nodeId, parentId, title = element
         if not nodeId in treeMap:
             treeMap[nodeId] = bytecode.Node(nodeId, title)
         else:
             treeMap[nodeId].id = nodeId
             treeMap[nodeId].title = title

         if not parentId in treeMap:
             treeMap[parentId] = bytecode.Node(0, '')
         treeMap[parentId].children.append(treeMap[nodeId])

        def print_map(node, l, lvl=0):
         for n in node.children:
             if lvl == 0:
                l.append("%s" % (n.title))
             else:
                l.append("%s %s" % ('\t' * lvl, n.title))
             if len(n.children) > 0:
                 print_map(n, l, lvl + 1)

        l = []
        print_map(Root, l)
        return l


class OdexHeaderItem:
    """
        This class can parse the odex header

        :param buff: a Buff object string which represents the odex dependencies
    """
    def __init__(self, buff):
        buff.set_idx(8)

        self.dex_offset = unpack("=I", buff.read(4))[0]
        self.dex_length = unpack("=I", buff.read(4))[0]
        self.deps_offset = unpack("=I", buff.read(4))[0]
        self.deps_length = unpack("=I", buff.read(4))[0]
        self.aux_offset = unpack("=I", buff.read(4))[0]
        self.aux_length = unpack("=I", buff.read(4))[0]
        self.flags = unpack("=I", buff.read(4))[0]
        self.padding = unpack("=I", buff.read(4))[0]

    def show(self):
        print "dex_offset:%x dex_length:%x deps_offset:%x deps_length:%x aux_offset:%x aux_length:%x flags:%x" % (self.dex_offset,
                                                                                                                  self.dex_length,
                                                                                                                  self.deps_offset,
                                                                                                                  self.deps_length,
                                                                                                                  self.aux_offset,
                                                                                                                  self.aux_length,
                                                                                                                  self.flags)


class OdexDependencies:
    """
        This class can parse the odex dependencies

        :param buff: a Buff object string which represents the odex dependencies
    """
    def __init__(self, buff):
        self.modification_time = unpack("=I", buff.read(4))[0]
        self.crc = unpack("=I", buff.read(4))[0]
        self.dalvik_build = unpack("=I", buff.read(4))[0]
        self.dependency_count = unpack("=I", buff.read(4))[0]
        self.dependencies = []
        self.dependency_checksums = []

        for i in range(0, self.dependency_count):
            string_length = unpack("=I", buff.read(4))[0]
            name_dependency = buff.read(string_length)[:-1]
            self.dependencies.append(name_dependency)
            self.dependency_checksums.append(buff.read(20))

    def get_dependencies(self):
        """
            Return the list of dependencies

            :rtype: a list of strings
        """
        return self.dependencies


class DalvikOdexVMFormat(DalvikVMFormat):
    """
        This class can parse an odex file

        :param buff: a string which represents the odex file
        :param decompiler: associate a decompiler object to display the java source code
        :type buff: string
        :type decompiler: object

        :Example:
          DalvikOdexVMFormat( open("classes.odex", "rb").read() )
    """
    def _preload(self, buff):
        magic = buff[:8]
        if magic == ODEX_FILE_MAGIC_35 or magic == ODEX_FILE_MAGIC_36:
            self.odex_header = OdexHeaderItem(self)

            self.set_idx(self.odex_header.deps_offset)
            self.dependencies = OdexDependencies(self)

            self.set_idx(self.odex_header.dex_offset)
            self.set_buff(self.read(self.odex_header.dex_length))
            self.set_idx(0)

    def get_dependencies(self):
        """
            Return the odex dependencies object

            :rtype: an OdexDependencies object
        """
        return self.dependencies

    def get_format_type(self):
        """
            Return the type

            :rtype: a string
        """
        return "ODEX"


def auto(filename, raw=None):
  """
      :param filename:
      :param raw:
      :type filename:
      :type raw:
  """
  data_raw = raw
  if raw == None:
    data_raw = open(filename, "rb").read()
    ret_type = is_android_raw(data_raw[:10])
    if ret_type == "DEX":
      return DalvikVMFormat(data_raw)
    elif ret_type == "ODEX":
      return DalvikOdexVMFormat(data_raw)

  return None
