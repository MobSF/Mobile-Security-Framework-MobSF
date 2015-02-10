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

from struct import unpack, pack

from androconf import Color, warning, error, CONF, disable_colors, enable_colors, remove_colors, save_colors

def disable_print_colors() :
  colors = save_colors()
  remove_colors()
  return colors 

def enable_print_colors(colors) :
  enable_colors(colors)

# Handle exit message
def Exit( msg ):
    warning("Error : " + msg)
    raise("oops")

def Warning( msg ):
    warning(msg)

def _PrintBanner() :
    print_fct = CONF["PRINT_FCT"]
    print_fct("*" * 75 + "\n")

def _PrintSubBanner(title=None) :
  print_fct = CONF["PRINT_FCT"]
  if title == None :
    print_fct("#" * 20 + "\n")
  else :
    print_fct("#" * 10 + " " + title + "\n")

def _PrintNote(note, tab=0) :
  print_fct = CONF["PRINT_FCT"]
  note_color = CONF["COLORS"]["NOTE"]
  normal_color = CONF["COLORS"]["NORMAL"]
  print_fct("\t" * tab + "%s# %s%s" % (note_color, note, normal_color) + "\n")

# Print arg into a correct format
def _Print(name, arg) :
    buff = name + " "

    if type(arg).__name__ == 'int' :
        buff += "0x%x" % arg
    elif type(arg).__name__ == 'long' :
        buff += "0x%x" % arg
    elif type(arg).__name__ == 'str' :
        buff += "%s" % arg
    elif isinstance(arg, SV) :
        buff += "0x%x" % arg.get_value()
    elif isinstance(arg, SVs) :
        buff += arg.get_value().__str__()

    print buff

def PrettyShowEx( exceptions ) :
    if len(exceptions) > 0 :
        CONF["PRINT_FCT"]("Exceptions:\n")
        for i in exceptions : 
          CONF["PRINT_FCT"]("\t%s%s%s\n" % (CONF["COLORS"]["EXCEPTION"], i.show_buff(), CONF["COLORS"]["NORMAL"]))

def _PrintXRef(tag, items) :
  print_fct = CONF["PRINT_FCT"]
  for i in items :
    print_fct("%s: %s %s %s %s\n" % (tag, i[0].get_class_name(), i[0].get_name(), i[0].get_descriptor(), ' '.join("%x" % j.get_idx() for j in i[1])))

def _PrintDRef(tag, items) :
  print_fct = CONF["PRINT_FCT"]
  for i in items :
    print_fct( "%s: %s %s %s %s\n" % (tag, i[0].get_class_name(), i[0].get_name(), i[0].get_descriptor(), ' '.join("%x" % j for j in i[1]) ) )

def _PrintDefault(msg) :
  print_fct = CONF["PRINT_FCT"]
  print_fct(msg)

def PrettyShow( basic_blocks, notes={} ) :
    idx = 0
    nb = 0

    offset_color = CONF["COLORS"]["OFFSET"]
    offset_addr_color = CONF["COLORS"]["OFFSET_ADDR"]
    instruction_name_color = CONF["COLORS"]["INSTRUCTION_NAME"]
    branch_false_color = CONF["COLORS"]["BRANCH_FALSE"]
    branch_true_color = CONF["COLORS"]["BRANCH_TRUE"]
    branch_color = CONF["COLORS"]["BRANCH"]
    exception_color = CONF["COLORS"]["EXCEPTION"]
    bb_color = CONF["COLORS"]["BB"]
    normal_color = CONF["COLORS"]["NORMAL"]
    print_fct = CONF["PRINT_FCT"]

    for i in basic_blocks :
        print_fct("%s%s%s : \n" % (bb_color, i.name, normal_color))
        instructions = i.get_instructions()
        for ins in instructions :
        #for ins in i.ins :

            if nb in notes :
              for note in notes[nb] :
                _PrintNote(note, 1)

            print_fct("\t%s%-3d%s(%s%08x%s) " % (offset_color, nb, normal_color, offset_addr_color, idx, normal_color))
            print_fct("%s%-20s%s %s" %(instruction_name_color, ins.get_name(), normal_color, ins.get_output(idx)))

            op_value = ins.get_op_value()
            if ins == instructions[-1] and i.childs != [] :
                print_fct(" ")

                # packed/sparse-switch
                if (op_value == 0x2b or op_value == 0x2c) and len(i.childs) > 1 :
                      values = i.get_special_ins(idx).get_values()
                      print_fct("%s[ D:%s%s " % (branch_false_color, i.childs[0][2].name, branch_color))
                      print_fct(' '.join("%d:%s" % (values[j], i.childs[j+1][2].name) for j in range(0, len(i.childs)-1) ) + " ]%s" % normal_color)
                else :
                    if len(i.childs) == 2 :
                        print_fct("%s[ %s%s " % (branch_false_color, i.childs[0][2].name, branch_true_color))
                        print_fct(' '.join("%s" % c[2].name for c in i.childs[1:]) + " ]%s" % normal_color)
                    else :
                        print_fct("%s[ " % branch_color + ' '.join("%s" % c[2].name for c in i.childs) + " ]%s" % normal_color)

            idx += ins.get_length()
            nb += 1

            print_fct("\n")

        if i.get_exception_analysis() != None :
          print_fct("\t%s%s%s\n" % (exception_color, i.exception_analysis.show_buff(), normal_color))

        print_fct("\n")

def method2dot( mx ) :
    """
        Export analysis method to dot format 

        @param mx : MethodAnalysis object

        @rtype : dot format buffer
    """

    vm = mx.get_vm()
    buff = ""
    for i in mx.basic_blocks.get() :
        val = "green"
        if len(i.childs) > 1 :
            val = "red"
        elif len(i.childs) == 1 :
            val = "blue"

        for j in i.childs :
            buff += "\"%s\" -> \"%s\" [color=\"%s\"];\n" % ( i.get_name(), j[-1].get_name(), val )
            if val == "red" :
                val = "green"

        idx = i.start
        label = ""
        for ins in i.get_instructions() :
            label += "%x %s\l" % (idx, vm.dotbuff(ins, idx))
            idx += ins.get_length()

        buff +=  "\"%s\" [color=\"lightgray\", label=\"%s\"]\n" % (i.get_name(), label)
    return buff

def method2format( output, _format="png", mx = None, raw = False ) :
    """
        Export method to a specific file format

        @param output : output filename
        @param _format : format type (png, jpg ...) (default : png)
        @param mx : specify the MethodAnalysis object
        @param raw : use directly a dot raw buffer
    """
    try :
        import pydot
    except ImportError :
        error("module pydot not found")

    buff = "digraph code {\n"
    buff += "graph [bgcolor=white];\n"
    buff += "node [color=lightgray, style=filled shape=box fontname=\"Courier\" fontsize=\"8\"];\n"

    if raw == False :
        buff += method2dot( mx )
    else :
        buff += raw

    buff += "}"

    d = pydot.graph_from_dot_data( buff )
    if d :
        getattr(d, "write_" + _format)( output )
      
def method2png( output, mx, raw = False ) :
    """
        Export method to a png file format

        :param output: output filename
        :type output: string
        :param mx: specify the MethodAnalysis object
        :type mx: :class:`MethodAnalysis` object
        :param raw: use directly a dot raw buffer
        :type raw: string
    """
    buff = raw
    if raw == False :
        buff = method2dot( mx )

    method2format( output, "png", mx, buff )

def method2jpg( output, mx, raw = False ) :
    """
        Export method to a jpg file format

        :param output: output filename
        :type output: string
        :param mx: specify the MethodAnalysis object
        :type mx: :class:`MethodAnalysis` object
        :param raw: use directly a dot raw buffer (optional)
        :type raw: string
    """
    buff = raw
    if raw == False :
        buff = method2dot( mx )

    method2format( output, "jpg", mx, buff )

class SV :
    def __init__(self, size, buff) :
        self.__size = size
        self.__value = unpack(self.__size, buff)[0]

    def _get(self) :
        return pack(self.__size, self.__value)

    def __str__(self) :
        return "0x%x" % self.__value

    def __int__(self) :
        return self.__value

    def get_value_buff(self) :
        return self._get()

    def get_value(self) :
        return self.__value

    def set_value(self, attr) :
        self.__value = attr

class SVs :
    def __init__(self, size, ntuple, buff) :
        self.__size = size

        self.__value = ntuple._make( unpack( self.__size, buff ) )

    def _get(self) :
        l = []
        for i in self.__value._fields :
            l.append( getattr( self.__value, i ) )
        return pack( self.__size, *l)

    def _export(self) :
        return [ x for x in self.__value._fields ]

    def get_value_buff(self) :
        return self._get()

    def get_value(self) :
        return self.__value

    def set_value(self, attr) :
        self.__value = self.__value._replace( **attr )

    def __str__(self) :
        return self.__value.__str__()

def object_to_str(obj) :
    if isinstance(obj, str) :
        return obj
    elif isinstance(obj, bool) :
        return ""
    elif isinstance(obj, int) :
        return pack("<L", obj)
    elif obj == None :
        return ""
    else :
        #print type(obj), obj
        return obj.get_raw()

class MethodBC(object) :
    def show(self, value) :
        getattr(self, "show_" + value)()


class BuffHandle:
    def __init__(self, buff):
        self.__buff = buff
        self.__idx = 0

    def size(self):
        return len(self.__buff)

    def set_idx(self, idx):
        self.__idx = idx

    def get_idx(self):
        return self.__idx

    def readNullString(self, size):
        data = self.read(size)
        return data

    def read_b(self, size) :
        return self.__buff[ self.__idx : self.__idx + size ]

    def read_at(self, offset, size):
        return self.__buff[ offset : offset + size ]

    def read(self, size) :
        if isinstance(size, SV) :
            size = size.value

        buff = self.__buff[ self.__idx : self.__idx + size ]
        self.__idx += size

        return buff

    def end(self) :
        return self.__idx == len(self.__buff)

class Buff :
    def __init__(self, offset, buff) :
        self.offset = offset
        self.buff = buff

        self.size = len(buff)

class _Bytecode(object) :
    def __init__(self, buff) :
        try :
            import psyco
            psyco.full()
        except ImportError :
            pass

        self.__buff = buff
        self.__idx = 0

    def read(self, size) :
        if isinstance(size, SV) :
            size = size.value

        buff = self.__buff[ self.__idx : self.__idx + size ]
        self.__idx += size

        return buff

    def readat(self, off) :
        if isinstance(off, SV) :
            off = off.value

        return self.__buff[ off : ]

    def read_b(self, size) :
        return self.__buff[ self.__idx : self.__idx + size ]

    def set_idx(self, idx) :
        self.__idx = idx

    def get_idx(self) :
        return self.__idx

    def add_idx(self, idx) :
        self.__idx += idx

    def register(self, type_register, fct) :
        self.__registers[ type_register ].append( fct )

    def get_buff(self) :
        return self.__buff

    def length_buff(self) :
        return len( self.__buff )

    def set_buff(self, buff) :
        self.__buff = buff

    def save(self, filename) :
        fd = open(filename, "w")
        buff = self._save()
        fd.write( buff )
        fd.close()

def FormatClassToJava(input) :
    """
       Transoform a typical xml format class into java format

       :param input: the input class name
       :rtype: string
    """
    return "L" + input.replace(".", "/") + ";"

def FormatClassToPython(input) :
    i = input[:-1]
    i = i.replace("/", "_")
    i = i.replace("$", "_")

    return i

def FormatNameToPython(input) :
    i = input.replace("<", "")
    i = i.replace(">", "")
    i = i.replace("$", "_")

    return i

def FormatDescriptorToPython(input) :
    i = input.replace("/", "_")
    i = i.replace(";", "")
    i = i.replace("[", "")
    i = i.replace("(", "")
    i = i.replace(")", "")
    i = i.replace(" ", "")
    i = i.replace("$", "")

    return i

class Node:
 def __init__(self, n, s):
     self.id = n
     self.title = s
     self.children = []