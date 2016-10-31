# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re, random, cPickle, collections

from androguard.core.androconf import error, warning, debug, is_ascii_problem,\
    load_api_specific_resource_module
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes.api_permissions import DVM_PERMISSIONS_BY_PERMISSION, DVM_PERMISSIONS_BY_ELEMENT

class ContextField(object):
    def __init__(self, mode):
        self.mode = mode
        self.details = []

    def set_details(self, details):
        for i in details:
            self.details.append( i )

class ContextMethod(object):
    def __init__(self):
        self.details = []

    def set_details(self, details):
        for i in details:
            self.details.append( i )

class ExternalFM(object):
    def __init__(self, class_name, name, descriptor):
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor

    def get_class_name(self):
        return self.class_name

    def get_name(self):
        return self.name

    def get_descriptor(self):
        return self.descriptor

class ToString(object):
    def __init__(self, tab):
        self.__tab = tab
        self.__re_tab = {}

        for i in self.__tab:
            self.__re_tab[i] = []
            for j in self.__tab[i]:
                self.__re_tab[i].append( re.compile( j ) )

        self.__string = ""

    def push(self, name):
        for i in self.__tab:
            for j in self.__re_tab[i]:
                if j.match(name) != None:
                    if len(self.__string) > 0:
                        if i == 'O' and self.__string[-1] == 'O':
                            continue
                    self.__string += i

    def get_string(self):
        return self.__string

class BreakBlock(object):
    def __init__(self, _vm, idx):
        self._vm = _vm
        self._start = idx
        self._end = self._start

        self._ins = []

        self._ops = []

        self._fields = {}
        self._methods = {}


    def get_ops(self):
        return self._ops

    def get_fields(self):
        return self._fields

    def get_methods(self):
        return self._methods

    def push(self, ins):
        self._ins.append(ins)
        self._end += ins.get_length()

    def get_start(self):
        return self._start

    def get_end(self):
        return self._end

    def show(self):
        for i in self._ins:
            print "\t\t",
            i.show(0)

DVM_FIELDS_ACCESS = {
      "iget" : "R",
      "iget-wide" : "R",
      "iget-object" : "R",
      "iget-boolean" : "R",
      "iget-byte" : "R",
      "iget-char" : "R",
      "iget-short" : "R",

      "iput" : "W",
      "iput-wide" : "W",
      "iput-object" : "W",
      "iput-boolean" : "W",
      "iput-byte" : "W",
      "iput-char" : "W",
      "iput-short" : "W",

      "sget" : "R",
      "sget-wide" : "R",
      "sget-object" : "R",
      "sget-boolean" : "R",
      "sget-byte" : "R",
      "sget-char" : "R",
      "sget-short" : "R",

      "sput" : "W",
      "sput-wide" : "W",
      "sput-object" : "W",
      "sput-boolean" : "W",
      "sput-byte" : "W",
      "sput-char" : "W",
      "sput-short" : "W",
   }


class DVMBasicBlock(object):
    """
        A simple basic block of a dalvik method
    """
    def __init__(self, start, vm, method, context):
        self.__vm = vm
        self.method = method
        self.context = context

        self.last_length = 0
        self.nb_instructions = 0

        self.fathers = []
        self.childs = []

        self.start = start
        self.end = self.start

        self.special_ins = {}

        self.name = "%s-BB@0x%x" % (self.method.get_name(), self.start)
        self.exception_analysis = None

        self.tainted_variables = self.context.get_tainted_variables()
        self.tainted_packages = self.context.get_tainted_packages()

        self.notes = []

    def get_notes(self):
        return self.notes

    def set_notes(self, value):
        self.notes = [value]

    def add_note(self, note):
        self.notes.append(note)

    def clear_notes(self):
        self.notes = []

    def get_instructions(self):
      """
        Get all instructions from a basic block.

        :rtype: Return all instructions in the current basic block
      """
      tmp_ins = []
      idx = 0
      for i in self.method.get_instructions():
        if idx >= self.start and idx < self.end:
          tmp_ins.append(i)

        idx += i.get_length()
      return tmp_ins

    def get_nb_instructions(self):
        return self.nb_instructions

    def get_method(self):
        return self.method

    def get_name(self):
        return "%s-BB@0x%x" % (self.method.get_name(), self.start)

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_last(self):
        return self.get_instructions()[-1]

    def get_next(self):
        """
            Get next basic blocks

            :rtype: a list of the next basic blocks
        """
        return self.childs

    def get_prev(self):
        """
            Get previous basic blocks

            :rtype: a list of the previous basic blocks
        """
        return self.fathers

    def set_fathers(self, f):
        self.fathers.append(f)

    def get_last_length(self):
      return self.last_length

    def set_childs(self, values):
        #print self, self.start, self.end, values
        if values == []:
            next_block = self.context.get_basic_block( self.end + 1 )
            if next_block != None:
                self.childs.append( ( self.end - self.get_last_length(), self.end, next_block ) )
        else:
            for i in values:
                if i != -1:
                    next_block = self.context.get_basic_block( i )
                    if next_block != None:
                        self.childs.append( ( self.end - self.get_last_length(), i, next_block) )

        for c in self.childs:
            if c[2] != None:
                c[2].set_fathers( ( c[1], c[0], self ) )

    def push(self, i):
      try:
            self.nb_instructions += 1
            idx = self.end
            self.last_length = i.get_length()
            self.end += self.last_length

            op_value = i.get_op_value()

            # field access
            if (op_value >= 0x52 and op_value <= 0x6d):
                desc = self.__vm.get_cm_field(i.get_ref_kind())
                if self.tainted_variables != None:
                    self.tainted_variables.push_info(TAINTED_FIELD, desc, DVM_FIELDS_ACCESS[i.get_name()][0], idx, self.method)

            # invoke
            elif (op_value >= 0x6e and op_value <= 0x72) or (op_value >= 0x74 and op_value <= 0x78):
                idx_meth = i.get_ref_kind()
                method_info = self.__vm.get_cm_method(idx_meth)
                if self.tainted_packages != None:
                    self.tainted_packages.push_info(method_info[0], TAINTED_PACKAGE_CALL, idx, self.method, idx_meth)

            # new_instance
            elif op_value == 0x22:
                idx_type = i.get_ref_kind()
                type_info = self.__vm.get_cm_type(idx_type)
                if self.tainted_packages != None:
                    self.tainted_packages.push_info(type_info, TAINTED_PACKAGE_CREATE, idx, self.method, None)

            # const-string
            elif (op_value >= 0x1a and op_value <= 0x1b):
                string_name = self.__vm.get_cm_string(i.get_ref_kind())
                if self.tainted_variables != None:
                    self.tainted_variables.push_info(TAINTED_STRING, string_name, "R", idx, self.method)

            elif op_value == 0x26 or (op_value >= 0x2b and op_value <= 0x2c):
                code = self.method.get_code().get_bc()
                self.special_ins[idx] = code.get_ins_off(idx + i.get_ref_off() * 2)
      except:
        pass

    def get_special_ins(self, idx):
        """
            Return the associated instruction to a specific instruction (for example a packed/sparse switch)

            :param idx: the index of the instruction

            :rtype: None or an Instruction
        """
        try:
            return self.special_ins[idx]
        except:
            return None

    def get_exception_analysis(self):
        return self.exception_analysis

    def set_exception_analysis(self, exception_analysis):
        self.exception_analysis = exception_analysis

TAINTED_LOCAL_VARIABLE = 0
TAINTED_FIELD = 1
TAINTED_STRING = 2

class PathVar(object):
  def __init__(self, access, idx, dst_idx, info_obj):
    self.access_flag = access
    self.idx = idx
    self.dst_idx = dst_idx
    self.info_obj = info_obj

  def get_var_info(self):
    return self.info_obj.get_info()

  def get_access_flag(self):
    return self.access_flag

  def get_src(self, cm):
    method = cm.get_method_ref( self.idx )
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_dst(self, cm):
    method = cm.get_method_ref( self.dst_idx )
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_idx(self):
    return self.idx

class TaintedVariable(object):
    def __init__(self, var, _type):
        self.var = var
        self.type = _type

        self.paths = {}
        self.__cache = []

    def get_type(self):
        return self.type

    def get_info(self):
        if self.type == TAINTED_FIELD:
            return [ self.var[0], self.var[2], self.var[1] ]
        return self.var

    def push(self, access, idx, ref):
        m_idx = ref.get_method_idx()

        if m_idx not in self.paths:
          self.paths[ m_idx ] = []

        self.paths[ m_idx ].append( (access, idx) )

    def get_paths_access(self, mode):
        for i in self.paths:
          for j in self.paths[ i ]:
            for k, v in self.paths[ i ][ j ]:
              if k in mode:
                yield i, j, k, v

    def get_paths(self):
        if self.__cache != []:
            return self.__cache

        for i in self.paths:
          for j in self.paths[ i ]:
              self.__cache.append( [j, i] )
              #yield j, i
        return self.__cache

    def get_paths_length(self):
        return len(self.paths)

    def show_paths(self, vm):
        show_PathVariable( vm, self.get_paths() )

class TaintedVariables(object):
    def __init__(self, _vm):
        self.__vm = _vm
        self.__vars = {
           TAINTED_LOCAL_VARIABLE : {},
           TAINTED_FIELD : {},
           TAINTED_STRING : {},
        }

        self.__cache_field_by_method = {}
        self.__cache_string_by_method = {}

        self.AOSP_PERMISSIONS_MODULE = load_api_specific_resource_module("aosp_permissions", self.__vm.get_api_version())
        self.API_PERMISSION_MAPPINGS_MODULE = load_api_specific_resource_module("api_permission_mappings", self.__vm.get_api_version())

    # functions to get particulars elements
    def get_string(self, s):
        try:
            return self.__vars[ TAINTED_STRING ][ s ]
        except KeyError:
            return None

    def get_field(self, class_name, name, descriptor):
        key = class_name + descriptor + name

        try:
            return self.__vars[ TAINTED_FIELD ] [ key ]
        except KeyError:
            return None

    def toPathVariable(self, obj):
      z = []
      for i in obj.get_paths():
        access, idx = i[0]
        m_idx = i[1]

        z.append( PathVar(access, idx, m_idx, obj ) )
      return z

    # permission functions
    def get_permissions_method(self, method):
        permissions = set()

        for f, f1 in self.get_fields():
            data = "%s-%s-%s" % (f.var[0], f.var[2], f.var[1])
            if data in self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_FIELDS"].keys():
                for path in f.get_paths():
                    #access, idx = path[0]
                    m_idx = path[1]
                    if m_idx == method.get_idx():
                        permissions.update(self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_FIELDS"][data])

        return permissions

    def get_permissions(self, permissions_needed):
        """
            @param permissions_needed : a list of restricted permissions to get ([] returns all permissions)

            @rtype : a dictionnary of permissions' paths
        """
        permissions = {}

        pn = set(permissions_needed)
        if permissions_needed == []:
            pn = set(self.AOSP_PERMISSIONS_MODULE["AOSP_PERMISSIONS"].keys())

        for f, _ in self.get_fields():
            data = "%s-%s-%s" % (f.var[0], f.var[2], f.var[1])
            if data in self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_FIELDS"].keys():
                perm_intersection = pn.intersection(self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_FIELDS"][data])
                for p in perm_intersection:
                    try:
                        permissions[p].extend(self.toPathVariable(f))
                    except KeyError:
                        permissions[p] = []
                        permissions[p].extend(self.toPathVariable(f))

        return permissions

    # global functions
    def get_strings(self):
        for i in self.__vars[ TAINTED_STRING ]:
            yield self.__vars[ TAINTED_STRING ][ i ], i

    def get_fields(self):
        for i in self.__vars[ TAINTED_FIELD ]:
            yield self.__vars[ TAINTED_FIELD ][ i ], i

    # specifics functions
    def get_strings_by_method(self, method):
        z = {}

        try:
            for i in self.__cache_string_by_method[ method.get_method_idx() ]:
                z[ i ] = []
                for j in i.get_paths():
                    if method.get_method_idx() == j[1]:
                        z[i].append( j[0] )

            return z
        except:
            return z


    def get_fields_by_method(self, method):
        z = {}

        try:
            for i in self.__cache_field_by_method[ method.get_method_idx() ]:
                z[ i ] = []
                for j in i.get_paths():
                    if method.get_method_idx() == j[1]:
                        z[i].append( j[0] )
            return z
        except:
            return z

    def add(self, var, _type, _method=None):
        if _type == TAINTED_FIELD:
            key = var[0] + var[1] + var[2]
            if key not in self.__vars[ TAINTED_FIELD ]:
                self.__vars[ TAINTED_FIELD ][ key ] = TaintedVariable( var, _type )
        elif _type == TAINTED_STRING:
            if var not in self.__vars[ TAINTED_STRING ]:
                self.__vars[ TAINTED_STRING ][ var ] = TaintedVariable( var, _type )
        elif _type == TAINTED_LOCAL_VARIABLE:
            if _method not in self.__vars[ TAINTED_LOCAL_VARIABLE ]:
                self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ] = {}

            if var not in self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ]:
                self.__vars[ TAINTED_LOCAL_VARIABLE ][ _method ][ var ] = TaintedVariable( var, _type )

    def push_info(self, _type, var, access, idx, ref):
        if _type == TAINTED_FIELD:
            self.add( var, _type )
            key = var[0] + var[1] + var[2]
            self.__vars[ _type ][ key ].push( access, idx, ref )

            method_idx = ref.get_method_idx()
            if method_idx not in self.__cache_field_by_method:
                self.__cache_field_by_method[ method_idx ] = set()

            self.__cache_field_by_method[ method_idx ].add( self.__vars[ TAINTED_FIELD ][ key ] )


        elif _type == TAINTED_STRING:
            self.add( var, _type )
            self.__vars[ _type ][ var ].push( access, idx, ref )

            method_idx = ref.get_method_idx()

            if method_idx not in self.__cache_string_by_method:
                self.__cache_string_by_method[ method_idx ] = set()

            self.__cache_string_by_method[ method_idx ].add( self.__vars[ TAINTED_STRING ][ var ] )

TAINTED_PACKAGE_CREATE = 0
TAINTED_PACKAGE_CALL = 1

TAINTED_PACKAGE = {
   TAINTED_PACKAGE_CREATE : "C",
   TAINTED_PACKAGE_CALL : "M"
}
def show_Path(vm, path):
  cm = vm.get_class_manager()

  if isinstance(path, PathVar):
    dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
    info_var = path.get_var_info()
    print "%s %s (0x%x) ---> %s->%s%s" % (path.get_access_flag(),
                                          info_var,
                                          path.get_idx(),
                                          dst_class_name,
                                          dst_method_name,
                                          dst_descriptor)
  else:
    if path.get_access_flag() == TAINTED_PACKAGE_CALL:
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

      print "%d %s->%s%s (0x%x) ---> %s->%s%s" % (path.get_access_flag(),
                                                  src_class_name,
                                                  src_method_name,
                                                  src_descriptor,
                                                  path.get_idx(),
                                                  dst_class_name,
                                                  dst_method_name,
                                                  dst_descriptor)
    else:
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      print "%d %s->%s%s (0x%x)" % (path.get_access_flag(),
                                    src_class_name,
                                    src_method_name,
                                    src_descriptor,
                                    path.get_idx())

def get_Path(vm, path):
  x = {}
  cm = vm.get_class_manager()

  if isinstance(path, PathVar):
    dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
    info_var = path.get_var_info()
    x["src"] = "%s" % info_var
    x["dst"] = "%s %s %s" % (dst_class_name, dst_method_name, dst_descriptor)
    x["idx"] = path.get_idx()

  else:
    if path.get_access_flag() == TAINTED_PACKAGE_CALL:
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

      x["src"] = "%s %s %s" % (src_class_name, src_method_name, src_descriptor)
      x["dst"] = "%s %s %s" % (dst_class_name, dst_method_name, dst_descriptor)
    else:
      src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
      x["src"] = "%s %s %s" % (src_class_name, src_method_name, src_descriptor)

    x["idx"] = path.get_idx()

  return x


def show_Paths(vm, paths):
    """
        Show paths of packages
        :param vm: the object which represents the dex file
        :param paths: a list of :class:`PathP` objects
    """
    for path in paths:
        show_Path( vm, path )


def get_Paths(vm, paths):
    """
        Return paths of packages
        :param vm: the object which represents the dex file
        :param paths: a list of :class:`PathP` objects
    """
    full_paths = []
    for path in paths:
        full_paths.append(get_Path( vm, path ))
    return full_paths


def show_PathVariable(vm, paths):
    for path in paths:
      access, idx = path[0]
      m_idx = path[1]
      method = vm.get_cm_method(m_idx)
      print "%s %x %s->%s %s" % (access, idx, method[0], method[1], method[2][0] + method[2][1])


class PathP(object):
  def __init__(self, access, idx, src_idx, dst_idx):
    self.access_flag = access
    self.idx = idx
    self.src_idx = src_idx
    self.dst_idx = dst_idx

  def get_access_flag(self):
    return self.access_flag

  def get_dst(self, cm):
    method = cm.get_method_ref(self.dst_idx)
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_src(self, cm):
    method = cm.get_method_ref(self.src_idx)
    return method.get_class_name(), method.get_name(), method.get_descriptor()

  def get_idx(self):
    return self.idx

  def get_src_idx(self):
    return self.src_idx

  def get_dst_idx(self):
    return self.dst_idx


class TaintedPackage(object):
    def __init__(self, vm, name):
        self.vm = vm
        self.name = name
        self.paths = {TAINTED_PACKAGE_CREATE : [], TAINTED_PACKAGE_CALL : []}

    def get_name(self):
        return self.name

    def gets(self):
        return self.paths

    def push(self, access, idx, src_idx, dst_idx):
        p = PathP( access, idx, src_idx, dst_idx )
        self.paths[ access ].append( p )
        return p

    def get_objects_paths(self):
        return self.paths[ TAINTED_PACKAGE_CREATE ]

    def search_method(self, name, descriptor):
        """
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method

            @rtype : a list of called paths
        """
        l = []
        m_name = re.compile(name)
        m_descriptor = re.compile(descriptor)

        for path in self.paths[ TAINTED_PACKAGE_CALL ]:
            _, dst_name, dst_descriptor = path.get_dst(self.vm.get_class_manager())

            if m_name.match( dst_name ) != None and m_descriptor.match( dst_descriptor ) != None:
                l.append( path )
        return l

    def get_method(self, name, descriptor):
        l = []
        for path in self.paths[ TAINTED_PACKAGE_CALL ]:
            if path.get_name() == name and path.get_descriptor() == descriptor:
                l.append( path )
        return l

    def get_paths(self):
        for i in self.paths:
            for j in self.paths[ i ]:
                yield j

    def get_paths_length(self):
        x = 0
        for i in self.paths:
            x += len(self.paths[ i ])
        return x

    def get_methods(self):
        return [path for path in self.paths[TAINTED_PACKAGE_CALL]]

    def get_new(self):
        return [path for path in self.paths[TAINTED_PACKAGE_CREATE]]

    def show(self):
        cm = self.vm.get_class_manager()
        print self.get_name()
        for _type in self.paths:
            print "\t -->", _type
            if _type == TAINTED_PACKAGE_CALL:
                for path in self.paths[_type]:
                    print "\t\t => %s <-- %x in %s" % (path.get_dst(cm), path.get_idx(), path.get_src(cm))
            else:
                for path in self.paths[_type]:
                    print "\t\t => %x in %s" % (path.get_idx(), path.get_src(cm))

def show_Permissions(dx):
    """
        Show where permissions are used in a specific application
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    p = dx.get_permissions( [] )

    for i in p:
        print i, ":"
        for j in p[i]:
            show_Path( dx.get_vm(), j )

def show_DynCode(dx):
    """
        Show where dynamic code is used
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    paths = []
    paths.extend(dx.get_tainted_packages().search_methods("Ldalvik/system/BaseDexClassLoader;",
                                                "<init>",
                                                "."))

    paths.extend(dx.get_tainted_packages().search_methods("Ldalvik/system/PathClassLoader;",
                                                "<init>",
                                                "."))

    paths.extend(dx.get_tainted_packages().search_methods("Ldalvik/system/DexClassLoader;",
                                                "<init>",
                                                "."))

    paths.extend(dx.get_tainted_packages().search_methods("Ldalvik/system/DexFile;",
                                                "<init>",
                                                "."))

    paths.extend(dx.get_tainted_packages().search_methods("Ldalvik/system/DexFile;",
                                                "loadDex",
                                                "."))
    show_Paths( dx.get_vm(), paths )


def show_NativeMethods(dx):
    """
        Show the native methods
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    print get_NativeMethods(dx)


def show_ReflectionCode(dx):
    """
        Show the reflection code
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
    """
    paths = dx.get_tainted_packages().search_methods("Ljava/lang/reflect/Method;", ".", ".")
    show_Paths(dx.get_vm(), paths)


def get_NativeMethods(dx):
    """
        Return the native methods
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: [tuple]
    """
    d = dx.get_vm()
    native_methods = []
    for i in d.get_methods():
        if i.get_access_flags() & 0x100:
            native_methods.append(
                (i.get_class_name(), i.get_name(), i.get_descriptor()))
    return native_methods


def get_ReflectionCode(dx):
    """
        Return the reflection code
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: [dict]
    """
    paths = dx.get_tainted_packages().search_methods(
        "Ljava/lang/reflect/Method;", ".", ".")
    return get_Paths(dx.get_vm(), paths)


def is_crypto_code(dx):
    """
        Crypto code is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    if dx.get_tainted_packages().search_methods("Ljavax/crypto/.",
                                                ".",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ljava/security/spec/.",
                                                ".",
                                                "."):
        return True

    return False


def is_dyn_code(dx):
    """
        Dalvik Dynamic code loading is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    if dx.get_tainted_packages().search_methods("Ldalvik/system/BaseDexClassLoader;",
                                                "<init>",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ldalvik/system/PathClassLoader;",
                                                "<init>",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ldalvik/system/DexClassLoader;",
                                                "<init>",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ldalvik/system/DexFile;",
                                                "<init>",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ldalvik/system/DexFile;",
                                                "loadDex",
                                                "."):
        return True

    return False


def is_reflection_code(dx):
    """
        Reflection is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    if dx.get_tainted_packages().search_methods("Ljava/lang/reflect/Method;",
                                                ".",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ljava/lang/reflect/Field;",
                                                ".",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ljava/lang/Class;",
                                                "forName",
                                                "."):
        return True

    return False


def is_native_code(dx):
    """
        Native code is present ?
        :param dx : the analysis virtual machine
        :type dx: a :class:`VMAnalysis` object
        :rtype: boolean
    """
    if dx.get_tainted_packages().search_methods("Ljava/lang/System;",
                                                "load.",
                                                "."):
        return True

    if dx.get_tainted_packages().search_methods("Ljava/lang/Runtime;",
                                                "load.",
                                                "."):
        return True

    return False


class TaintedPackages(object):
    def __init__(self, _vm):
        self.__vm = _vm
        self.__packages = {}
        self.__methods = {}

        self.AOSP_PERMISSIONS_MODULE = load_api_specific_resource_module("aosp_permissions", self.__vm.get_api_version())
        self.API_PERMISSION_MAPPINGS_MODULE = load_api_specific_resource_module("api_permission_mappings", self.__vm.get_api_version())

    def _add_pkg(self, name):
        if name not in self.__packages:
            self.__packages[ name ] = TaintedPackage( self.__vm, name )

    #self.context.get_tainted_packages().push_info( method_info[0], TAINTED_PACKAGE_CALL, idx, self, self.method, method_info[1], method_info[2][0] + method_info[2][1] )
    def push_info(self, class_name, access, idx, method, idx_method):
        self._add_pkg( class_name )
        p = self.__packages[ class_name ].push( access, idx, method.get_method_idx(), idx_method )

        try:
            self.__methods[ method ][ class_name ].append( p )
        except:
            try:
                self.__methods[ method ][ class_name ] = []
            except:
                self.__methods[ method ] = {}
                self.__methods[ method ][ class_name ] = []

            self.__methods[ method ][ class_name ].append( p )

    def get_packages_by_method(self, method):
        try:
            return self.__methods[method]
        except KeyError:
            return {}

    def get_package(self, name):
        return self.__packages[name]

    def get_packages_by_bb(self, bb):
        """
            :rtype: return a list of packaged used in a basic block
        """
        l = []
        for i in self.__packages:
            paths = self.__packages[i].gets()
            for j in paths:
                for k in paths[j]:
                    if k.get_bb() == bb:
                        l.append( (i, k.get_access_flag(), k.get_idx(), k.get_method()) )

        return l

    def get_packages(self):
        for i in self.__packages:
            yield self.__packages[i], i

    def get_internal_packages_from_package(self, package):
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())

                if src_class_name == package and dst_class_name in classes:
                    l.append(j)
        return l

    def get_internal_packages(self):
        """
            :rtype: return a list of the internal packages called in the application
        """
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                  dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())
                  if dst_class_name in classes and m.get_name() in classes:
                    l.append(j)
        return l

    def get_internal_new_packages(self):
        """
            :rtype: return a list of the internal packages created in the application
        """
        classes = self.__vm.get_classes_names()
        l = {}
        for m, _ in self.get_packages():
            paths = m.get_new()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                if src_class_name in classes and m.get_name() in classes:
                    if j.get_access_flag() == TAINTED_PACKAGE_CREATE:
                        try:
                            l[m.get_name()].append(j)
                        except:
                            l[m.get_name()] = []
                            l[m.get_name()].append(j)
        return l

    def get_external_packages(self):
        """
            :rtype: return a list of the external packages called in the application
        """
        classes = self.__vm.get_classes_names()
        l = []
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                src_class_name, _, _ = j.get_src(self.__vm.get_class_manager())
                dst_class_name, _, _ = j.get_dst(self.__vm.get_class_manager())
                if src_class_name in classes and dst_class_name not in classes:
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                        l.append(j)
        return l

    def search_packages(self, package_name):
        """
            :param package_name: a regexp for the name of the package

            :rtype: a list of called packages' paths
        """
        ex = re.compile(package_name)

        l = []
        for m, _ in self.get_packages():
            if ex.search(m.get_name()) != None:
                l.extend(m.get_methods())
        return l

    def search_unique_packages(self, package_name):
        """
            :param package_name: a regexp for the name of the package
        """
        ex = re.compile( package_name )

        l = []
        d = {}
        for m, _ in self.get_packages():
            if ex.match( m.get_info() ) != None:
                for path in m.get_methods():
                    try:
                        d[ path.get_class_name() + path.get_name() + path.get_descriptor() ] += 1
                    except KeyError:
                        d[ path.get_class_name() + path.get_name() + path.get_descriptor() ] = 0
                        l.append( [ path.get_class_name(), path.get_name(), path.get_descriptor() ] )
        return l, d

    def search_methods(self, class_name, name, descriptor, re_expr=True):
        """
            @param class_name : a regexp for the class name of the method (the package)
            @param name : a regexp for the name of the method
            @param descriptor : a regexp for the descriptor of the method

            @rtype : a list of called methods' paths
        """
        l = []
        if re_expr == True:
            ex = re.compile( class_name )

            for m, _ in self.get_packages():
                if ex.search( m.get_name() ) != None:
                    l.extend( m.search_method( name, descriptor ) )

        return l

    def search_objects(self, class_name):
        """
            @param class_name : a regexp for the class name

            @rtype : a list of created objects' paths
        """
        ex = re.compile( class_name )
        l = []

        for m, _ in self.get_packages():
            if ex.search( m.get_name() ) != None:
                l.extend( m.get_objects_paths() )

        return l

    def search_crypto_packages(self):
        """
            @rtype : a list of called crypto packages
        """
        return self.search_packages( "Ljavax/crypto/" )

    def search_telephony_packages(self):
        """
            @rtype : a list of called telephony packages
        """
        return self.search_packages( "Landroid/telephony/" )

    def search_net_packages(self):
        """
            @rtype : a list of called net packages
        """
        return self.search_packages( "Landroid/net/" )

    def get_method(self, class_name, name, descriptor):
        try:
            return self.__packages[ class_name ].get_method( name, descriptor )
        except KeyError:
            return []

    def get_permissions_method(self, method):
        permissions = set()
        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                if j.get_method() == method:
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                        dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.__vm.get_class_manager() )
                        data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
                        if data in self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_METHODS"].keys():
                            permissions.update(self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_METHODS"][data])

        return permissions

    def get_permissions(self, permissions_needed):
        """
            @param permissions_needed : a list of restricted permissions to get ([] returns all permissions)
            @rtype : a dictionnary of permissions' paths
        """
        permissions = {}

        pn = set(permissions_needed)
        if permissions_needed == []:
            pn = set(self.AOSP_PERMISSIONS_MODULE["AOSP_PERMISSIONS"].keys())

        classes = self.__vm.get_classes_names()

        for m, _ in self.get_packages():
            paths = m.get_methods()
            for j in paths:
                src_class_name, src_method_name, src_descriptor = j.get_src( self.__vm.get_class_manager() )
                dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.__vm.get_class_manager() )
                if (src_class_name in classes) and (dst_class_name not in classes):
                    if j.get_access_flag() == TAINTED_PACKAGE_CALL:
                        data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
                        if data in self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_METHODS"].keys():
                            perm_intersection = pn.intersection(self.API_PERMISSION_MAPPINGS_MODULE["AOSP_PERMISSIONS_BY_METHODS"][data])
                            for p in perm_intersection:
                                try:
                                    permissions[p].append(j)
                                except KeyError:
                                    permissions[p] = []
                                    permissions[p].append(j)

        return permissions

class Enum(object):
  def __init__(self, names):
    self.names = names
    for value, name in enumerate(self.names):
      setattr(self, name.upper(), value)

  def tuples(self):
    return tuple(enumerate(self.names))

TAG_ANDROID = Enum([ 'ANDROID', 'TELEPHONY', 'SMS', 'SMSMESSAGE', 'ACCESSIBILITYSERVICE', 'ACCOUNTS',
    'ANIMATION', 'APP', 'BLUETOOTH', 'CONTENT', 'DATABASE', 'DEBUG', 'DRM', 'GESTURE',
    'GRAPHICS', 'HARDWARE', 'INPUTMETHODSERVICE', 'LOCATION', 'MEDIA', 'MTP',
    'NET', 'NFC', 'OPENGL', 'OS', 'PREFERENCE', 'PROVIDER', 'RENDERSCRIPT',
    'SAX', 'SECURITY', 'SERVICE', 'SPEECH', 'SUPPORT', 'TEST', 'TEXT', 'UTIL',
    'VIEW', 'WEBKIT', 'WIDGET', 'DALVIK_BYTECODE', 'DALVIK_SYSTEM', 'JAVA_REFLECTION'])

TAG_REVERSE_ANDROID = dict((i[0], i[1]) for i in TAG_ANDROID.tuples())

TAGS_ANDROID = { TAG_ANDROID.ANDROID :                  [ 0, "Landroid" ],
                 TAG_ANDROID.TELEPHONY :                [ 0, "Landroid/telephony"],
                 TAG_ANDROID.SMS :                      [ 0, "Landroid/telephony/SmsManager"],
                 TAG_ANDROID.SMSMESSAGE :               [ 0, "Landroid/telephony/SmsMessage"],
                 TAG_ANDROID.DEBUG :                    [ 0, "Landroid/os/Debug"],
                 TAG_ANDROID.ACCESSIBILITYSERVICE :     [ 0, "Landroid/accessibilityservice" ],
                 TAG_ANDROID.ACCOUNTS :                 [ 0, "Landroid/accounts" ],
                 TAG_ANDROID.ANIMATION :                [ 0, "Landroid/animation" ],
                 TAG_ANDROID.APP :                      [ 0, "Landroid/app" ],
                 TAG_ANDROID.BLUETOOTH :                [ 0, "Landroid/bluetooth" ],
                 TAG_ANDROID.CONTENT :                  [ 0, "Landroid/content" ],
                 TAG_ANDROID.DATABASE :                 [ 0, "Landroid/database" ],
                 TAG_ANDROID.DRM :                      [ 0, "Landroid/drm" ],
                 TAG_ANDROID.GESTURE :                  [ 0, "Landroid/gesture" ],
                 TAG_ANDROID.GRAPHICS :                 [ 0, "Landroid/graphics" ],
                 TAG_ANDROID.HARDWARE :                 [ 0, "Landroid/hardware" ],
                 TAG_ANDROID.INPUTMETHODSERVICE :       [ 0, "Landroid/inputmethodservice" ],
                 TAG_ANDROID.LOCATION :                 [ 0, "Landroid/location" ],
                 TAG_ANDROID.MEDIA :                    [ 0, "Landroid/media" ],
                 TAG_ANDROID.MTP :                      [ 0, "Landroid/mtp" ],
                 TAG_ANDROID.NET :                      [ 0, "Landroid/net" ],
                 TAG_ANDROID.NFC :                      [ 0, "Landroid/nfc" ],
                 TAG_ANDROID.OPENGL :                   [ 0, "Landroid/opengl" ],
                 TAG_ANDROID.OS :                       [ 0, "Landroid/os" ],
                 TAG_ANDROID.PREFERENCE :               [ 0, "Landroid/preference" ],
                 TAG_ANDROID.PROVIDER :                 [ 0, "Landroid/provider" ],
                 TAG_ANDROID.RENDERSCRIPT :             [ 0, "Landroid/renderscript" ],
                 TAG_ANDROID.SAX :                      [ 0, "Landroid/sax" ],
                 TAG_ANDROID.SECURITY :                 [ 0, "Landroid/security" ],
                 TAG_ANDROID.SERVICE :                  [ 0, "Landroid/service" ],
                 TAG_ANDROID.SPEECH :                   [ 0, "Landroid/speech" ],
                 TAG_ANDROID.SUPPORT :                  [ 0, "Landroid/support" ],
                 TAG_ANDROID.TEST :                     [ 0, "Landroid/test" ],
                 TAG_ANDROID.TEXT :                     [ 0, "Landroid/text" ],
                 TAG_ANDROID.UTIL :                     [ 0, "Landroid/util" ],
                 TAG_ANDROID.VIEW :                     [ 0, "Landroid/view" ],
                 TAG_ANDROID.WEBKIT :                   [ 0, "Landroid/webkit" ],
                 TAG_ANDROID.WIDGET :                   [ 0, "Landroid/widget" ],
                 TAG_ANDROID.DALVIK_BYTECODE :          [ 0, "Ldalvik/bytecode" ],
                 TAG_ANDROID.DALVIK_SYSTEM :            [ 0, "Ldalvik/system" ],

                 TAG_ANDROID.JAVA_REFLECTION :          [ 0, "Ljava/lang/reflect"],
}

class Tags(object):
  """
      Handle specific tags

      :param patterns:
      :params reverse:
  """
  def __init__(self, patterns=TAGS_ANDROID, reverse=TAG_REVERSE_ANDROID):
    self.tags = set()

    self.patterns = patterns
    self.reverse = TAG_REVERSE_ANDROID

    for i in self.patterns:
      self.patterns[i][1] = re.compile(self.patterns[i][1])

  def emit(self, method):
    for i in self.patterns:
      if self.patterns[i][0] == 0:
        if self.patterns[i][1].search( method.get_class() ) != None:
          self.tags.add( i )

  def emit_by_classname(self, classname):
    for i in self.patterns:
      if self.patterns[i][0] == 0:
        if self.patterns[i][1].search( classname ) != None:
          self.tags.add( i )

  def get_list(self):
    return [ self.reverse[ i ] for i in self.tags ]

  def __contains__(self, key):
    return key in self.tags

  def __str__(self):
    return str([ self.reverse[ i ] for i in self.tags ])


  def empty(self):
    return self.tags == set()


class BasicBlocks(object):
    """
        This class represents all basic blocks of a method
    """
    def __init__(self, _vm, tv):
        self.__vm = _vm
        self.tainted = tv

        self.bb = []

    def push(self, bb):
        self.bb.append(bb)

    def pop(self, idx):
        return self.bb.pop(idx)

    def get_basic_block(self, idx):
        for i in self.bb:
            if idx >= i.get_start() and idx < i.get_end():
                return i
        return None

    def get_tainted_integers(self):
        try:
          return self.tainted.get_tainted_integers()
        except:
          return None

    def get_tainted_packages(self):
        try:
          return self.tainted.get_tainted_packages()
        except:
          return None

    def get_tainted_variables(self):
        try:
          return self.tainted.get_tainted_variables()
        except:
          return None

    def get(self):
        """
            :rtype: return each basic block (:class:`DVMBasicBlock` object)
        """
        for i in self.bb:
            yield i

    def gets(self):
        """
            :rtype: a list of basic blocks (:class:`DVMBasicBlock` objects)
        """
        return self.bb

    def get_basic_block_pos(self, idx):
        return self.bb[idx]


class ExceptionAnalysis(object):
    def __init__(self, exception, bb):
        self.start = exception[0]
        self.end = exception[1]

        self.exceptions = exception[2:]

        for i in self.exceptions:
            i.append(bb.get_basic_block(i[1]))

    def show_buff(self):
        buff = "%x:%x\n" % (self.start, self.end)

        for i in self.exceptions:
            if i[2] == None:
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2])
            else:
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2].get_name())

        return buff[:-1]

    def get(self):
        d = {"start": self.start, "end": self.end, "list": []}

        for i in self.exceptions:
            d["list"].append({"name": i[0], "idx": i[1], "bb": i[2].get_name()})

        return d


class Exceptions(object):
    def __init__(self, _vm):
        self.__vm = _vm
        self.exceptions = []

    def add(self, exceptions, basic_blocks):
        for i in exceptions:
            self.exceptions.append( ExceptionAnalysis( i, basic_blocks ) )

    def get_exception(self, addr_start, addr_end):
        for i in self.exceptions:
#            print hex(i.start), hex(i.end), hex(addr_start), hex(addr_end), i.start >= addr_start and i.end <= addr_end, addr_end <= i.end and addr_start >= i.start
            if i.start >= addr_start and i.end <= addr_end:
                return i

            elif addr_end <= i.end and addr_start >= i.start:
                return i

        return None

    def gets(self):
        return self.exceptions

    def get(self):
        for i in self.exceptions:
            yield i

BO = { "BasicOPCODES" : dvm.BRANCH_DVM_OPCODES, "BasicClass" : DVMBasicBlock, "Dnext" : dvm.determineNext, "Dexception" : dvm.determineException }

BO["BasicOPCODES_H"] = []
for i in BO["BasicOPCODES"]:
  BO["BasicOPCODES_H"].append( re.compile( i ) )


class MethodAnalysis(object):
    """
        This class analyses in details a method of a class/dex file

        :param vm: the object which represent the dex file
        :param method: the original method
        :param tv: a virtual object to get access to tainted information
        :type vm: a :class:`DalvikVMFormat` object
        :type method: a :class:`EncodedMethod` object
    """
    def __init__(self, vm, method, tv):
        self.__vm = vm
        self.method = method

        self.tainted = tv

        self.basic_blocks = BasicBlocks(self.__vm, self.tainted)
        self.exceptions = Exceptions(self.__vm)

        code = self.method.get_code()
        if code == None:
            return

        current_basic = BO["BasicClass"](0, self.__vm, self.method, self.basic_blocks)
        self.basic_blocks.push(current_basic)

        ##########################################################

        bc = code.get_bc()
        l = []
        h = {}
        idx = 0

        debug("Parsing instructions")
        instructions = [i for i in bc.get_instructions()]
        for i in instructions:
            for j in BO["BasicOPCODES_H"]:
                if j.match(i.get_name()) != None:
                    v = BO["Dnext"](i, idx, self.method)
                    h[ idx ] = v
                    l.extend(v)
                    break

            idx += i.get_length()

        debug("Parsing exceptions")
        excepts = BO["Dexception"]( self.__vm, self.method )
        for i in excepts:
            l.extend( [i[0]] )
            for handler in i[2:]:
                l.append( handler[1] )

        debug("Creating basic blocks in %s" % self.method)
        idx = 0
        for i in instructions:
            # index is a destination
            if idx in l:
                if current_basic.get_nb_instructions() != 0:
                    current_basic = BO["BasicClass"](current_basic.get_end(), self.__vm, self.method, self.basic_blocks)
                    self.basic_blocks.push(current_basic)

            current_basic.push(i)

            # index is a branch instruction
            if idx in h:
                current_basic = BO["BasicClass"]( current_basic.get_end(), self.__vm, self.method, self.basic_blocks )
                self.basic_blocks.push( current_basic )

            idx += i.get_length()

        if current_basic.get_nb_instructions() == 0:
            self.basic_blocks.pop(-1)

        debug("Settings basic blocks childs")

        for i in self.basic_blocks.get():
            try:
                i.set_childs( h[ i.end - i.get_last_length() ] )
            except KeyError:
                i.set_childs( [] )

        debug("Creating exceptions")

        # Create exceptions
        self.exceptions.add(excepts, self.basic_blocks)

        for i in self.basic_blocks.get():
            # setup exception by basic block
            i.set_exception_analysis(self.exceptions.get_exception( i.start, i.end - 1 ))

        del instructions
        del h, l

    def get_basic_blocks(self):
        """
            :rtype: a :class:`BasicBlocks` object
        """
        return self.basic_blocks

    def get_length(self):
        """
            :rtype: an integer which is the length of the code
        """
        return self.get_code().get_length()

    def get_vm(self):
        return self.__vm

    def get_method(self):
        return self.method

    def get_local_variables(self):
        return self.tainted.get_tainted_variables().get_local_variables( self.method )

    def show(self):
        print "METHOD", self.method.get_class_name(), self.method.get_name(), self.method.get_descriptor()

        for i in self.basic_blocks.get():
            print "\t", i
            i.show()
            print ""

    def show_methods(self):
        print "\t #METHODS :"
        for i in self.__bb:
            methods = i.get_methods()
            for method in methods:
                print "\t\t-->", method.get_class_name(), method.get_name(), method.get_descriptor()
                for context in methods[method]:
                    print "\t\t\t |---|", context.details

    def create_tags(self):
      """
          Create the tags for the method
      """
      self.tags = Tags()
      for i in self.tainted.get_tainted_packages().get_packages_by_method( self.method ):
        self.tags.emit_by_classname( i )

    def get_tags(self):
      """
          Return the tags of the method

          :rtype: a :class:`Tags` object
      """
      return self.tags

SIGNATURE_L0_0 = "L0_0"
SIGNATURE_L0_1 = "L0_1"
SIGNATURE_L0_2 = "L0_2"
SIGNATURE_L0_3 = "L0_3"
SIGNATURE_L0_4 = "L0_4"
SIGNATURE_L0_5 = "L0_5"
SIGNATURE_L0_6 = "L0_6"
SIGNATURE_L0_0_L1 = "L0_0:L1"
SIGNATURE_L0_1_L1 = "L0_1:L1"
SIGNATURE_L0_2_L1 = "L0_2:L1"
SIGNATURE_L0_3_L1 = "L0_3:L1"
SIGNATURE_L0_4_L1 = "L0_4:L1"
SIGNATURE_L0_5_L1 = "L0_5:L1"
SIGNATURE_L0_0_L2 = "L0_0:L2"
SIGNATURE_L0_0_L3 = "L0_0:L3"
SIGNATURE_HEX = "hex"
SIGNATURE_SEQUENCE_BB = "sequencebb"

SIGNATURES = {
                SIGNATURE_L0_0 : { "type" : 0 },
                SIGNATURE_L0_1 : { "type" : 1 },
                SIGNATURE_L0_2 : { "type" : 2, "arguments" : ["Landroid"] },
                SIGNATURE_L0_3 : { "type" : 2, "arguments" : ["Ljava"] },
                SIGNATURE_L0_4 : { "type" : 2, "arguments" : ["Landroid", "Ljava"] },
                SIGNATURE_L0_5 : { "type" : 3, "arguments" : ["Landroid"] },
                SIGNATURE_L0_6 : { "type" : 3, "arguments" : ["Ljava"] },
                SIGNATURE_SEQUENCE_BB : {},
                SIGNATURE_HEX : {},
            }

from sign import Signature

class StringAnalysis(object):
    def __init__(self, value):
        self.value = value
        self.xreffrom = set()

    def AddXrefFrom(self, classobj, methodobj):
        #debug("Added strings xreffrom for %s to %s" % (self.value, methodobj))
        self.xreffrom.add((classobj, methodobj))

    def get_xref_from(self):
        return self.xreffrom

    def __str__(self):
        data = "XREFto for string %s in\n" % repr(self.value)
        for ref_class, ref_method in self.xreffrom:
            data += "%s:%s\n" % (ref_class.get_vm_class().get_name(), ref_method)
        return data


class MethodClassAnalysis(object):
    def __init__(self, method):
        self.method = method
        self.xrefto = set()
        self.xreffrom = set()

    def AddXrefTo(self, classobj, methodobj):
        #debug("Added method xrefto for %s [%s] to %s" % (self.method, classobj, methodobj))
        self.xrefto.add((classobj, methodobj))

    def AddXrefFrom(self, classobj, methodobj):
        #debug("Added method xreffrom for %s [%s] to %s" % (self.method, classobj, methodobj))
        self.xreffrom.add((classobj, methodobj))

    def get_xref_from(self):
        return self.xreffrom

    def get_xref_to(self):
        return self.xrefto

    def __str__(self):
        data = "XREFto for %s\n" % self.method
        for ref_class, ref_method in self.xrefto:
            data += "in\n"
            data += "%s:%s\n" % (ref_class.get_vm_class().get_name(), ref_method)

        data += "XREFFrom for %s\n" % self.method
        for ref_class, ref_method in self.xreffrom:
            data += "in\n"
            data += "%s:%s\n" % (ref_class.get_vm_class().get_name(), ref_method)

        return data

class FieldClassAnalysis(object):
    def __init__(self, field):
        self.field = field
        self.xrefread = set()
        self.xrefwrite = set()

    def AddXrefRead(self, classobj, methodobj):
        #debug("Added method xrefto for %s [%s] to %s" % (self.method, classobj, methodobj))
        self.xrefread.add((classobj, methodobj))

    def AddXrefWrite(self, classobj, methodobj):
        #debug("Added method xreffrom for %s [%s] to %s" % (self.method, classobj, methodobj))
        self.xrefwrite.add((classobj, methodobj))

    def get_xref_read(self):
        return self.xrefread

    def get_xref_write(self):
        return self.xrefwrite

    def __str__(self):
        data = "XREFRead for %s\n" % self.field
        for ref_class, ref_method in self.xrefread:
            data += "in\n"
            data += "%s:%s\n" % (ref_class.get_vm_class().get_name(), ref_method)

        data += "XREFWrite for %s\n" % self.field
        for ref_class, ref_method in self.xrefwrite:
            data += "in\n"
            data += "%s:%s\n" % (ref_class.get_vm_class().get_name(), ref_method)

        return data

REF_NEW_INSTANCE = 0
REF_CLASS_USAGE = 1

class ClassAnalysis(object):
    def __init__(self, classobj):
        self._class = classobj
        self._methods = {}
        self._fields = {}

        self.xrefto = collections.defaultdict(set)
        self.xreffrom = collections.defaultdict(set)

    def get_method_analysis(self, method):
        return self._methods.get(method)

    def get_field_analysis(self, field):
        return self._fields.get(field)

    def AddFXrefRead(self, method, classobj, field):
        if field not in self._fields:
            self._fields[field] = FieldClassAnalysis(field)
        self._fields[field].AddXrefRead(classobj, method)

    def AddFXrefWrite(self, method, classobj, field):
        if field not in self._fields:
            self._fields[field] = FieldClassAnalysis(field)
        self._fields[field].AddXrefWrite(classobj, method)

    def AddMXrefTo(self, method1, classobj, method2):
        if method1 not in self._methods:
            self._methods[method1] = MethodClassAnalysis(method1)
        self._methods[method1].AddXrefTo(classobj, method2)

    def AddMXrefFrom(self, method1, classobj, method2):
        if method1 not in self._methods:
            self._methods[method1] = MethodClassAnalysis(method1)
        self._methods[method1].AddXrefFrom(classobj, method2)

    def AddXrefTo(self, ref_kind, classobj, methodobj):
        #debug("Added class xrefto for %s to %s" % (self._class.get_name(), classobj.get_vm_class().get_name()))
        self.xrefto[classobj].add((ref_kind, methodobj))

    def AddXrefFrom(self, ref_kind, classobj, methodobj):
        #debug("Added class xreffrom for %s to %s" % (self._class.get_name(), classobj.get_vm_class().get_name()))
        self.xreffrom[classobj].add((ref_kind, methodobj))

    def get_xref_from(self):
        return self.xreffrom

    def get_xref_to(self):
        return self.xrefto

    def get_vm_class(self):
        return self._class

    def __str__(self):
        data = "XREFto for %s\n" % self._class
        for ref_class in self.xrefto:
            data += str(ref_class.get_vm_class().get_name()) + " "
            data += "in\n"
            for ref_kind, ref_method in self.xrefto[ref_class]:
                data += "%d %s\n" % (ref_kind, ref_method)

            data += "\n"

        data += "XREFFrom for %s\n" % self._class
        for ref_class in self.xreffrom:
            data += str(ref_class.get_vm_class().get_name()) + " "
            data += "in\n"
            for ref_kind, ref_method in self.xreffrom[ref_class]:
                data += "%d %s\n" % (ref_kind, ref_method)

            data += "\n"

        return data

class newVMAnalysis(object):
    def __init__(self, vm):
        self.vm = vm
        self.classes = {}
        self.strings = {}

        for current_class in self.vm.get_classes():
            self.classes[current_class.get_name()] = ClassAnalysis(current_class)

    def create_xref(self):
        debug("Creating XREF/DREF")

        instances_class_name = self.classes.keys()
        external_instances = {}

        for current_class in self.vm.get_classes():
            for current_method in current_class.get_methods():
                debug("Creating XREF for %s" % current_method)

                code = current_method.get_code()
                if code == None:
                    continue

                off = 0
                bc = code.get_bc()
                for instruction in bc.get_instructions():
                    op_value = instruction.get_op_value()
                    if op_value in [0x1c, 0x22]:
                        idx_type = instruction.get_ref_kind()
                        type_info = self.vm.get_cm_type(idx_type)

                        # Internal xref related to class manipulation
                        if type_info in instances_class_name and type_info != current_class.get_name():
                            # new instance
                            if op_value == 0x22:
                                self.classes[current_class.get_name()].AddXrefTo(REF_NEW_INSTANCE, self.classes[type_info], current_method)
                                self.classes[type_info].AddXrefFrom(REF_NEW_INSTANCE, self.classes[current_class.get_name()], current_method)
                            # class reference
                            else:
                                self.classes[current_class.get_name()].AddXrefTo(REF_CLASS_USAGE, self.classes[type_info], current_method)
                                self.classes[type_info].AddXrefFrom(REF_CLASS_USAGE, self.classes[current_class.get_name()], current_method)

                    elif ((op_value >= 0x6e and op_value <= 0x72) or
                        (op_value >= 0x74 and op_value <= 0x78)):
                            idx_meth = instruction.get_ref_kind()
                            method_info = self.vm.get_cm_method(idx_meth)
                            if method_info:
                                class_info = method_info[0]

                                method_item = self.vm.get_method_descriptor(method_info[0], method_info[1], ''.join(method_info[2]))
                                if method_item:
                                    self.classes[current_class.get_name()].AddMXrefTo(current_method, self.classes[class_info], method_item)
                                    self.classes[class_info].AddMXrefFrom(method_item, self.classes[current_class.get_name()], current_method)

                                    # Internal xref related to class manipulation
                                    if class_info in instances_class_name and class_info != current_class.get_name():
                                        self.classes[current_class.get_name()].AddXrefTo(REF_CLASS_USAGE, self.classes[class_info], method_item)
                                        self.classes[class_info].AddXrefFrom(REF_CLASS_USAGE, self.classes[current_class.get_name()], current_method)

                    elif op_value >= 0x1a and op_value <= 0x1b:
                        string_value = self.vm.get_cm_string(instruction.get_ref_kind())
                        if string_value not in self.strings:
                            self.strings[string_value] = StringAnalysis(string_value)
                        self.strings[string_value].AddXrefFrom(self.classes[current_class.get_name()], current_method)

                    elif op_value >= 0x52 and op_value <= 0x6d:
                        idx_field = instruction.get_ref_kind()
                        field_info = self.vm.get_cm_field(idx_field)
                        field_item = self.vm.get_field_descriptor(field_info[0], field_info[2], field_info[1])
                        if field_item:
                            # read access to a field
                            if (op_value >= 0x52 and op_value <= 0x58) or (op_value >= 0x60 and op_value <= 0x66):
                                self.classes[current_class.get_name()].AddFXrefRead(current_method, self.classes[current_class.get_name()], field_item)
                            # write access to a field
                            else:
                                self.classes[current_class.get_name()].AddFXrefWrite(current_method, self.classes[current_class.get_name()], field_item)

                    off += instruction.get_length()

    def get_method(self, method):
        return MethodAnalysis( self.vm, method, None )

    def get_method_by_name(self, class_name, method_name, method_descriptor):
        print class_name, method_name, method_descriptor
        if class_name in self.classes:
            for method in self.classes[class_name].get_vm_class().get_methods():
                print method.get_name(), method.get_descriptor()
                if method.get_name() == method_name and method.get_descriptor() == method_descriptor:
                    return method
        return None

    def is_class_present(self, class_name):
        return class_name in self.classes

    def get_class_analysis(self, class_name):
        return self.classes.get(class_name)

    def get_strings_analysis(self):
        return self.strings

class VMAnalysis(object):
    """
       This class analyses a dex file

       :param _vm: the object which represent the dex file
       :type _vm: a :class:`DalvikVMFormat` object

       :Example:
            VMAnalysis( DalvikVMFormat( read("toto.dex", binary=False) ) )
    """
    def __init__(self, vm):
        self.vm = vm

        self.tainted_variables = TaintedVariables( self.vm )
        self.tainted_packages = TaintedPackages( self.vm )

        self.tainted = { "variables" : self.tainted_variables,
                         "packages" : self.tainted_packages,
                       }

        self.signature = None

        for i in self.vm.get_all_fields():
            self.tainted_variables.add( [ i.get_class_name(), i.get_descriptor(), i.get_name() ], TAINTED_FIELD )

        self.methods = []
        self.hmethods = {}
        self.__nmethods = {}
        for i in self.vm.get_methods():
            x = MethodAnalysis( self.vm, i, self )
            self.methods.append( x )
            self.hmethods[ i ] = x
            self.__nmethods[ i.get_name() ] = x

    def get_vm(self):
        return self.vm

    def get_method(self, method):
        """
            Return an analysis method

            :param method: a classical method object
            :type method: an :class:`EncodedMethod` object

            :rtype: a :class:`MethodAnalysis` object
        """
        return self.hmethods[ method ]

    def get_methods(self):
        """
           Return each analysis method

           :rtype: a :class:`MethodAnalysis` object
        """
        for i in self.hmethods:
            yield self.hmethods[i]

    def get_method_signature(self, method, grammar_type="", options={}, predef_sign=""):
        """
            Return a specific signature for a specific method

            :param method: a reference to method from a vm class
            :type method: a :class:`EncodedMethod` object

            :param grammar_type: the type of the signature (optional)
            :type grammar_type: string

            :param options: the options of the signature (optional)
            :param options: dict

            :param predef_sign: used a predefined signature (optional)
            :type predef_sign: string

            :rtype: a :class:`Sign` object
        """
        if self.signature == None:
          self.signature = Signature( self )

        if predef_sign != "":
            g = ""
            o = {}

            for i in predef_sign.split(":"):
                if "_" in i:
                    g += "L0:"
                    o[ "L0" ] = SIGNATURES[ i ]
                else:
                    g += i
                    g += ":"

            return self.signature.get_method( self.get_method( method ), g[:-1], o )
        else:
            return self.signature.get_method( self.get_method( method ), grammar_type, options )

    def get_permissions(self, permissions_needed):
        """
            Return the permissions used

            :param permissions_needed: a list of restricted permissions to get ([] returns all permissions)
            :type permissions_needed: list

            :rtype: a dictionnary of permissions paths
        """
        permissions = {}

        permissions.update( self.get_tainted_packages().get_permissions( permissions_needed ) )
        permissions.update( self.get_tainted_variables().get_permissions( permissions_needed ) )

        return permissions

    def get_permissions_method(self, method):
        permissions_f = self.get_tainted_packages().get_permissions_method( method )
        permissions_v = self.get_tainted_variables().get_permissions_method( method )

        all_permissions_of_method = permissions_f.union(permissions_v)

        return list(all_permissions_of_method)

    def get_tainted_variables(self):
        """
           Return the tainted variables

           :rtype: a :class:`TaintedVariables` object
        """
        return self.tainted_variables

    def get_tainted_packages(self):
        """
           Return the tainted packages

           :rtype: a :class:`TaintedPackages` object
        """
        return self.tainted_packages

    def get_tainted_fields(self):
        return self.get_tainted_variables().get_fields()

    def get_tainted_field(self, class_name, name, descriptor):
        """
           Return a specific tainted field

           :param class_name: the name of the class
           :param name: the name of the field
           :param descriptor: the descriptor of the field
           :type class_name: string
           :type name: string
           :type descriptor: string

           :rtype: a :class:`TaintedVariable` object
        """
        return self.get_tainted_variables().get_field( class_name, name, descriptor )

class uVMAnalysis(VMAnalysis):
  """
     This class analyses a dex file but on the fly (quicker !)

     :param _vm: the object which represent the dex file
     :type _vm: a :class:`DalvikVMFormat` object

     :Example:
          uVMAnalysis( DalvikVMFormat( read("toto.dex", binary=False) ) )
  """
  def __init__(self, vm):
    self.vm = vm
    self.tainted_variables = TaintedVariables( self.vm )
    self.tainted_packages = TaintedPackages( self.vm )

    self.tainted = { "variables" : self.tainted_variables,
                     "packages" : self.tainted_packages,
    }

    self.signature = None
    self.resolve = False

  def get_methods(self):
    self.resolve = True
    for i in self.vm.get_methods():
      yield MethodAnalysis(self.vm, i, self)

  def get_method(self, method):
    return MethodAnalysis( self.vm, method, None )

  def get_vm(self):
    return self.vm

  def _resolve(self):
    if self.resolve == False:
      for i in self.get_methods():
        pass

  def get_tainted_packages(self):
    self._resolve()
    return self.tainted_packages

  def get_tainted_variables(self):
        self._resolve()
        return self.tainted_variables

def is_ascii_obfuscation(vm):
    for classe in vm.get_classes():
        if is_ascii_problem(classe.get_name()):
            return True
        for method in classe.get_methods():
            if is_ascii_problem(method.get_name()):
                return True
    return False
