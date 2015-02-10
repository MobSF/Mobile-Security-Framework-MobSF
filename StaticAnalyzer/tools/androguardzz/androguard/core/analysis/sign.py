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


from analysis import TAINTED_PACKAGE_CREATE, TAINTED_PACKAGE_CALL
import dvm

TAINTED_PACKAGE_INTERNAL_CALL = 2
FIELD_ACCESS = { "R" : 0, "W" : 1 }
PACKAGE_ACCESS = { TAINTED_PACKAGE_CREATE : 0, TAINTED_PACKAGE_CALL : 1, TAINTED_PACKAGE_INTERNAL_CALL : 2 }

class Sign :
    def __init__(self) :
        self.levels = {} 
        self.hlevels = []

    def add(self, level, value) :
        self.levels[ level ] = value
        self.hlevels.append( level )

    def get_level(self, l) :
        return self.levels[ "L%d" % l ]

    def get_string(self) :
        buff = ""
        for i in self.hlevels :
            buff += self.levels[ i ]
        return buff

    def get_list(self) :
      return self.levels[ "sequencebb" ]

class Signature :
    def __init__(self, vmx) :
        self.vmx = vmx
        self.tainted_packages = self.vmx.get_tainted_packages()
        self.tainted_variables = self.vmx.get_tainted_variables()

        self._cached_signatures = {}
        self._cached_fields = {}
        self._cached_packages = {}
        self._global_cached = {}

        self.levels = {
                        # Classical method signature with basic blocks, strings, fields, packages
                        "L0" : {
                                    0 : ( "_get_strings_a",     "_get_fields_a",    "_get_packages_a" ),
                                    1 : ( "_get_strings_pa",    "_get_fields_a",    "_get_packages_a" ),
                                    2 : ( "_get_strings_a",     "_get_fields_a",    "_get_packages_pa_1" ),
                                    3 : ( "_get_strings_a",     "_get_fields_a",    "_get_packages_pa_2" ),
                                },

                        # strings
                        "L1" : [ "_get_strings_a1" ],

                        # exceptions
                        "L2" : [ "_get_exceptions" ],

                        # fill array data
                        "L3" : [ "_get_fill_array_data" ],
                    }

        self.classes_names = None
        self._init_caches()

    def _get_method_info(self, m) :
        m1 = m.get_method()
        return "%s-%s-%s" % (m1.get_class_name(), m1.get_name(), m1.get_descriptor())


    def _get_sequence_bb(self, analysis_method) :
        l = []

        for i in analysis_method.basic_blocks.get() :
          buff = ""
          instructions = [j for j in i.get_instructions()]
          if len(instructions) > 5 :
            for ins in instructions :
              buff += ins.get_name()
          if buff != "" :
            l.append( buff )

        return l

    def _get_hex(self, analysis_method) :
        code = analysis_method.get_method().get_code()
        if code == None :
            return ""

        buff = ""
        for i in code.get_bc().get_instructions() :
            buff += dvm.clean_name_instruction( i )
            buff += dvm.static_operand_instruction( i )

        return buff

    def _get_bb(self, analysis_method, functions, options) :
        bbs = []
        for b in analysis_method.basic_blocks.get() :
            l = []
            l.append( (b.start, "B") )
            l.append( (b.start, "[") )

            internal = []

            op_value = b.get_last().get_op_value()

            # return
            if op_value >= 0x0e and op_value <= 0x11 :
                internal.append( (b.end-1, "R") )

            # if
            elif op_value >= 0x32 and op_value <= 0x3d :
                internal.append( (b.end-1, "I") )

            # goto
            elif op_value >= 0x28 and op_value <= 0x2a :
                internal.append( (b.end-1, "G") )

            # sparse or packed switch
            elif op_value >= 0x2b and op_value <= 0x2c :
                internal.append( (b.end-1, "G") )


            for f in functions :
                try :
                    internal.extend( getattr( self, f )( analysis_method, options ) )
                except TypeError :
                    internal.extend( getattr( self, f )( analysis_method ) )

            internal.sort()
            
            for i in internal :
                if i[0] >= b.start and i[0] < b.end :
                    l.append( i )

            del internal

            l.append( (b.end, "]") )

            bbs.append( ''.join(i[1] for i in l) )
        return bbs

    def _init_caches(self) :
        if self._cached_fields == {} :
            for f_t, f in self.tainted_variables.get_fields() :
                self._cached_fields[ f ] = f_t.get_paths_length()
            n = 0
            for f in sorted( self._cached_fields ) :
                self._cached_fields[ f ] = n
                n += 1

        if self._cached_packages == {} :
            for m_t, m in self.tainted_packages.get_packages() :
                self._cached_packages[ m ] = m_t.get_paths_length()
            n = 0
            for m in sorted( self._cached_packages ) :
                self._cached_packages[ m ] = n
                n += 1

    def _get_fill_array_data(self, analysis_method) :
        buff = ""
        for b in analysis_method.basic_blocks.get() :
            for i in b.get_instructions() :
                if i.get_name() == "FILL-ARRAY-DATA" :
                    buff_tmp = i.get_operands()
                    for j in range(0, len(buff_tmp)) :
                        buff += "\\x%02x" % ord( buff_tmp[j] )
        return buff

    def _get_exceptions(self, analysis_method) :
        buff = ""

        method = analysis_method.get_method()
        code = method.get_code()
        if code == None or code.get_tries_size() <= 0 :
            return buff

        handler_catch_list = code.get_handlers()

        for handler_catch in handler_catch_list.get_list() :
            for handler in handler_catch.get_handlers() :
                buff += analysis_method.get_vm().get_cm_type( handler.get_type_idx() )
        return buff

    def _get_strings_a1(self, analysis_method) :
        buff = ""

        strings_method = self.tainted_variables.get_strings_by_method( analysis_method.get_method() )
        for s in strings_method :
            for path in strings_method[s] :
                buff += s.replace('\n', ' ')
        return buff

    def _get_strings_pa(self, analysis_method) :
        l = []

        strings_method = self.tainted_variables.get_strings_by_method( analysis_method.get_method() )
        for s in strings_method :
            for path in strings_method[s] :
                l.append( ( path[1], "S%d" % len(s) ) )
        return l


    def _get_strings_a(self, analysis_method) :
        key = "SA-%s" % self._get_method_info(analysis_method)
        if key in self._global_cached :
            return self._global_cached[ key ]

        l = []

        strings_method = self.tainted_variables.get_strings_by_method( analysis_method.get_method() )
        for s in strings_method :
            for path in strings_method[s] :
                l.append( ( path[1], "S") )

        self._global_cached[ key ] = l
        return l

    def _get_fields_a(self, analysis_method) :
        key = "FA-%s" % self._get_method_info(analysis_method)
        if key in self._global_cached :
            return self._global_cached[ key ]

        fields_method = self.tainted_variables.get_fields_by_method( analysis_method.get_method() )
        l = []

        for f in fields_method :
            for path in fields_method[ f ] :
                l.append( (path[1], "F%d" % FIELD_ACCESS[ path[0] ]) )

        self._global_cached[ key ] = l
        return l

    def _get_packages_a(self, analysis_method) :
        packages_method = self.tainted_packages.get_packages_by_method( analysis_method.get_method() )
        l = []

        for m in packages_method :
            for path in packages_method[ m ] :
                l.append( (path.get_idx(), "P%s" % (PACKAGE_ACCESS[ path.get_access_flag() ]) ) )
        return l

    def _get_packages(self, analysis_method, include_packages) :
        l = self._get_packages_pa_1( analysis_method, include_packages )
        return "".join([ i[1] for i in l ])

    def _get_packages_pa_1(self, analysis_method, include_packages) :
        key = "PA1-%s-%s" % (self._get_method_info(analysis_method), include_packages)
        if key in self._global_cached :
            return self._global_cached[ key ]

        packages_method = self.tainted_packages.get_packages_by_method( analysis_method.get_method() )
        if self.classes_names == None :
            self.classes_names = analysis_method.get_vm().get_classes_names()

        l = []


        for m in packages_method :
            for path in packages_method[ m ] :
                present = False
                for i in include_packages :
                    if m.find(i) == 0 :
                        present = True
                        break

                if path.get_access_flag() == 1 :
                    dst_class_name, dst_method_name, dst_descriptor = path.get_dst( analysis_method.get_vm().get_class_manager() )

                    if dst_class_name in self.classes_names :
                        l.append( (path.get_idx(), "P%s" % (PACKAGE_ACCESS[ 2 ]) ) )
                    else :
                        if present == True :
                            l.append( (path.get_idx(), "P%s{%s%s%s}" % (PACKAGE_ACCESS[ path.get_access_flag() ], dst_class_name, dst_method_name, dst_descriptor ) ) )
                        else :
                            l.append( (path.get_idx(), "P%s" % (PACKAGE_ACCESS[ path.get_access_flag() ]) ) )
                else :
                    if present == True :
                        l.append( (path.get_idx(), "P%s{%s}" % (PACKAGE_ACCESS[ path.get_access_flag() ], m) ) )
                    else :
                        l.append( (path.get_idx(), "P%s" % (PACKAGE_ACCESS[ path.get_access_flag() ]) ) )

        self._global_cached[ key ] = l
        return l

    def _get_packages_pa_2(self, analysis_method, include_packages) :
        packages_method = self.tainted_packages.get_packages_by_method( analysis_method.get_method() )

        l = []

        for m in packages_method :
            for path in packages_method[ m ] :
                present = False
                for i in include_packages :
                    if m.find(i) == 0 :
                        present = True
                        break
                
                if present == True :
                    l.append( (path.get_idx(), "P%s" % (PACKAGE_ACCESS[ path.get_access_flag() ]) ) )
                    continue

                if path.get_access_flag() == 1 :
                    dst_class_name, dst_method_name, dst_descriptor = path.get_dst( analysis_method.get_vm().get_class_manager() )
                    l.append( (path.get_idx(), "P%s{%s%s%s}" % (PACKAGE_ACCESS[ path.get_access_flag() ], dst_class_name, dst_method_name, dst_descriptor ) ) )
                else :
                    l.append( (path.get_idx(), "P%s{%s}" % (PACKAGE_ACCESS[ path.get_access_flag() ], m) ) )

        return l

    def get_method(self, analysis_method, signature_type, signature_arguments={}) :
        key = "%s-%s-%s" % (self._get_method_info(analysis_method), signature_type, signature_arguments)

        if key in self._cached_signatures :
            return self._cached_signatures[ key ]

        s = Sign()

        #print signature_type, signature_arguments
        for i in signature_type.split(":") :
        #    print i, signature_arguments[ i ]
            if i == "L0" : 
                _type = self.levels[ i ][ signature_arguments[ i ][ "type" ] ]
                try : 
                    _arguments = signature_arguments[ i ][ "arguments" ] 
                except KeyError :
                    _arguments = []

                value = self._get_bb( analysis_method, _type, _arguments ) 
                s.add( i, ''.join(z for z in value) )

            elif i == "L4" :
                try :
                    _arguments = signature_arguments[ i ][ "arguments" ]
                except KeyError :
                    _arguments = []

                value = self._get_packages( analysis_method, _arguments )
                s.add( i , value )

            elif i == "hex" :
                value = self._get_hex( analysis_method )
                s.add( i, value )

            elif i == "sequencebb" :
                _type = ('_get_strings_a', '_get_fields_a', '_get_packages_pa_1')
                _arguments = ['Landroid', 'Ljava']

                #value = self._get_bb( analysis_method, _type, _arguments )
                #s.add( i, value )

                value = self._get_sequence_bb( analysis_method )
                s.add( i, value )

            else :
                for f in self.levels[ i ] : 
                    value = getattr( self, f )( analysis_method )
                s.add( i, value )

        self._cached_signatures[ key ] = s
        return s
