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

from androguard.core import androconf
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis
from androguard.core.analysis import ganalysis
from androguard.util import read

class BC(object):
    def __init__(self, bc):
        self.__bc = bc

    def get_vm(self):
        return self.__bc

    def get_analysis(self):
        return self.__a

    def analyze(self):
        self.__a = analysis.uVMAnalysis( self.__bc )
        self.__bc.set_vmanalysis( self.__a )

        self.__g = ganalysis.GVMAnalysis( self.__a, None )

        self.__bc.set_gvmanalysis( self.__g )

        self.__bc.create_xref()
        self.__bc.create_dref()

    def _get(self, val, name):
        l = []
        r = getattr(self.__bc, val)(name)
        for i in r:
            l.append( i )
        return l

    def _gets(self, val):
        l = []
        r = getattr(self.__bc, val)()
        for i in r:
            l.append( i )
        return l

    def gets(self, name):
        return self._gets("get_" + name)

    def get(self, val, name):
        return self._get("get_" + val, name)

    def insert_direct_method(self, name, method):
        return self.__bc.insert_direct_method(name, method)

    def insert_craft_method(self, name, proto, codes):
        return self.__bc.insert_craft_method( name, proto, codes)

    def show(self):
        self.__bc.show()

    def pretty_show(self):
        self.__bc.pretty_show()

    def save(self):
        return self.__bc.save()

    def __getattr__(self, value):
        return getattr(self.__bc, value)

class Androguard(object):
    """Androguard is the main object to abstract and manage differents formats

       @param files : a list of filenames (filename must be terminated by .class or .dex)
       @param raw : specify if the filename is in fact a raw buffer (default : False) #FIXME
    """
    def __init__(self, files, raw=False):
        self.__files = files

        self.__orig_raw = {}
        for i in self.__files:
            self.__orig_raw[ i ] = read(i)

        self.__bc = []
        self._analyze()

    def _iterFlatten(self, root):
        if isinstance(root, (list, tuple)):
            for element in root:
                for e in self._iterFlatten(element):
                    yield e
        else:
            yield root

    def _analyze(self):
        for i in self.__files:
            ret_type = androconf.is_android( i )
            if ret_type == "APK":
                x = apk.APK( i )
                bc = dvm.DalvikVMFormat( x.get_dex() )
            elif ret_type == "DEX":
                bc = dvm.DalvikVMFormat( read(i) )
            elif ret_type == "DEY":
                bc = dvm.DalvikOdexVMFormat( read(i) )
            elif ret_type == "ELF":
                from androguard.core.binaries import elf
                bc = elf.ELF( read(i) )
            else:
                raise( "Unknown format" )

            self.__bc.append( (i, BC( bc )) )

    def ianalyze(self):
        for i in self.get_bc():
            i[1].analyze()

    def get_class(self, class_name):
        for _, bc in self.__bc:
            if bc.get_class(class_name) == True:
                return bc
        return None

    def get_raw(self):
        """Return raw format of all file"""
        l = []
        for _, bc in self.__bc:
            l.append( bc._get_raw() )
        return l

    def get_orig_raw(self):
        return self.__orig_raw

    def get_method_descriptor(self, class_name, method_name, descriptor):
        """
           Return the specific method

           @param class_name : the class name of the method
           @param method_name : the name of the method
           @param descriptor : the descriptor of the method
        """
        for file_name, bc in self.__bc:
            x = bc.get_method_descriptor( class_name, method_name, descriptor )
            if x != None:
                return x, bc
        return None, None

    def get_field_descriptor(self, class_name, field_name, descriptor):
        """
           Return the specific field

           @param class_name : the class name of the field
           @param field_name : the name of the field
           @param descriptor : the descriptor of the field
        """
        for file_name, bc in self.__bc:
            x = bc.get_field_descriptor( class_name, field_name, descriptor )
            if x != None:
                return x, bc
        return None, None

    def get(self, name, val):
        """
           Return the specific value for all files

           @param name:
           @param val:
        """
        if name == "file":
            for file_name, bc in self.__bc:
                if file_name == val:
                    return bc

            return None
        else:
            l = []
            for file_name, bc in self.__bc:
                l.append( bc.get( name, val ) )

            return list( self._iterFlatten(l) )

    def gets(self, name):
        """
           Return the specific value for all files

           @param name:
        """
        l = []
        for file_name, bc in self.__bc:
            l.append( bc.gets( name ) )

        return list( self._iterFlatten(l) )

    def get_vms(self):
        return [ i[1].get_vm() for i in self.__bc ]

    def get_bc(self):
        return self.__bc

    def show(self):
        """
           Display all files
        """
        for _, bc in self.__bc:
            bc.show()

    def pretty_show(self):
        """
           Display all files
        """
        for _, bc in self.__bc:
            bc.pretty_show()

class AndroguardS(object):
    """AndroguardS is the main object to abstract and manage differents formats but only per filename. In fact this class is just a wrapper to the main class Androguard

       @param filename : the filename to use (filename must be terminated by .class or .dex)
       @param raw : specify if the filename is a raw buffer (default : False)
    """
    def __init__(self, filename, raw=False):
        self.__filename = filename
        self.__orig_a = Androguard( [ filename ], raw )
        self.__a = self.__orig_a.get( "file", filename )

    def get_orig_raw(self):
        return self.__orig_a.get_orig_raw()[ self.__filename ]

    def get_vm(self):
        """
           This method returns the VMFormat which correspond to the file

           @rtype: L{dvm.DalvikVMFormat}
        """
        return self.__a.get_vm()

    def save(self):
        """
           Return the original format (with the modifications) into raw format

           @rtype: string
        """
        return self.__a.save()

    def __getattr__(self, value):
        try:
            return getattr(self.__orig_a, value)
        except AttributeError:
            return getattr(self.__a, value)
