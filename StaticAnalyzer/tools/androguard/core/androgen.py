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

from androguard.core import androconf
from androguard.core.bytecodes import jvm
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis

class BC :
    def __init__(self, bc) :
        self.__bc = bc

    def get_vm(self) :
        return self.__bc

    def get_analysis(self) :
        return self.__a

    def analyze(self) :
        self.__a = analysis.uVMAnalysis( self.__bc )
        self.__bc.set_vmanalysis( self.__a )

    def _get(self, val, name) :
        l = []
        r = getattr(self.__bc, val)(name)
        for i in r :
            l.append( i )
        return l

    def _gets(self, val) :
        l = []
        r = getattr(self.__bc, val)()
        for i in r :
            l.append( i )
        return l

    def gets(self, name) :
        return self._gets("get_" + name)

    def get(self, val, name) :
        return self._get("get_" + val, name)

    def insert_direct_method(self, name, method) :
        return self.__bc.insert_direct_method(name, method)

    def insert_craft_method(self, name, proto, codes) :
        return self.__bc.insert_craft_method( name, proto, codes)

    def show(self) :
        self.__bc.show()

    def pretty_show(self) :
        self.__bc.pretty_show()

    def save(self) :
        return self.__bc.save()

    def __getattr__(self, value) :
        return getattr(self.__bc, value)

class Androguard:
    """Androguard is the main object to abstract and manage differents formats

       @param files : a list of filenames (filename must be terminated by .class or .dex)
       @param raw : specify if the filename is in fact a raw buffer (default : False) #FIXME
    """
    def __init__(self, files, raw=False) :
        self.__files = files

        self.__orig_raw = {}
        for i in self.__files :
            self.__orig_raw[ i ] = open(i, "rb").read()

        self.__bc = []
        self._analyze()

    def _iterFlatten(self, root):
        if isinstance(root, (list, tuple)):
            for element in root :
                for e in self._iterFlatten(element) :
                    yield e
        else:
            yield root

    def _analyze(self) :
        for i in self.__files :
            #print "processing ", i
            if ".class" in i :
                bc = jvm.JVMFormat( self.__orig_raw[ i ] )
            elif ".jar" in i :
                x = jvm.JAR( i )
                bc = x.get_classes()
            elif ".dex" in i :
                bc = dvm.DalvikVMFormat( self.__orig_raw[ i ] )
            elif ".apk" in i :
                x = apk.APK( i )
                bc = dvm.DalvikVMFormat( x.get_dex() )
            else :
                ret_type = androconf.is_android( i )
                if ret_type == "APK" :
                    x = apk.APK( i )
                    bc = dvm.DalvikVMFormat( x.get_dex() )
                elif ret_type == "DEX" : 
                    bc = dvm.DalvikVMFormat( open(i, "rb").read() )
                elif ret_type == "ELF" :
                    from androguard.core.binaries import elf
                    bc = elf.ELF( open(i, "rb").read() )
                else :
                    raise( "Unknown bytecode" )

            if isinstance(bc, list) :
                for j in bc :
                    self.__bc.append( (j[0], BC( jvm.JVMFormat(j[1]) ) ) )
            else :
                self.__bc.append( (i, BC( bc )) )

    def ianalyze(self) :
        for i in self.get_bc() :
            i[1].analyze()

    def get_class(self, class_name) :
        for _, bc in self.__bc :
            if bc.get_class(class_name) == True :
                return bc
        return None

    def get_raw(self) :
        """Return raw format of all file"""
        l = []
        for _, bc in self.__bc :
            l.append( bc._get_raw() )
        return l

    def get_orig_raw(self) :
        return self.__orig_raw

    def get_method_descriptor(self, class_name, method_name, descriptor) :
        """
           Return the specific method

           @param class_name : the class name of the method
           @param method_name : the name of the method
           @param descriptor : the descriptor of the method
        """
        for file_name, bc in self.__bc :
            x = bc.get_method_descriptor( class_name, method_name, descriptor )
            if x != None :
                return x, bc
        return None, None

    def get_field_descriptor(self, class_name, field_name, descriptor) :
        """
           Return the specific field

           @param class_name : the class name of the field
           @param field_name : the name of the field
           @param descriptor : the descriptor of the field
        """
        for file_name, bc in self.__bc :
            x = bc.get_field_descriptor( class_name, field_name, descriptor )
            if x != None :
                return x, bc
        return None, None

    def get(self, name, val) :
        """
           Return the specific value for all files

           @param name :
           @param val :
        """
        if name == "file" :
            for file_name, bc in self.__bc :
                if file_name == val :
                    return bc

            return None
        else :
            l = []
            for file_name, bc in self.__bc :
                l.append( bc.get( name, val ) )

            return list( self._iterFlatten(l) )

    def gets(self, name) :
        """
           Return the specific value for all files

           @param name :
        """
        l = []
        for file_name, bc in self.__bc :
            l.append( bc.gets( name ) )

        return list( self._iterFlatten(l) )

    def get_vms(self) :
        return [ i[1].get_vm() for i in self.__bc ]

    def get_bc(self) :
        return self.__bc

    def show(self) :
        """
           Display all files
        """
        for _, bc in self.__bc :
            bc.show()

    def pretty_show(self) :
        """
           Display all files
        """
        for _, bc in self.__bc :
            bc.pretty_show()

class AndroguardS :
    """AndroguardS is the main object to abstract and manage differents formats but only per filename. In fact this class is just a wrapper to the main class Androguard

       @param filename : the filename to use (filename must be terminated by .class or .dex)
       @param raw : specify if the filename is a raw buffer (default : False)
    """
    def __init__(self, filename, raw=False) :
        self.__filename = filename
        self.__orig_a = Androguard( [ filename ], raw )
        self.__a = self.__orig_a.get( "file", filename )

    def get_orig_raw(self) :
        return self.__orig_a.get_orig_raw()[ self.__filename ]

    def get_vm(self) :
        """
           This method returns the VMFormat which correspond to the file

           @rtype: L{jvm.JVMFormat} or L{dvm.DalvikVMFormat}
        """
        return self.__a.get_vm()

    def save(self) :
        """
           Return the original format (with the modifications) into raw format

           @rtype: string
        """
        return self.__a.save()

    def __getattr__(self, value) :
        try :
            return getattr(self.__orig_a, value)
        except AttributeError :
            return getattr(self.__a, value)
