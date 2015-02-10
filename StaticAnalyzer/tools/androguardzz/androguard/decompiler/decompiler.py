# This file is part of Androguard.
#
# Copyright (C) 2011, Anthony Desnos <desnos at t0t0.fr>
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

from subprocess import Popen, PIPE, STDOUT

import tempfile
import os

from androguard.core.androconf import rrmdir
from androguard.decompiler.dad import decompile

PYGMENTS = True
try:
    from pygments.filter import Filter
    from pygments import highlight
    from pygments.lexers import get_lexer_by_name
    from pygments.formatters import HtmlFormatter, TerminalFormatter
    from pygments.token import Token, Text, STANDARD_TYPES
except ImportError:
    PYGMENTS = False
    class Filter:
        pass

class DecompilerDex2Jad :
    def __init__(self, vm, path_dex2jar = "./decompiler/dex2jar/", bin_dex2jar = "dex2jar.sh", path_jad="./decompiler/jad/", bin_jad="jad", tmp_dir="/tmp/") :
        self.classes = {}
        self.classes_failed = []
        
        pathtmp = tmp_dir
        if not os.path.exists(pathtmp) :
            os.makedirs( pathtmp )

        fd, fdname = tempfile.mkstemp( dir=pathtmp )
        fd = os.fdopen(fd, "w+b")
        fd.write( vm.get_buff() )
        fd.flush()
        fd.close()
       
        compile = Popen([ path_dex2jar + bin_dex2jar, fdname ], stdout=PIPE, stderr=STDOUT)        
        stdout, stderr = compile.communicate()
        os.unlink( fdname )

        pathclasses = fdname + "dex2jar/"
        compile = Popen([ "unzip", fdname + "_dex2jar.jar", "-d", pathclasses ], stdout=PIPE, stderr=STDOUT)        
        stdout, stderr = compile.communicate()
        os.unlink( fdname + "_dex2jar.jar" )

        for root, dirs, files in os.walk( pathclasses, followlinks=True ) :
            if files != [] :
                for f in files :
                    real_filename = root
                    if real_filename[-1] != "/" :
                        real_filename += "/"
                    real_filename += f
                    
                    compile = Popen([ path_jad + bin_jad, "-o", "-d", root, real_filename ], stdout=PIPE, stderr=STDOUT)
                    stdout, stderr = compile.communicate()

        for i in vm.get_classes() :
            fname = pathclasses + "/" + i.get_name()[1:-1] + ".jad"
            if os.path.isfile(fname) == True :
                fd = open(fname, "r")
                self.classes[ i.get_name() ] = fd.read() 
                fd.close()
            else :
                self.classes_failed.append( i.get_name() )
    
        rrmdir( pathclasses )

    def get_source_method(self, method):
        class_name = method.get_class_name()
        method_name = method.get_name()

        if class_name not in self.classes:
            return ""

        if PYGMENTS:
            lexer = get_lexer_by_name("java", stripall=True)
            lexer.add_filter(MethodFilter(method_name=method_name))
            formatter = TerminalFormatter()
            result = highlight(self.classes[class_name], lexer, formatter)
            return result

        return self.classes[class_name]

    def display_source(self, method):
        print self.get_source_method(method)

    def get_all(self, class_name) :
        if class_name not in self.classes :
            return ""

        if PYGMENTS:
            lexer = get_lexer_by_name("java", stripall=True)
            formatter = TerminalFormatter()
            result = highlight(self.classes[class_name], lexer, formatter)
            return result
        return self.classes[class_name]

    def display_all(self, _class) :
        print self.get_all( _class.get_name() )

class DecompilerDed :
    def __init__(self, vm, path="./decompiler/ded/", bin_ded = "ded.sh", tmp_dir="/tmp/") :
        self.classes = {}
        self.classes_failed = []

        pathtmp = tmp_dir
        if not os.path.exists(pathtmp) :
            os.makedirs( pathtmp )

        fd, fdname = tempfile.mkstemp( dir=pathtmp )
        fd = os.fdopen(fd, "w+b")
        fd.write( vm.get_buff() )
        fd.flush()
        fd.close()
       
        dirname = tempfile.mkdtemp(prefix=fdname + "-src")
        compile = Popen([ path + bin_ded, "-c", "-o", "-d", dirname, fdname ], stdout=PIPE, stderr=STDOUT)        
        stdout, stderr = compile.communicate()
        os.unlink( fdname )

        findsrc = None 
        for root, dirs, files in os.walk( dirname + "/optimized-decompiled/" ) :
            if dirs != [] :
                for f in dirs :
                    if f == "src" :
                        findsrc = root
                        if findsrc[-1] != "/" :
                            findsrc += "/"
                        findsrc += f
                        break
            if findsrc != None :
                break
        
        for i in vm.get_classes() :
            fname = findsrc + "/" + i.get_name()[1:-1] + ".java"
            #print fname
            if os.path.isfile(fname) == True :
                fd = open(fname, "r")
                self.classes[ i.get_name() ] = fd.read() 
                fd.close()
            else :
                self.classes_failed.append( i.get_name() )
      
        rrmdir( dirname )

    def get_source_method(self, method):
        class_name = method.get_class_name()
        method_name = method.get_name()

        if class_name not in self.classes:
            return ""

        lexer = get_lexer_by_name("java", stripall=True)
        lexer.add_filter(MethodFilter(method_name=method_name))
        formatter = TerminalFormatter()
        result = highlight(self.classes[class_name], lexer, formatter)
        return result

    def display_source(self, method) :
        print self.get_source_method(method)

    def get_all(self, class_name) :
        if class_name not in self.classes :
            return ""

        lexer = get_lexer_by_name("java", stripall=True)
        formatter = TerminalFormatter()
        result = highlight(self.classes[class_name], lexer, formatter)
        return result
    
    def display_all(self, _class) :
        print self.get_all( _class.get_name() )

class MethodFilter(Filter):
    def __init__(self, **options):
        Filter.__init__(self, **options)
        
        self.method_name = options["method_name"]
        #self.descriptor = options["descriptor"]

        self.present = False
        self.get_desc = True #False

    def filter(self, lexer, stream) :
        a = []
        l = []
        rep = []

        for ttype, value in stream:
            if self.method_name == value and (ttype is Token.Name.Function or ttype is Token.Name) :
                #print ttype, value

                item_decl = -1
                for i in range(len(a)-1, 0, -1) :
                    if a[i][0] is Token.Keyword.Declaration :
                        if a[i][1] != "class" :
                            item_decl = i
                        break
               
                if item_decl != -1 :
                    self.present = True
                    l.extend( a[item_decl:] )
        

            if self.present and ttype is Token.Keyword.Declaration :
                item_end = -1
                for i in range(len(l)-1, 0, -1) :
                    if l[i][0] is Token.Operator and l[i][1] == "}" :
                        item_end = i
                        break
               
                if item_end != -1 :
                    rep.extend( l[:item_end+1] )
                    l = []
                    self.present = False
                
            if self.present :
                l.append( (ttype, value) )

            a.append( (ttype, value) )

        
        if self.present :
            nb = 0
            item_end = -1
            for i in range(len(l)-1, 0, -1) :
                if l[i][0] is Token.Operator and l[i][1] == "}" :
                    nb += 1
                    if nb == 2 :
                        item_end = i
                        break
            
            rep.extend( l[:item_end+1] )
            
        return rep


class DecompilerDAD:
    def __init__(self, vm, vmx):
        self.vm = vm
        self.vmx = vmx

    def get_source_method(self, m):
        mx = self.vmx.get_method(m)
        z = decompile.DvMethod(mx)
        z.process()

        result = z.get_source()

        return result

    def display_source(self, m):
        result = self.get_source_method(m)

        if PYGMENTS:
            lexer = get_lexer_by_name("java", stripall=True)
            formatter = TerminalFormatter()
            result = highlight(result, lexer, formatter)
        print result

    def get_source_class(self, _class):
        c = decompile.DvClass(_class, self.vmx)
        c.process()

        result = c.get_source()

        return result

    def display_all(self, _class):
        result = self.get_source_class(_class)

        if PYGMENTS:
            lexer = get_lexer_by_name("java", stripall=True)
            formatter = TerminalFormatter()
            result = highlight(result, lexer, formatter)
        print result

    def get_all(self, class_name):
        pass
