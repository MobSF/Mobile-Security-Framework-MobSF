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

from subprocess import Popen, PIPE, STDOUT

import os, sys
import xmlrpclib

import cPickle

class _Method :
    def __init__(self, proxy, name) :
        self.proxy = proxy
        self.name = name
    
    def __call__(self, *args):
        #print "CALL", self.name, args
        z = getattr( self.proxy, self.name, None )
        #print "SEND", repr(cPickle.dumps( args ) )
       
        try :
            if len(args) == 1 :
                ret = z( cPickle.dumps( args[0] ) )
            else :
                ret = z( cPickle.dumps( args ) )
            #print "RECEIVE", repr(ret)
            return cPickle.loads( ret )
        except xmlrpclib.ProtocolError :
            return []

class MyXMLRPC :
    def __init__(self, proxy) :
        self.proxy = proxy

    def __getattr__(self, name) :
        return _Method(self.proxy, name)

class BasicBlock :
    def __init__(self, ins) :
        self.ins = ins

    def show(self) :
        for i in self.ins :
            print i

class Function :
    def __init__(self, name, start_ea, instructions, information) :
        #print name, start_ea
                
        self.name = name
        self.start_ea = start_ea
        self.information = information
        self.basic_blocks = []
        self.instructions = instructions

        r = {}
        idx = 0
        for i in instructions :
            r[ i[0] ] = idx
            idx += 1

        for i in information[0] :
            try :
                start = r[i[0]]
                end = r[i[1]] + 1
                self.basic_blocks.append( BasicBlock( instructions[start:end] ) )
            except KeyError :
                pass

    def get_instructions(self) :
        return [ i for i in self.instructions ]

def run_ida(idapath, wrapper_init_path, binpath) :
    os.environ["TVHEADLESS"] = "1"
    pid = os.fork()
    if pid == 0:
        wrapper_path = "-S" + wrapper_init_path
        l = [ idapath, "-A", wrapper_path, binpath ]
        print l
        compile = Popen(l, stdout=open('/dev/null', 'w'), stderr=STDOUT)
        stdout, stderr = compile.communicate()
#        print stdout, stderr
        sys.exit(0)

class IDAPipe :
    def __init__(self, idapath, binpath, wrapper_init_path) :
        self.idapath = idapath
        self.binpath = binpath

        self.proxy = None
        
        run_ida(self.idapath, self.binpath, wrapper_init_path)

        while 1 :
            try :
                self.proxy = xmlrpclib.ServerProxy("http://localhost:9000/")
                self.proxy.is_connected()
                break
            except :
                pass
            
        #print self.proxy
        self.proxy = MyXMLRPC( self.proxy )

    def quit(self) :
        try :
            self.proxy.quit()
        except :
            pass

    def _build_functions(self, functions) :
        F = {}

        for i in functions :
            F[ i ] = Function( functions[i][0], i, functions[i][1:-1], functions[i][-1] )

        return F

    def get_quick_functions(self) :
        functions = self.get_raw()
        return self._build_functions( functions )

    def get_raw(self) :
        return self.proxy.get_raw()

    def get_nb_functions(self) :
        return len(self.proxy.Functions())

    def get_functions(self) :
        for function_ea in self.proxy.Functions() :
            self.get_function_addr( function_ea )

    def get_function_name(self, name) :
        function_ea = self.proxy.get_function( name )
        self.get_function_addr( function_ea )

    def get_function_addr(self, function_ea) :
        if function_ea == -1 :
            return

        f_start = function_ea 
        f_end = self.proxy.GetFunctionAttr(function_ea, 4) #FUNCATTR_END)
        
        edges = set()
        boundaries = set((f_start,))
        
        for head in self.proxy.Heads(f_start, f_end) :
            if self.proxy.isCode( self.proxy.GetFlags( head ) ) :
                refs = self.proxy.CodeRefsFrom(head, 0)
                refs = set(filter(lambda x: x>=f_start and x<=f_end, refs))

                #print head, f_end, refs, self.proxy.GetMnem(head), self.proxy.GetOpnd(head, 0), self.proxy.GetOpnd(head, 1)

                if refs :
                    next_head = self.proxy.NextHead(head, f_end)
                    if self.proxy.isFlow(self.proxy.GetFlags(next_head)):
                        refs.add(next_head)
                                                      
                    # Update the boundaries found so far.
                    boundaries.update(refs)
                                                                                                  
                    # For each of the references found, and edge is
                    # created.
                    for r in refs:
                    # If the flow could also come from the address
                    # previous to the destination of the branching
                    # an edge is created.
                        if self.proxy.isFlow(self.proxy.GetFlags(r)):
                            edges.add((self.proxy.PrevHead(r, f_start), r))
                        edges.add((head, r))
                

        #print edges, boundaries
        # Let's build the list of (startEA, startEA) couples
        # for each basic block
        sorted_boundaries = sorted(boundaries, reverse = True)
        end_addr = self.proxy.PrevHead(f_end, f_start)
        bb_addr = []
        for begin_addr in sorted_boundaries:
            bb_addr.append((begin_addr, end_addr))
            # search the next end_addr which could be
            # farther than just the previous head
            # if data are interlaced in the code
            # WARNING: it assumes it won't epicly fail ;)
            end_addr = self.proxy.PrevHead(begin_addr, f_start)
            while not self.proxy.isCode(self.proxy.GetFlags(end_addr)):
                end_addr = self.proxy.PrevHead(end_addr, f_start)
        # And finally return the result
        bb_addr.reverse()
        #print bb_addr, sorted(edges)

def display_function(f) :
    print f, f.name, f.information

    for i in f.basic_blocks :
        print i
        i.show()
