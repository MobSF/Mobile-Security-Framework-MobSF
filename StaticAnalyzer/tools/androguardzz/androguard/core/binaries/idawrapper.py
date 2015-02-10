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


from idaapi import *
from idautils import *
from idc import *

from SimpleXMLRPCServer import SimpleXMLRPCServer
import cPickle

def is_connected() :
    return True 

def wrapper_get_raw(oops) :
    F = {}
    for function_ea in Functions() :

        F[ function_ea ] = []

        f_start = function_ea
        f_end = GetFunctionAttr(function_ea, FUNCATTR_END)
        
        edges = set()
        boundaries = set((f_start,))

        F[ function_ea ].append( GetFunctionName(function_ea) )

        for head in Heads(f_start, f_end) :
            if isCode( GetFlags( head ) ) :
                F[ function_ea ].append( (head, GetMnem(head), GetOpnd(head, 0), GetOpnd(head, 1), GetOpnd(head, 2)) )

                refs = CodeRefsFrom(head, 0)
                refs = set(filter(lambda x: x>=f_start and x<=f_end, refs))
                
                if refs :
                    next_head = NextHead(head, f_end)
                    if isFlow(GetFlags(next_head)):
                        refs.add(next_head)
                                                      
                    # Update the boundaries found so far.
                    boundaries.update(refs)
                                                                                                  
                    # For each of the references found, and edge is
                    # created.
                    for r in refs:
                    # If the flow could also come from the address
                    # previous to the destination of the branching
                    # an edge is created.
                        if isFlow(GetFlags(r)):
                            edges.add((PrevHead(r, f_start), r))
                        edges.add((head, r))
        
        #print edges, boundaries
        # Let's build the list of (startEA, startEA) couples
        # for each basic block
        sorted_boundaries = sorted(boundaries, reverse = True)
        end_addr = PrevHead(f_end, f_start)
        bb_addr = []
        for begin_addr in sorted_boundaries:
            bb_addr.append((begin_addr, end_addr))
            # search the next end_addr which could be
            # farther than just the previous head
            # if data are interlaced in the code
            # WARNING: it assumes it won't epicly fail ;)
            end_addr = PrevHead(begin_addr, f_start)
            while not isCode(GetFlags(end_addr)):
                end_addr = PrevHead(end_addr, f_start)
        # And finally return the result
        bb_addr.reverse()
        F[ function_ea ].append( (bb_addr, sorted(edges)) )

    return cPickle.dumps( F )

def wrapper_Heads(oops) :
    start, end = cPickle.loads(oops)
    return cPickle.dumps( [ x for x in Heads( start, end ) ] )

def wrapper_Functions(oops) :
    return cPickle.dumps( [ x for x in Functions() ] )

def wrapper_get_function(oops) :
    name = cPickle.loads(oops)
    for function_ea in Functions() :
        if GetFunctionName(function_ea) == name :
            return cPickle.dumps( function_ea )
    return cPickle.dumps( -1 )

def wrapper_quit(oops) :
    qexit(0)

class IDAWrapper :
    def _dispatch(self, x, params) :
        #fd = open("toto.txt", "w")
        #fd.write( x + "\n" )
        #fd.write( str(type(params[0])) + "\n" )
        #fd.close()
        
        params = cPickle.loads( *params )
        if isinstance(params, tuple) == False :
            params = (params,)

        import types
        import idautils
        import idc

        #[getattr(idautils, a, None) for a in dir(idautils) if isinstance(getattr(idautils, a, None) , types.FunctionType)]
        for a in dir(idautils) :
            #fd.write( "\t" + a + "\n" )
            if a == x :
                z = getattr(idautils, a, None)
                ret = z( *params )
                if type(ret).__name__=='generator' :
                    return cPickle.dumps( [ i for i in ret ] )
                return cPickle.dumps( ret )

        for a in dir(idc) :
            #fd.write( "\t" + a + "\n" )
            if a == x :
                z = getattr(idc, a, None)
                ret = z( *params )
                if type(ret).__name__=='generator' :
                    return cPickle.dumps( [ i for i in ret ] )
                return cPickle.dumps( ret )

        return cPickle.dumps( [] )

def main() :
    autoWait()
    ea = ScreenEA()

    server = SimpleXMLRPCServer(("localhost", 9000))
    server.register_function(is_connected, "is_connected")
    
    server.register_function(wrapper_get_raw, "get_raw")
    server.register_function(wrapper_get_function, "get_function")
    server.register_function(wrapper_Heads, "Heads")
    server.register_function(wrapper_Functions, "Functions")
    
    server.register_instance(IDAWrapper())
    
    server.register_function(wrapper_quit, "quit")
    server.serve_forever()

    qexit(0)

main()
