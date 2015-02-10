#!/usr/bin/env python

# This file is part of Elsim
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Elsim is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Elsim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Elsim.  If not, see <http://www.gnu.org/licenses/>.

import hashlib

from elsim import error, warning, debug, set_debug, get_debug
import elsim

def filter_sim_value_meth( v ) :
    if v >= 0.2 :
        return 1.0
    return v

class CheckSumFunc :
    def __init__(self, f, sim) :
        self.f = f
        self.sim = sim
        self.buff = ""
        self.entropy = 0.0
        self.signature = None
      
        for i in self.f.get_instructions() :
            self.buff += i.get_mnemonic()
        
        self.entropy, _ = sim.entropy( self.buff )

    def get_signature(self) :
        if self.signature == None :
            self.signature = self.buff
            self.signature_entropy, _ = self.sim.entropy( self.signature )

        return self.signature
    
    def get_signature_entropy(self) :
        if self.signature == None :
            self.signature = self.buff
            self.signature_entropy, _ = self.sim.entropy( self.signature )
        
        return self.signature_entropy
        
    def get_entropy(self) :
        return self.entropy

    def get_buff(self) :
        return self.buff

def filter_checksum_meth_basic( f, sim ) :
    return CheckSumFunc( f, sim )

def filter_sim_meth_basic( sim, m1, m2 ) :
    #ncd1, _ = sim.ncd( m1.checksum.get_signature(), m2.checksum.get_signature() )
    ncd2, _ = sim.ncd( m1.checksum.get_buff(), m2.checksum.get_buff() )
    #return (ncd1 + ncd2) / 2.0
    return ncd2

def filter_sort_meth_basic( j, x, value ) :
    z = sorted(x.iteritems(), key=lambda (k,v): (v,k))

    if get_debug() :
        for i in z :
            debug("\t %s %f" %(i[0].get_info(), i[1]))
 
    if z[:1][0][1] > value :
        return []

    return z[:1]

class Instruction :
    def __init__(self, i) :
        self.mnemonic = i[1]

    def get_mnemonic(self) :
        return self.mnemonic

class Function :
    def __init__(self, e, el) :
        self.function = el

    def get_instructions(self) :
        for i in self.function.get_instructions() :
            yield Instruction(i)

    def get_nb_instructions(self) :
        return len(self.function.get_instructions())

    def get_info(self) :
        return "%s" % (self.function.name)

    def set_checksum(self, fm) :
        self.sha256 = hashlib.sha256( fm.get_buff() ).hexdigest()
        self.checksum = fm
    
    def getsha256(self) :
        return self.sha256

def filter_element_meth_basic(el, e) :
    return Function( e, el )

class FilterNone :
    def skip(self, e) :
        #if e.get_nb_instructions() < 2 :
        #    return True
        return False

FILTERS_X86 = {
    elsim.FILTER_ELEMENT_METH     : filter_element_meth_basic,
    elsim.FILTER_CHECKSUM_METH    : filter_checksum_meth_basic,
    elsim.FILTER_SIM_METH         : filter_sim_meth_basic,
    elsim.FILTER_SORT_METH        : filter_sort_meth_basic,
    elsim.FILTER_SORT_VALUE       : 0.6,
    elsim.FILTER_SKIPPED_METH     : FilterNone(),
    elsim.FILTER_SIM_VALUE_METH   : filter_sim_value_meth,
}

class ProxyX86IDA :
    def __init__(self, ipipe) :
        self.functions = ipipe.get_quick_functions()

    def get_elements(self) :
        for i in self.functions :
            yield self.functions[ i ]
