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

class CheckSumText :
    def __init__(self, s1, sim) :
        self.s1 = s1
        self.sim = sim
        self.buff = s1.string
        self.entropy = 0.0
        self.signature = None
        
    def get_signature(self) :
        if self.signature == None :
            raise("ooo")
            self.signature_entropy, _ = self.sim.entropy( self.signature )

        return self.signature
    
    def get_signature_entropy(self) :
        if self.signature == None :
            raise("ooo")
            self.signature_entropy, _ = self.sim.entropy( self.signature )

        return self.signature_entropy
        
    def get_entropy(self) :
        return self.entropy

    def get_buff(self) :
        return self.buff

def filter_checksum_meth_basic( m1, sim ) :
    return CheckSumText( m1, sim )

def filter_sim_meth_basic( sim, m1, m2 ) :
    from similarity.similarity import XZ_COMPRESS
    sim.set_compress_type( XZ_COMPRESS )
    ncd1, _ = sim.ncd( m1.checksum.get_buff(), m2.checksum.get_buff() )
    return ncd1

    #ncd1, _ = sim.ncd( m1.checksum.get_signature(), m2.checksum.get_signature() )
    #ncd2, _ = sim.ncd( m1.checksum.get_buff(), m2.checksum.get_buff() )
    #return (ncd1 + ncd2) / 2.0

def filter_sort_meth_basic( j, x, value ) :
    z = sorted(x.iteritems(), key=lambda (k,v): (v,k))

    if get_debug() :
        for i in z :
            debug("\t %s %f" %(i[0].get_info(), i[1]))
 
    if z[:1][0][1] > value :
        return []

    return z[:1]

class Text :
    def __init__(self, e, el) :
        self.string = el

        nb = 0
        for i in range(0, len(self.string)) :
            if self.string[i] == " " :
                nb += 1
            else :
                break

        self.string = self.string[nb:]
        self.sha256 = None

    def get_info(self) :
        return "%d %s" % (len(self.string), repr(self.string))
        #return "%d %s" % (len(self.string), "")

    def set_checksum(self, fm) :
        self.sha256 = hashlib.sha256( fm.get_buff() ).hexdigest()
        self.checksum = fm
    
    def getsha256(self) :
        return self.sha256

def filter_element_meth_basic(el, e) :
    return Text( e, el )

class FilterNone :
    def skip(self, e):
        # remove whitespace elements
        if e.string.isspace() == True :
            return True

        if len(e.string) == 0 :
            return True

        return False

FILTERS_TEXT = {
    elsim.FILTER_ELEMENT_METH     : filter_element_meth_basic,
    elsim.FILTER_CHECKSUM_METH    : filter_checksum_meth_basic,
    elsim.FILTER_SIM_METH         : filter_sim_meth_basic,
    elsim.FILTER_SORT_METH        : filter_sort_meth_basic,
    elsim.FILTER_SORT_VALUE       : 0.6,
    elsim.FILTER_SKIPPED_METH     : FilterNone(),
    elsim.FILTER_SIM_VALUE_METH   : filter_sim_value_meth,
}

class ProxyText :
    def __init__(self, buff) :
        self.buff = buff

    def get_elements(self) :
        buff = self.buff.replace("\n"," ")
        # multi split elements: ".", ",", ":"
        import re
        for i in re.split('; |, |-|\.|\?|:', buff) :
            yield i
