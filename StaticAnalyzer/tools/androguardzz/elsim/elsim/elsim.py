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

import logging

ELSIM_VERSION = 0.2

log_elsim = logging.getLogger("elsim")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
log_elsim.addHandler(console_handler)
log_runtime = logging.getLogger("elsim.runtime")          # logs at runtime
log_interactive = logging.getLogger("elsim.interactive")  # logs in interactive functions
log_loading = logging.getLogger("elsim.loading")          # logs when loading

def set_debug() :
    log_elsim.setLevel( logging.DEBUG )

def get_debug() :
    return log_elsim.getEffectiveLevel() == logging.DEBUG

def warning(x):
    log_runtime.warning(x)

def error(x) :
    log_runtime.error(x)
    raise()

def debug(x) :
    log_runtime.debug(x)

from similarity.similarity import *

FILTER_ELEMENT_METH         =       "FILTER_ELEMENT_METH"
FILTER_CHECKSUM_METH        =       "FILTER_CHECKSUM_METH"      # function to checksum an element
FILTER_SIM_METH             =       "FILTER_SIM_METH"           # function to calculate the similarity between two elements
FILTER_SORT_METH            =       "FILTER_SORT_METH"          # function to sort all similar elements 
FILTER_SORT_VALUE           =       "FILTER_SORT_VALUE"         # value which used in the sort method to eliminate not interesting comparisons 
FILTER_SKIPPED_METH         =       "FILTER_SKIPPED_METH"       # object to skip elements
FILTER_SIM_VALUE_METH       =       "FILTER_SIM_VALUE_METH"     # function to modify values of the similarity

BASE                        =       "base"
ELEMENTS                    =       "elements"
HASHSUM                     =       "hashsum"
SIMILAR_ELEMENTS            =       "similar_elements"
HASHSUM_SIMILAR_ELEMENTS    =       "hash_similar_elements"
NEW_ELEMENTS                =       "newelements"
HASHSUM_NEW_ELEMENTS        =       "hash_new_elements"
DELETED_ELEMENTS            =       "deletedelements"
IDENTICAL_ELEMENTS          =       "identicalelements"
INTERNAL_IDENTICAL_ELEMENTS =       "internal identical elements"
SKIPPED_ELEMENTS            =       "skippedelements"
SIMILARITY_ELEMENTS         =       "similarity_elements"
SIMILARITY_SORT_ELEMENTS    =       "similarity_sort_elements"


class ElsimNeighbors :
    def __init__(self, x, ys) :
        import numpy as np
        from sklearn.neighbors import NearestNeighbors
        #print x, ys

        CI = np.array( [x.checksum.get_signature_entropy(), x.checksum.get_entropy()] )
        #print CI, x.get_info()
        #print

        for i in ys : 
            CI = np.vstack( (CI, [i.checksum.get_signature_entropy(), i.checksum.get_entropy()]) )

        #idx = 0
        #for i in np.array(CI)[1:] :
        #    print idx+1, i, ys[idx].get_info()
        #    idx += 1

        self.neigh = NearestNeighbors(2, 0.4)
        self.neigh.fit(np.array(CI))
        #print self.neigh.kneighbors( CI[0], len(CI) )

        self.CI = CI
        self.ys = ys

    def cmp_elements(self) :
        z = self.neigh.kneighbors( self.CI[0], 5 )
        l = []
        
        cmp_values = z[0][0]
        cmp_elements = z[1][0]
        idx = 1
        for i in cmp_elements[1:] :
            
            #if cmp_values[idx] > 1.0 :
            #    break

            #print i, cmp_values[idx], self.ys[ i - 1 ].get_info()
            l.append( self.ys[ i - 1 ] )
            idx += 1

        return l

def split_elements(el, els) :
    e1 = {}
    for i in els :
        e1[ i ] = el.get_associated_element( i )
    return e1

####
# elements : entropy raw, hash, signature
# 
# set elements : hash
# hash table elements : hash --> element
class Elsim :
    def __init__(self, e1, e2, F, T=None, C=None, libnative=True, libpath="elsim/elsim/similarity/libsimilarity/libsimilarity.so") :
        self.e1 = e1
        self.e2 = e2
        self.F = F
        self.compressor = SNAPPY_COMPRESS

        set_debug()

        if T != None :
            self.F[ FILTER_SORT_VALUE ] = T

        if isinstance(libnative, str) :
            libpath = libnative
            libnative = True

        self.sim = SIMILARITY( libpath, libnative )

        if C != None :
            if C in H_COMPRESSOR :
                self.compressor = H_COMPRESSOR[ C ]

            self.sim.set_compress_type( self.compressor )
        else :
            self.sim.set_compress_type( self.compressor )

        self.filters = {}

        self._init_filters()
        self._init_index_elements()
        self._init_similarity()
        self._init_sort_elements()
        self._init_new_elements()

    def _init_filters(self) :
        self.filters = {}
        self.filters[ BASE ]                = {}
        self.filters[ BASE ].update( self.F )
        self.filters[ ELEMENTS ]            = {}
        self.filters[ HASHSUM ]             = {}
        self.filters[ IDENTICAL_ELEMENTS ]  = set()

        self.filters[ SIMILAR_ELEMENTS ]    = []
        self.filters[ HASHSUM_SIMILAR_ELEMENTS ]    = []
        self.filters[ NEW_ELEMENTS ]        = set()
        self.filters[ HASHSUM_NEW_ELEMENTS ]        = []
        self.filters[ DELETED_ELEMENTS ]    = []
        self.filters[ SKIPPED_ELEMENTS ]     = []

        self.filters[ ELEMENTS ][ self.e1 ] = []
        self.filters[ HASHSUM ][ self.e1 ]  = []
        
        self.filters[ ELEMENTS ][ self.e2 ] = []
        self.filters[ HASHSUM ][ self.e2 ]  = []
        
        self.filters[ SIMILARITY_ELEMENTS ] = {}
        self.filters[ SIMILARITY_SORT_ELEMENTS ] = {}

        self.set_els = {}
        self.ref_set_els = {}
        self.ref_set_ident = {}

    def _init_index_elements(self) :
        self.__init_index_elements( self.e1, 1 )
        self.__init_index_elements( self.e2 )


    def __init_index_elements(self, ce, init=0) :
        self.set_els[ ce ] = set()
        self.ref_set_els[ ce ] = {}
        self.ref_set_ident[ce] = {}
        
        for ae in ce.get_elements() :
            e = self.filters[BASE][FILTER_ELEMENT_METH]( ae, ce )
       
            if self.filters[BASE][FILTER_SKIPPED_METH].skip( e ) :
                self.filters[ SKIPPED_ELEMENTS ].append( e )
                continue
          
            self.filters[ ELEMENTS ][ ce ].append( e )
            fm = self.filters[ BASE ][ FILTER_CHECKSUM_METH ]( e, self.sim )
            e.set_checksum( fm )
            
            sha256 = e.getsha256()
            self.filters[ HASHSUM ][ ce ].append( sha256 )
            
            if sha256 not in self.set_els[ ce ] :
                self.set_els[ ce ].add( sha256 )
                self.ref_set_els[ ce ][ sha256 ] = e
                
                self.ref_set_ident[ce][sha256] = []
            self.ref_set_ident[ce][sha256].append(e)


    def _init_similarity(self) :
        intersection_elements = self.set_els[ self.e2 ].intersection( self.set_els[ self.e1 ] ) 
        difference_elements = self.set_els[ self.e2 ].difference( intersection_elements )

        self.filters[IDENTICAL_ELEMENTS].update([ self.ref_set_els[ self.e1 ][ i ] for i in intersection_elements ])
        available_e2_elements = [ self.ref_set_els[ self.e2 ][ i ] for i in difference_elements ]

        # Check if some elements in the first file has been modified
        for j in self.filters[ELEMENTS][self.e1] :
            self.filters[ SIMILARITY_ELEMENTS ][ j ] = {}

            #debug("SIM FOR %s" % (j.get_info()))
            if j.getsha256() not in self.filters[HASHSUM][self.e2] :
                
                #eln = ElsimNeighbors( j, available_e2_elements )
                #for k in eln.cmp_elements() :
                for k in available_e2_elements :
                    #debug("%s" % k.get_info()) 
                    self.filters[SIMILARITY_ELEMENTS][ j ][ k ] = self.filters[BASE][FILTER_SIM_METH]( self.sim, j, k )
                    if j.getsha256() not in self.filters[HASHSUM_SIMILAR_ELEMENTS] :
                        self.filters[SIMILAR_ELEMENTS].append(j)
                        self.filters[HASHSUM_SIMILAR_ELEMENTS].append( j.getsha256() )

    def _init_sort_elements(self) :
        deleted_elements = []
        for j in self.filters[SIMILAR_ELEMENTS] :
            #debug("SORT FOR %s" % (j.get_info()))
            
            sort_h = self.filters[BASE][FILTER_SORT_METH]( j, self.filters[SIMILARITY_ELEMENTS][ j ], self.filters[BASE][FILTER_SORT_VALUE] )
            self.filters[SIMILARITY_SORT_ELEMENTS][ j ] = set( i[0] for i in sort_h )

            ret = True
            if sort_h == [] :
                ret = False

            if ret == False :
                deleted_elements.append( j )

        for j in deleted_elements :
            self.filters[ DELETED_ELEMENTS ].append( j )
            self.filters[ SIMILAR_ELEMENTS ].remove( j )
        
    def __checksort(self, x, y) :
        return y in self.filters[SIMILARITY_SORT_ELEMENTS][ x ]

    def _init_new_elements(self) :
        # Check if some elements in the second file are totally new !
        for j in self.filters[ELEMENTS][self.e2] :

            # new elements can't be in similar elements
            if j not in self.filters[SIMILAR_ELEMENTS] :
                # new elements hashes can't be in first file
                if j.getsha256() not in self.filters[HASHSUM][self.e1] :
                    ok = True
                    # new elements can't be compared to another one
                    for diff_element in self.filters[SIMILAR_ELEMENTS] :
                        if self.__checksort( diff_element, j ) :
                            ok = False
                            break

                    if ok :
                        if j.getsha256() not in self.filters[HASHSUM_NEW_ELEMENTS] :
                            self.filters[NEW_ELEMENTS].add( j )
                            self.filters[HASHSUM_NEW_ELEMENTS].append( j.getsha256() )

    def get_similar_elements(self) :
        """ Return the similar elements
            @rtype : a list of elements
        """
        return self.get_elem( SIMILAR_ELEMENTS )

    def get_new_elements(self) :
        """ Return the new elements
            @rtype : a list of elements
        """
        return self.get_elem( NEW_ELEMENTS )
    
    def get_deleted_elements(self) :
        """ Return the deleted elements
            @rtype : a list of elements
        """
        return self.get_elem( DELETED_ELEMENTS )
    
    def get_internal_identical_elements(self, ce) :
        """ Return the internal identical elements 
            @rtype : a list of elements
        """
        return self.get_elem( INTERNAL_IDENTICAL_ELEMENTS )

    def get_identical_elements(self) :
        """ Return the identical elements 
            @rtype : a list of elements
        """
        return self.get_elem( IDENTICAL_ELEMENTS )
    
    def get_skipped_elements(self) :
        return self.get_elem( SKIPPED_ELEMENTS )

    def get_elem(self, attr) :
        return [ x for x in self.filters[attr] ]

    def show_element(self, i, details=True) :
        print "\t", i.get_info()

        if details :
            if i.getsha256() == None :
                pass
            elif i.getsha256() in self.ref_set_els[self.e2]:
                if len(self.ref_set_ident[self.e2][i.getsha256()]) > 1:
                    for ident in self.ref_set_ident[self.e2][i.getsha256()]:
                        print "\t\t-->", ident.get_info()
                else:
                    print "\t\t-->", self.ref_set_els[self.e2][ i.getsha256() ].get_info()
            else :
                for j in self.filters[ SIMILARITY_SORT_ELEMENTS ][ i ] :
                    print "\t\t-->", j.get_info(), self.filters[ SIMILARITY_ELEMENTS ][ i ][ j ]
    
    def get_element_info(self, i) :
        
        l = []

        if i.getsha256() == None :
            pass
        elif i.getsha256() in self.ref_set_els[self.e2] :
            l.append( [ i, self.ref_set_els[self.e2][ i.getsha256() ] ] )
        else :
            for j in self.filters[ SIMILARITY_SORT_ELEMENTS ][ i ] :
                l.append( [i, j, self.filters[ SIMILARITY_ELEMENTS ][ i ][ j ] ] )
        return l

    def get_associated_element(self, i) :
        return list(self.filters[ SIMILARITY_SORT_ELEMENTS ][ i ])[0]

    def get_similarity_value(self, new=True) :
        values = []

        self.sim.set_compress_type( BZ2_COMPRESS )

        for j in self.filters[SIMILAR_ELEMENTS] :
            k = self.get_associated_element( j )
            value = self.filters[BASE][FILTER_SIM_METH]( self.sim, j, k )
            # filter value
            value = self.filters[BASE][FILTER_SIM_VALUE_METH]( value )

            values.append( value )

        values.extend( [ self.filters[BASE][FILTER_SIM_VALUE_METH]( 0.0 ) for i in self.filters[IDENTICAL_ELEMENTS] ] )
        if new == True :
            values.extend( [ self.filters[BASE][FILTER_SIM_VALUE_METH]( 1.0 ) for i in self.filters[NEW_ELEMENTS] ] )
        else :
            values.extend( [ self.filters[BASE][FILTER_SIM_VALUE_METH]( 1.0 ) for i in self.filters[DELETED_ELEMENTS] ] )

        self.sim.set_compress_type( self.compressor )

        similarity_value = 0.0
        for i in values :
            similarity_value += (1.0 - i)

        if len(values) == 0 :
            return 0.0

        return (similarity_value/len(values)) * 100

    def show(self): 
        print "Elements:"
        print "\t IDENTICAL:\t", len(self.get_identical_elements())
        print "\t SIMILAR: \t", len(self.get_similar_elements())
        print "\t NEW:\t\t", len(self.get_new_elements())
        print "\t DELETED:\t", len(self.get_deleted_elements())
        print "\t SKIPPED:\t", len(self.get_skipped_elements())

        #self.sim.show()

ADDED_ELEMENTS = "added elements"
DELETED_ELEMENTS = "deleted elements"
LINK_ELEMENTS = "link elements"
DIFF = "diff"
class Eldiff :
    def __init__(self, elsim, F) :
        self.elsim = elsim
        self.F = F
       
        self._init_filters()
        self._init_diff()

    def _init_filters(self) :
        self.filters = {}

        self.filters[ BASE ]                = {}
        self.filters[ BASE ].update( self.F )
        self.filters[ ELEMENTS ]            = {}
        self.filters[ ADDED_ELEMENTS ] = {} 
        self.filters[ DELETED_ELEMENTS ] = {}
        self.filters[ LINK_ELEMENTS ] = {}

    def _init_diff(self) :
        for i, j in self.elsim.get_elements() :
            self.filters[ ADDED_ELEMENTS ][ j ] = []
            self.filters[ DELETED_ELEMENTS ][ i ] = []

            x = self.filters[ BASE ][ DIFF ]( i, j )

            self.filters[ ADDED_ELEMENTS ][ j ].extend( x.get_added_elements() )
            self.filters[ DELETED_ELEMENTS ][ i ].extend( x.get_deleted_elements() )

            self.filters[ LINK_ELEMENTS ][ j ] = i
            #self.filters[ LINK_ELEMENTS ][ i ] = j

    def show(self) :
        for bb in self.filters[ LINK_ELEMENTS ] : #print "la"
            print bb.get_info(), self.filters[ LINK_ELEMENTS ][ bb ].get_info()
            
            print "Added Elements(%d)" % (len(self.filters[ ADDED_ELEMENTS ][ bb ]))
            for i in self.filters[ ADDED_ELEMENTS ][ bb ] :
                print "\t",
                i.show()

            print "Deleted Elements(%d)" % (len(self.filters[ DELETED_ELEMENTS ][ self.filters[ LINK_ELEMENTS ][ bb ] ]))
            for i in self.filters[ DELETED_ELEMENTS ][ self.filters[ LINK_ELEMENTS ][ bb ] ] :
                print "\t",
                i.show()
            print

    def get_added_elements(self) :
        return self.filters[ ADDED_ELEMENTS ]

    def get_deleted_elements(self) :
        return self.filters[ DELETED_ELEMENTS ]
