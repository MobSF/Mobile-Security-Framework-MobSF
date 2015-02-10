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


import zlib, bz2
import math, json, re

def simhash(x) :
    import simhash
    return simhash.simhash(x)

def entropy(data):
    entropy = 0.0

    if len(data) == 0 :
        return entropy

    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

try :
    from ctypes import cdll, c_float, c_double, c_int, c_uint, c_void_p, Structure, addressof, cast, c_size_t

    #struct libsimilarity {
    #   void *orig;
    #   unsigned int size_orig;
    #   void *cmp;
    #   unsigned size_cmp;

    #   unsigned int *corig;
    #   unsigned int *ccmp;
    #   
    #   float res;
    #};

    class LIBSIMILARITY_T(Structure) :
        _fields_ = [("orig", c_void_p),
                    ("size_orig", c_size_t),
                    ("cmp", c_void_p),
                    ("size_cmp", c_size_t),

                    ("corig", c_size_t),
                    ("ccmp", c_size_t),

                    ("res", c_float),
                ]    
    
    def new_zero_native() :
        return c_size_t( 0 )
    
    NATIVE_LIB = True
except :
    NATIVE_LIB = False

def new_zero_python() :
    return 0

ZLIB_COMPRESS         =     0
BZ2_COMPRESS          =     1
SMAZ_COMPRESS         =     2
LZMA_COMPRESS         =     3
XZ_COMPRESS           =     4
SNAPPY_COMPRESS       =     5
VCBLOCKSORT_COMPRESS  =     6

H_COMPRESSOR = { "BZ2" :    BZ2_COMPRESS,
                 "ZLIB" :   ZLIB_COMPRESS,
                 "LZMA" :   LZMA_COMPRESS,
                 "XZ" :     XZ_COMPRESS,
                 "SNAPPY" : SNAPPY_COMPRESS,
               }

HR_COMPRESSOR = {
                BZ2_COMPRESS :      "BZ2",
                ZLIB_COMPRESS :     "ZLIB",
                LZMA_COMPRESS :     "LZMA",
                XZ_COMPRESS :       "XZ",
                SNAPPY_COMPRESS :   "SNAPPY",
        }

class SIMILARITYBase(object) :
    def __init__(self, native_lib=False) :
        self.ctype = ZLIB_COMPRESS

        self.__caches = {
           ZLIB_COMPRESS : {},
           BZ2_COMPRESS : {},
           SMAZ_COMPRESS : {},
           LZMA_COMPRESS : {},
           XZ_COMPRESS : {},
           SNAPPY_COMPRESS : {},
           VCBLOCKSORT_COMPRESS : {},
        }
        
        self.__rcaches = {
           ZLIB_COMPRESS : {},
           BZ2_COMPRESS : {},
           SMAZ_COMPRESS : {},
           LZMA_COMPRESS : {},
           XZ_COMPRESS : {},
           SNAPPY_COMPRESS : {},
           VCBLOCKSORT_COMPRESS : {},
        }

        self.__ecaches = {}
        
        self.level = 9

        if native_lib == True :
            self.new_zero = new_zero_native
        else :
            self.new_zero = new_zero_python
    
    def set_level(self, level) :
        self.level = level

    def get_in_caches(self, s) :
        try :
            return self.__caches[ self.ctype ][ zlib.adler32( s ) ]
        except KeyError :
            return self.new_zero()

    def get_in_rcaches(self, s1, s2) :
        try :
            return self.__rcaches[ self.ctype ][ zlib.adler32( s1 + s2 ) ]
        except KeyError :
            try :
                return self.__rcaches[ self.ctype ][ zlib.adler32( s2 + s1 ) ]
            except KeyError :
                return -1, -1

    def add_in_caches(self, s, v) :
        h = zlib.adler32( s )
        if h not in self.__caches[ self.ctype ] :
            self.__caches[ self.ctype ][ h ] = v
    
    def add_in_rcaches(self, s, v, r) :
        h = zlib.adler32( s )
        if h not in self.__rcaches[ self.ctype ] :
            self.__rcaches[ self.ctype ][ h ] = (v, r)

    def clear_caches(self) :
        for i in self.__caches :
            self.__caches[i] = {}

    def add_in_ecaches(self, s, v, r) :
        h = zlib.adler32( s )
        if h not in self.__ecaches :
            self.__ecaches[ h ] = (v, r)
    
    def get_in_ecaches(self, s1) :
        try :
            return self.__ecaches[ zlib.adler32( s1 ) ]
        except KeyError :
            return -1, -1
    
    def __nb_caches(self, caches) :
        nb = 0
        for i in caches :
            nb += len(caches[i])
        return nb

    def set_compress_type(self, t):
        self.ctype = t

    def show(self) :
        print "ECACHES", len(self.__ecaches)
        print "RCACHES", self.__nb_caches( self.__rcaches )
        print "CACHES", self.__nb_caches( self.__caches )


class SIMILARITYNative(SIMILARITYBase) :
    def __init__(self, path="./libsimilarity/libsimilarity.so") :
        super(SIMILARITYNative, self).__init__(True)

        self._u = cdll.LoadLibrary( path )

        self._u.compress.restype = c_uint
        self._u.ncd.restype = c_int
        self._u.ncs.restype = c_int
        self._u.cmid.restype = c_int
        self._u.entropy.restype = c_double
        self._u.levenshtein.restype = c_uint
        
        self._u.kolmogorov.restype = c_uint
        self._u.bennett.restype = c_double
        self._u.RDTSC.restype = c_double

        self.__libsim_t = LIBSIMILARITY_T()

        self.set_compress_type( ZLIB_COMPRESS )

    def raz(self) :
        del self._u
        del self.__libsim_t

    def compress(self, s1) :
        res = self._u.compress( self.level, cast( s1, c_void_p ), len( s1 ) )
        return res

    def _sim(self, s1, s2, func) :
        end, ret = self.get_in_rcaches( s1, s2 )
        if end != -1 :
            return end, ret

        self.__libsim_t.orig = cast( s1, c_void_p )
        self.__libsim_t.size_orig = len(s1)

        self.__libsim_t.cmp = cast( s2, c_void_p )
        self.__libsim_t.size_cmp = len(s2)

        corig = self.get_in_caches(s1)
        ccmp = self.get_in_caches(s2)
        
        self.__libsim_t.corig = addressof( corig )
        self.__libsim_t.ccmp = addressof( ccmp )

        ret = func( self.level, addressof( self.__libsim_t ) )

        self.add_in_caches(s1, corig)
        self.add_in_caches(s2, ccmp)
        self.add_in_rcaches(s1+s2, self.__libsim_t.res, ret)

        return self.__libsim_t.res, ret

    def ncd(self, s1, s2) :
        return self._sim( s1, s2, self._u.ncd )

    def ncs(self, s1, s2) :
        return self._sim( s1, s2, self._u.ncs )

    def cmid(self, s1, s2) :
        return self._sim( s1, s2, self._u.cmid )
    
    def kolmogorov(self, s1) :
        ret = self._u.kolmogorov( self.level, cast( s1, c_void_p ), len( s1 ) )
        return ret, 0
    
    def bennett(self, s1) :
        ret = self._u.bennett( self.level, cast( s1, c_void_p ), len( s1 ) )
        return ret, 0

    def entropy(self, s1) :
        end, ret = self.get_in_ecaches( s1 )
        if end != -1 :
            return end, ret

        res = self._u.entropy( cast( s1, c_void_p ), len( s1 ) )
        self.add_in_ecaches( s1, res, 0 )
        
        return res, 0

    def RDTSC(self) :
        return self._u.RDTSC()

    def levenshtein(self, s1, s2) :
        res = self._u.levenshtein( cast( s1, c_void_p ), len( s1 ), cast( s2, c_void_p ), len( s2 ) )
        return res, 0
    
    def set_compress_type(self, t):
        self.ctype = t
        self._u.set_compress_type(t)

class SIMILARITYPython(SIMILARITYBase) :
    def __init__(self) :
        super(SIMILARITYPython, self).__init__()
    
    def set_compress_type(self, t):
        self.ctype = t
        if self.ctype != ZLIB_COMPRESS and self.ctype != BZ2_COMPRESS :
            print "warning: compressor %s is not supported (use zlib default compressor)" % HR_COMPRESSOR[ t ]
            self.ctype = ZLIB_COMPRESS

    def compress(self, s1) :
        return len(self._compress(s1))

    def _compress(self, s1) :
        if self.ctype == ZLIB_COMPRESS :
            return zlib.compress( s1, self.level )
        elif self.ctype == BZ2_COMPRESS :
            return bz2.compress( s1, self.level )
       
    def _sim(self, s1, s2, func) :
        end, ret = self.get_in_rcaches( s1, s2 )
        if end != -1 :
            return end, ret

        corig = self.get_in_caches(s1)
        ccmp = self.get_in_caches(s2)
        
        res, corig, ccmp, ret = func( s1, s2, corig, ccmp )

        self.add_in_caches(s1, corig)
        self.add_in_caches(s2, ccmp)
        self.add_in_rcaches(s1+s2, res, ret)

        return res, ret

    def _ncd(self, s1, s2, s1size=0, s2size=0) :
        if s1size == 0 :
            s1size = self.compress(s1)

        if s2size == 0 :
            s2size = self.compress(s2)

        s3size = self.compress(s1+s2)

        smax = max(s1size, s2size)
        smin = min(s1size, s2size)

        res = (abs(s3size - smin)) / float(smax)
        if res > 1.0 :
            res = 1.0

        return res, s1size, s2size, 0

    def ncd(self, s1, s2) :
        return self._sim( s1, s2, self._ncd )

    def ncs(self, s1, s2) :
        return self._sim( s1, s2, self._u.ncs )

    def entropy(self, s1) :
        end, ret = self.get_in_ecaches( s1 )
        if end != -1 :
            return end, ret

        res = entropy( s1 )
        self.add_in_ecaches( s1, res, 0 )

        return res, 0

    def levenshtein(self, a, b):
        "Calculates the Levenshtein distance between a and b."
        n, m = len(a), len(b)
        if n > m:
            # Make sure n <= m, to use O(min(n,m)) space
            a,b = b,a
            n,m = m,n

        current = range(n+1)
        for i in range(1,m+1):
            previous, current = current, [i]+[0]*n
            for j in range(1,n+1):
                add, delete = previous[j]+1, current[j-1]+1
                change = previous[j-1]
                if a[j-1] != b[i-1]:
                    change = change + 1
                current[j] = min(add, delete, change)

        return current[n]

class SIMILARITY :
    def __init__(self, path="./libsimilarity/libsimilarity.so", native_lib=True) :
        if native_lib == True and NATIVE_LIB == True:
            try :
                self.s = SIMILARITYNative( path )
            except : 
                self.s = SIMILARITYPython()
        else :
            self.s = SIMILARITYPython()

    def raz(self) :
        return self.s.raz()

    def set_level(self, level) :
        return self.s.set_level(level)

    def compress(self, s1) :
        return self.s.compress(s1)

    def ncd(self, s1, s2) :
        return self.s.ncd(s1, s2)

    def ncs(self, s1, s2) :
        return self.s.ncs(s1, s2)

    def cmid(self, s1, s2) :
        return self.s.cmid(s1, s2)
    
    def kolmogorov(self, s1) :
        return self.s.kolmogorov(s1)
    
    def bennett(self, s1) :
        return self.s.bennett(s1)

    def entropy(self, s1) :
        return self.s.entropy(s1)

    def RDTSC(self) :
        return self.s.RDTSC()

    def levenshtein(self, s1, s2) :
        return self.s.levenshtein(s1, s2)
    
    def set_compress_type(self, t):
        return self.s.set_compress_type(t)

    def show(self) :
        self.s.show()


class DBFormat:
    def __init__(self, filename):
        self.filename = filename
       
        self.D = {}

        fd = None

        try :
            fd = open(self.filename, "r+")
            self.D = json.load( fd )
            fd.close()
        except IOError :
            print "Impossible to open filename: " + filename
            self.D = {}

        self.H = {}
        self.N = {}

        for i in self.D :
            self.H[i] = {}
            for j in self.D[i] :
                if j == "NAME" :
                    self.N[ i ] = re.compile( self.D[i][j] )
                    continue

                self.H[i][j] = {}
                for k in self.D[i][j] :
                    if isinstance(self.D[i][j][k], dict) :
                        self.H[i][j][k] = set()
                        for e in self.D[i][j][k].keys() :
                            self.H[i][j][k].add( long(e) )

    def add_name(self, name, value) :
        if name not in self.D :
            self.D[ name ] = {}

        self.D[ name ]["NAME"] = value

    def add_element(self, name, sname, sclass, size, elem):
        try :
            if elem not in self.D[ name ][ sname ][ sclass ] :
                self.D[ name ][ sname ][ sclass ][ elem ] = size
                self.D[ name ][ sname ][ "SIZE" ] += size

        except KeyError :
            if name not in self.D :
                self.D[ name ] = {}
                self.D[ name ][ sname ] = {}
                self.D[ name ][ sname ][ "SIZE" ] = 0
                self.D[ name ][ sname ][ sclass ] = {}
            elif sname not in self.D[ name ] :
                self.D[ name ][ sname ] = {}
                self.D[ name ][ sname ][ "SIZE" ] = 0
                self.D[ name ][ sname ][ sclass ] = {}
            elif sclass not in self.D[ name ][ sname ] :
                self.D[ name ][ sname ][ sclass ] = {}

            self.D[ name ][ sname ][ "SIZE" ] += size
            self.D[ name ][ sname ][ sclass ][ elem ] = size

    def is_present(self, elem) :
        for i in self.D :
            if elem in self.D[i] :
                return True, i
        return False, None

    def elems_are_presents(self, elems) :
        ret = {}
        info = {}

        for i in self.H:
            ret[i] = {}
            info[i] = {}

            for j in self.H[i] :
                ret[i][j] = {}
                info[i][j] = {}

                for k in self.H[i][j] :
                    val = [self.H[i][j][k].intersection(elems), len(self.H[i][j][k]), 0, 0]

                    size = 0
                    for z in val[0] :
                        size += self.D[i][j][k][str(z)]

                    val[2] = (float(len(val[0]))/(val[1])) * 100
                    val[3] = size

                    if val[3] != 0 :
                        ret[i][j][k] = val

                info[i][j][ "SIZE" ] = self.D[i][j]["SIZE"]

        return ret, info

    def classes_are_presents(self, classes) :
        m = set()
        for j in classes :
            for i in self.N :
                if self.N[i].search(j) != None :
                    m.add( i )
        return m

    def show(self) :
        for i in self.D :
            print i, ":"
            for j in self.D[i] :
                print "\t", j, len(self.D[i][j])
                for k in self.D[i][j] :
                    print "\t\t", k, len(self.D[i][j][k])

    def save(self):
        fd = open(self.filename, "w")
        json.dump(self.D, fd)
        fd.close()