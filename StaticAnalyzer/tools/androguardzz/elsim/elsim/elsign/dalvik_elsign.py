# This file is part of Elsim.
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

import sys
import json, base64

from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm

from androguard.core.analysis import analysis
from androguard.core import androconf

from libelsign.libelsign import Elsign, entropy

METHSIM = 0
CLASSSIM = 1

DEFAULT_SIGNATURE = analysis.SIGNATURE_L0_4
def get_signature(vmx, m) :
    return vmx.get_method_signature(m, predef_sign = DEFAULT_SIGNATURE).get_string()

def create_entropies(vmx, m) :
    default_signature = vmx.get_method_signature(m, predef_sign = DEFAULT_SIGNATURE).get_string()
    l = [ default_signature,
          entropy( vmx.get_method_signature(m, "L4", { "L4" : { "arguments" : ["Landroid"] } } ).get_string() ),
          entropy( vmx.get_method_signature(m, "L4", { "L4" : { "arguments" : ["Ljava"] } } ).get_string() ),
          entropy( vmx.get_method_signature(m, "hex" ).get_string() ),
          entropy( vmx.get_method_signature(m, "L2" ).get_string() ),
        ]

    return l

def FIX_FORMULA(x, z) :
    if "0" in x :
        x = x.replace("and", "&&")
        x = x.replace("or", "||")

        for i in range(0, z) :
            t = "%c" % (ord('a') + i)
            x = x.replace("%d" % i, t)

        return x
    return x

class ElfElsign :
    pass

class DalvikElsign :
    def __init__(self) :
        self.debug = False
        self.meth_elsign = Elsign()
        self.class_elsign = Elsign()

    def raz(self) :
        self.meth_elsign.raz()
        self.class_elsign.raz()

    def load_config(self, buff) :
    ################ METHOD ################
        methsim = buff["METHSIM"]
        
        self.meth_elsign.set_distance( str( methsim["DISTANCE"] ) )
        self.meth_elsign.set_method( str( methsim["METHOD"] ) )
        self.meth_elsign.set_weight( methsim["WEIGHTS"] )#[ 2.0, 1.2, 0.5, 0.1, 0.6 ] )
        #self.meth_elsign.set_cut_element( 1 )

        # NCD
        self.meth_elsign.set_sim_method( 0 )
        self.meth_elsign.set_threshold_low( methsim["THRESHOLD_LOW" ] )
        self.meth_elsign.set_threshold_high( methsim["THRESHOLD_HIGH"] )
        # SNAPPY
        self.meth_elsign.set_ncd_compression_algorithm( 5 )


    ################ CLASS ################
        classsim = buff["METHSIM"]
        
        self.class_elsign.set_distance( str( classsim["DISTANCE"] ) )
        self.class_elsign.set_method( str( classsim["METHOD"] ) )
        self.class_elsign.set_weight( classsim["WEIGHTS"] )#[ 2.0, 1.2, 0.5, 0.1, 0.6 ] )
        #self.class_elsign.set_cut_element( 1 )

        # NCD
        self.class_elsign.set_sim_method( 0 )
        self.class_elsign.set_threshold_low( classsim["THRESHOLD_LOW" ] )
        self.class_elsign.set_threshold_high( classsim["THRESHOLD_HIGH"] )
        # SNAPPY
        self.class_elsign.set_ncd_compression_algorithm( 5 )
      
    def add_signature(self, type_signature, x, y, z) :
        ret = None
        #print type_signature, x, y, z
        
        # FIX ENTROPIES (old version)
        for j in z :
            if len(j[0]) == 5 :
                j[0].pop(0)
       
        # FIX FORMULA (old version)
        y = FIX_FORMULA(y, len(z))

        if type_signature == METHSIM :
            ret = self.meth_elsign.add_signature(x, y, z)
        elif type_signature == CLASSSIM :
            ret = self.class_elsign.add_signature(x, y, z)

        return ret

    def set_debug(self, debug) :
        self.debug = debug
        x = { True : 1, False : 0 }
        self.meth_elsign.set_debug_log(x[debug])

    def load_meths(self, vm, vmx) :
        if self.debug :
            print "LM",
            sys.stdout.flush()

        # Add methods for METHSIM
        for method in vm.get_methods() :
            if method.get_length() < 15 :
                continue
                
            entropies = create_entropies(vmx, method)
            self.meth_elsign.add_element( entropies[0], entropies[1:] )
            del entropies
   
    def load_classes(self, vm, vmx) :
        if self.debug :
            print "LC",
            sys.stdout.flush()
       
        # Add classes for CLASSSIM
        for c in vm.get_classes() :
            value = ""
            android_entropy = 0.0
            java_entropy = 0.0
            hex_entropy = 0.0
            exception_entropy = 0.0
            nb_methods = 0
            
            class_data = c.get_class_data()
            if class_data == None :
                continue

            for m in c.get_methods() :
                z_tmp = create_entropies( vmx, m )
                            
                value += z_tmp[0]
                android_entropy += z_tmp[1]
                java_entropy += z_tmp[2]
                hex_entropy += z_tmp[3]
                exception_entropy += z_tmp[4]

                nb_methods += 1
                
            if nb_methods != 0 :
                self.class_elsign.add_element( value, [ android_entropy/nb_methods, 
                                                        java_entropy/nb_methods, 
                                                        hex_entropy/nb_methods,
                                                        exception_entropy/nb_methods ] )
                del value, z_tmp

    def check(self, vm, vmx) :
        self.load_meths(vm, vmx)
        
        if self.debug :
            print "CM",
            sys.stdout.flush()
        ret = self.meth_elsign.check() 
        
        
        if self.debug :
            dt = self.meth_elsign.get_debug()
            debug_nb_sign = dt[0]
            debug_nb_clusters = dt[1]
            debug_nb_cmp_clusters = dt[2]
            debug_nb_elements = dt[3]
            debug_nb_cmp_elements = dt[4]

            debug_nb_cmp_max = debug_nb_sign * debug_nb_elements
            print "[SIGN:%d CLUSTERS:%d CMP_CLUSTERS:%d ELEMENTS:%d CMP_ELEMENTS:%d" % (debug_nb_sign, debug_nb_clusters, debug_nb_cmp_clusters, debug_nb_elements, debug_nb_cmp_elements),
            try :
                percentage = debug_nb_cmp_elements/float(debug_nb_cmp_max)
            except :
                percentage = 0
            finally :
                print "-> %d %f%%]" % (debug_nb_cmp_max, percentage * 100),

            print ret[1:],

        if ret[0] == None :
            self.load_classes(vm, vmx)
            
            if self.debug :
                print "CC",
                sys.stdout.flush()
            ret = self.class_elsign.check()
        
            if self.debug :
                dt = self.class_elsign.get_debug()
                debug_nb_sign = dt[0]
                debug_nb_clusters = dt[1]
                debug_nb_cmp_clusters = dt[2]
                debug_nb_elements = dt[3]
                debug_nb_cmp_elements = dt[4]

                debug_nb_cmp_max = debug_nb_sign * debug_nb_elements
                print "[SIGN:%d CLUSTERS:%d CMP_CLUSTERS:%d ELEMENTS:%d CMP_ELEMENTS:%d" % (debug_nb_sign, debug_nb_clusters, debug_nb_cmp_clusters, debug_nb_elements, debug_nb_cmp_elements),
                try :
                    percentage = debug_nb_cmp_elements/float(debug_nb_cmp_max)
                except :
                    percentage = 0
                finally :
                    print "-> %d %f%%]" % (debug_nb_cmp_max, percentage * 100),

                print ret[1:],

        return ret[0], ret[1:]

class PublicSignature :
    def __init__(self, database, config, debug=False) :
        self.debug = debug

        self.DE = DalvikElsign()
        self.DE.set_debug( debug )

        self.database = database
        self.config = config

        print self.database, self.config, debug

        self._load()

    def _load(self) :
        self.DE.load_config( json.loads( open(self.config, "rb").read() ) )

        buff = json.loads( open(self.database, "rb").read() )
        for i in buff :

            type_signature = None
            sub_signatures = []
            for j in buff[i][0] :
                if j[0] == METHSIM :
                    type_signature = METHSIM
                    sub_signatures.append( [ j[2:], str(base64.b64decode( j[1] ) ) ] )
                elif j[0] == CLASSSIM :
                    type_signature = CLASSSIM
                    sub_signatures.append( [ j[2:], str(base64.b64decode( j[1] ) ) ] )


            if type_signature != None :
                self.DE.add_signature( type_signature, i, buff[i][1], sub_signatures )
            else :
                print i, "ERROR"

    def check_apk(self, apk) :
        if self.debug :
            print "loading apk..",
            sys.stdout.flush()
       
        classes_dex = apk.get_dex()
        ret = self._check_dalvik( classes_dex )
        
        return ret

    def check_dex(self, buff) :
        """
            Check if a signature matches the dex application

            @param buff : a buffer which represents a dex file
            @rtype : None if no signatures match, otherwise the name of the signature
        """
        return self._check_dalvik( buff )

    def check_dex_direct(self, d, dx) :
        """
            Check if a signature matches the dex application

            @param buff : a buffer which represents a dex file
            @rtype : None if no signatures match, otherwise the name of the signature
        """
        return self._check_dalvik_direct( d, dx )
    
    def _check_dalvik(self, buff) :
        if self.debug :
            print "loading dex..",
            sys.stdout.flush()
        
        vm = dvm.DalvikVMFormat( buff )
        
        if self.debug :
            print "analysis..",
            sys.stdout.flush()
        
        vmx = analysis.VMAnalysis( vm )
        return self._check_dalvik_direct( vm, vmx )

    def _check_dalvik_direct(self, vm, vmx) :
        # check methods with similarity
        ret = self.DE.check(vm, vmx)

        self.DE.raz()
        del vmx, vm

        return ret

class MSignature :
    def __init__(self, dbname, dbconfig, debug, ps=PublicSignature) :
        """
            Check if signatures from a database is present in an android application (apk/dex)

            @param dbname : the filename of the database
            @param dbconfig : the filename of the configuration

        """

        self.debug = debug
        self.p = ps( dbname, dbconfig, self.debug )

    def load(self) :
        """
            Load the database
        """
        self.p.load()

    def set_debug(self) :
        """
            Debug mode !
        """
        self.debug = True
        self.p.set_debug()
        

    def check_apk(self, apk) :
        """
            Check if a signature matches the application

            @param apk : an L{APK} object
            @rtype : None if no signatures match, otherwise the name of the signature
        """
        if self.debug :
            print "loading apk..",
            sys.stdout.flush()
        
        classes_dex = apk.get_dex()
        ret, l = self.p._check_dalvik( classes_dex )

        if ret == None :
            #ret, l1 = self.p._check_bin( apk )
            l1 = []
            l.extend( l1 )

        return ret, l

    def check_dex(self, buff) :
        """
            Check if a signature matches the dex application

            @param buff : a buffer which represents a dex file
            @rtype : None if no signatures match, otherwise the name of the signature
        """
        return self.p._check_dalvik( buff )

    def check_dex_direct(self, d, dx) :
        """
            Check if a signature matches the dex application

            @param buff : a buffer which represents a dex file
            @rtype : None if no signatures match, otherwise the name of the signature
        """
        return self.p._check_dalvik_direct( d, dx )

class PublicCSignature :
    def add_file(self, srules) :
        l = []
        rules = json.loads( srules )

        ret_type = androconf.is_android( rules[0]["SAMPLE"] )
        if ret_type == "APK" :
            a = apk.APK( rules[0]["SAMPLE"] )
            classes_dex = a.get_dex()
        elif ret_type == "DEX" :
            classes_dex = open( rules[0]["SAMPLE"], "rb" ).read()
        elif ret_type == "ELF" :
            elf_file = open( rules[0]["SAMPLE"], "rb" ).read()
        else :
            return None

        if ret_type == "APK" or ret_type == "DEX" :
            vm = dvm.DalvikVMFormat( classes_dex )
            vmx = analysis.VMAnalysis( vm )

        for i in rules[1:] :
            x = { i["NAME"] : [] }
            
            sign = []
            for j in i["SIGNATURE"] :
                z = []
                if j["TYPE"] == "METHSIM" :
                    z.append( METHSIM )
                    m = vm.get_method_descriptor( j["CN"], j["MN"], j["D"] )
                    if m == None :
                        print "impossible to find", j["CN"], j["MN"], j["D"]
                        raise("ooo")
                    
                    #print m.get_length()
                   
                    z_tmp = create_entropies( vmx, m )
                    print z_tmp[0]
                    z_tmp[0] = base64.b64encode( z_tmp[0] )
                    z.extend( z_tmp )
                elif j["TYPE"] == "CLASSSIM" :
                    for c in vm.get_classes() :
                        if j["CN"] == c.get_name() :
                            z.append( CLASSSIM )
                            value = ""
                            android_entropy = 0.0
                            java_entropy = 0.0
                            hex_entropy = 0.0
                            exception_entropy = 0.0
                            nb_methods = 0
                            for m in c.get_methods() :
                                z_tmp = create_entropies( vmx, m )
                            
                                value += z_tmp[0]
                                android_entropy += z_tmp[1]
                                java_entropy += z_tmp[2]
                                hex_entropy += z_tmp[3]
                                exception_entropy += z_tmp[4]

                                nb_methods += 1

                            z.extend( [ base64.b64encode(value), 
                                        android_entropy/nb_methods, 
                                        java_entropy/nb_methods, 
                                        hex_entropy/nb_methods, 
                                        exception_entropy/nb_methods ] )
                else :
                    return None

                sign.append( z )

            x[ i["NAME"] ].append( sign )
            x[ i["NAME"] ].append( FIX_FORMULA(i["BF"], len(sign)) )
            l.append( x )
        print l
        return l

    def get_info(self, srules) :
        rules = json.loads( srules )

        ret_type = androconf.is_android( rules[0]["SAMPLE"] )
        if ret_type == "APK" :
            a = apk.APK( rules[0]["SAMPLE"] )
            classes_dex = a.get_dex()
        elif ret_type == "DEX" :
            classes_dex = open( rules[0]["SAMPLE"], "rb" ).read()
        #elif ret_type == "ELF" :
            #elf_file = open( rules[0]["SAMPLE"], "rb" ).read()
        else :
            return None

        if ret_type == "APK" or ret_type == "DEX" :
            vm = dvm.DalvikVMFormat( classes_dex )
            vmx = analysis.VMAnalysis( vm )

        res = []
        for i in rules[1:] :
            for j in i["SIGNATURE"] :
                if j["TYPE"] == "METHSIM" :
                    m = vm.get_method_descriptor( j["CN"], j["MN"], j["D"] )
                    if m == None :
                        print "impossible to find", j["CN"], j["MN"], j["D"]
                    else :
                        res.append( m )

                elif j["TYPE"] == "CLASSSIM" :
                    for c in vm.get_classes() :
                        if j["CN"] == c.get_name() :
                            res.append( c )

        return vm, vmx, res


class CSignature :
    def __init__(self, pcs=PublicCSignature) :
        self.pcs = pcs()

    def add_file(self, srules) :
        return self.pcs.add_file(srules)

    def get_info(self, srules) :
        return self.pcs.get_info(srules)

    def list_indb(self, output) :
        from elsim.similarity import similarity
        s = similarity.SIMILARITY( "./elsim/elsim/similarity/libsimilarity/libsimilarity.so" )
        s.set_compress_type( similarity.ZLIB_COMPRESS )

        fd = open(output, "r")
        buff = json.loads( fd.read() )
        fd.close()

        for i in buff :
            print i
            for j in buff[i][0] :
                sign = base64.b64decode(j[1])
                print "\t", j[0], "ENTROPIES:", j[2:], "L:%d" % len(sign), "K:%d" % s.kolmogorov(sign)[0]
            print "\tFORMULA:", buff[i][-1]

    def check_db(self, output) :
        ids = {}
        meth_sim = []
        class_sim = []

        fd = open(output, "r")
        buff = json.loads( fd.read() )
        fd.close()
        
        for i in buff :
            nb = 0
            for ssign in buff[i][0] :
                if ssign[0] == METHSIM :
                    value = base64.b64decode( ssign[1] )
                    if value in ids :
                        print "IDENTICAL", ids[ value ], i, nb
                    else :
                        ids[ value ] = (i, nb)
                        meth_sim.append( value )
                elif ssign[0] == CLASSSIM :
                    ids[ base64.b64decode( ssign[1] ) ] = (i, nb)
                    class_sim.append( base64.b64decode( ssign[1] ) )
                nb += 1


        from elsim.similarity import similarity
        s = similarity.SIMILARITY( "./elsim/elsim/similarity/libsimilarity/libsimilarity.so" )
        s.set_compress_type( similarity.SNAPPY_COMPRESS )

        self.__check_db( s, ids, meth_sim )
        self.__check_db( s, ids, class_sim )

    def __check_db(self, s, ids, elem_sim) :
        from elsim.similarity import similarity
        problems = {}
        for i in elem_sim :
            for j in elem_sim :
                if i != j :
                    ret = s.ncd( i, j )[0]
                    if ret < 0.3 :
                        ids_cmp = ids[ i ] + ids[ j ]
                        if ids_cmp not in problems :
                            s.set_compress_type( similarity.BZ2_COMPRESS )
                            ret = s.ncd( i, j )[0]
                            s.set_compress_type( similarity.SNAPPY_COMPRESS )
                            print "[-] ", ids[ i ], ids[ j ], ret
                            problems[ ids_cmp ] = 0
                            problems[ ids[ j ] + ids[ i ] ] = 0

    def remove_indb(self, signature, output) :
        fd = open(output, "r")
        buff = json.loads( fd.read() )
        fd.close()

        del buff[signature]

        fd = open(output, "w")
        fd.write( json.dumps( buff ) )
        fd.close()

    def add_indb(self, signatures, output) :
        if signatures == None :
            return

        fd = open(output, "a+")
        buff = fd.read() 
        if buff == "" :
            buff = {}
        else :
            buff = json.loads( buff )
        fd.close()

        for i in signatures :
            buff.update( i )

        fd = open(output, "w") 
        fd.write( json.dumps( buff ) )
        fd.close()
