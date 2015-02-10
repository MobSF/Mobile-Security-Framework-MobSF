#!/usr/bin/env python

import sys
import hashlib

import pyDes

PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "./")
sys.path.append(PATH_INSTALL + "/core")
sys.path.append(PATH_INSTALL + "/core/bytecodes")
sys.path.append(PATH_INSTALL + "/core/analysis")

from androguard import *
import analysis

TEST = "./geinimi/geinimi.apk"

_a = AndroguardS( TEST )
_x = analysis.VMAnalysis( _a.get_vm() )

#print _a.get_strings()

KEY = "\x01\x02\x03\x04\x05\x06\x07\x08"
_des = pyDes.des( KEY )

#_x.tainted_packages.export_call_graph("toto.dot", "Lcom/swampy/sexpos/pos")

tainted_string = _x.tainted_variables.get_string( "DES" )
if tainted_string != None :
    print "\t -->", tainted_string.get_info()
    for path in tainted_string.get_paths() :
        print "\t\t =>", path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), path.get_bb().get_name(), "%x" % ( path.get_bb().start + path.get_idx() )

tainted_field = _x.tainted_variables.get_field( "Lcom/swampy/sexpos/pos/e/k;", "b", "[B" )
if tainted_field != None :
    print "\t -->", tainted_field.get_info()
    for path in tainted_field.get_paths() :
        print "\t\t =>", path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), path.get_bb().get_name(), "%x" % (path.get_bb().start + path.get_idx() )


tainted_field = _x.tainted_variables.get_field( "Lcom/swampy/sexpos/pos/e/p;", "a", "[[B" )
if tainted_field != None :
    print "\t -->", tainted_field.get_info()
    for path in tainted_field.get_paths() :
        print "\t\t =>", path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), path.get_bb().get_name(), "%x" % (path.get_bb().start + path.get_idx() )
        if path.get_access_flag() == "W" :
            b = ""
            for ins in path.get_method().get_code().get_bc().get() :
                if ins.get_name() == "FILL-ARRAY-DATA" :
                    b += ins.get_data()

            print repr( _des.decrypt( b ) )

tainted_field = _x.tainted_variables.get_field( "Lcom/swampy/sexpos/pos/a;", "g", "Ljava/lang/String;" )
if tainted_field != None :
    print "\t -->", tainted_field.get_info()
    for path in tainted_field.get_paths() :
        print "\t\t =>", path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), path.get_bb().get_name(), "%x" % (path.get_bb().start + path.get_idx() )

tainted_method = _x.tainted_packages.get_method( "Lcom/swampy/sexpos/pos/e/q;", "a", "(Ljava/lang/String;)Ljava/lang/String;" )
for path in tainted_method :
    print path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor(), path.get_bb().get_name(), "%x" % (path.get_bb().start + path.get_idx() )
