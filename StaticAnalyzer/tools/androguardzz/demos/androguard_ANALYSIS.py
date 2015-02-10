#!/usr/bin/env python

import sys, hashlib
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "./")

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

OUTPUT = "./output/"
#TEST  = 'examples/java/test/orig/Test1.class'
#TEST  = 'examples/java/Demo1/orig/DES.class'
#TEST  = 'examples/java/Demo1/orig/Util.class'
#TEST = "apks/DroidDream/tmp/classes.dex"
#TEST = "./examples/android/TCDiff/bin/classes.dex"
TEST = "apks/iCalendar.apk"
#TEST = "apks/adrd/5/8370959.dex"

def display_CFG(a, x, classes) :
    for method in a.get_methods() :
        g = x.get_method( method )

        print method.get_class_name(), method.get_name(), method.get_descriptor()
        for i in g.basic_blocks.get() :
            print "\t %s %x %x" % (i.name, i.start, i.end), '[ NEXT = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.childs ), ']', '[ PREV = ', ', '.join( j[2].get_name() for j in i.fathers ), ']'


def display_STRINGS(a, x, classes) :
    print "STRINGS"
    for s, _ in x.get_tainted_variables().get_strings() :
        print "String : ", repr(s.get_info())
        analysis.show_PathVariable( a, s.get_paths() )

def display_FIELDS(a, x, classes) :
    print "FIELDS"
    for f, _ in x.get_tainted_variables().get_fields() :
        print "field : ", repr(f.get_info())
        analysis.show_PathVariable( a, f.get_paths() )

def display_PACKAGES(a, x, classes) :
    print "CREATED PACKAGES"
    for m, _ in x.get_tainted_packages().get_packages() :
      m.show()

def display_PACKAGES_II(a, x, classes) :
# Internal Methods -> Internal Methods
    print "Internal --> Internal"
    for j in x.get_tainted_packages().get_internal_packages() :
      analysis.show_Path( a, j )

def display_PACKAGES_IE(a, x, classes) :
# Internal Methods -> External Methods
    print "Internal --> External"
    for j in x.get_tainted_packages().get_external_packages() :
      analysis.show_Path( a, j )

def display_SEARCH_PACKAGES(a, x, classes, package_name) :
    print "Search package", package_name
    analysis.show_Paths( a, x.get_tainted_packages().search_packages( package_name ) )

def display_SEARCH_METHODS(a, x, classes, package_name, method_name, descriptor) :
    print "Search method", package_name, method_name, descriptor
    analysis.show_Paths( a, x.get_tainted_packages().search_methods( package_name, method_name, descriptor) )

def display_PERMISSION(a, x, classes) :
    # Show methods used by permission
    perms_access = x.get_tainted_packages().get_permissions( [] )
    for perm in perms_access :
        print "PERM : ", perm
        analysis.show_Paths( a, perms_access[ perm ] )

def display_OBJECT_CREATED(a, x, class_name) :
    print "Search object", class_name
    analysis.show_Paths( a, x.get_tainted_packages().search_objects( class_name ) )

a = AndroguardS( TEST )
x = analysis.uVMAnalysis( a.get_vm() )

#print a.get_vm().get_strings()
print a.get_vm().get_regex_strings( "access" )
print a.get_vm().get_regex_strings( "(long).*2" )
print a.get_vm().get_regex_strings( ".*(t\_t).*" )

classes = a.get_vm().get_classes_names()
vm = a.get_vm()

display_CFG( a, x, classes )
display_STRINGS( vm, x, classes )
display_FIELDS( vm, x, classes )
display_PACKAGES( vm, x, classes )
display_PACKAGES_IE( vm, x, classes )
display_PACKAGES_II( vm, x, classes )
display_PERMISSION( vm, x, classes )

display_SEARCH_PACKAGES( a, x, classes, "Landroid/telephony/" )
display_SEARCH_PACKAGES( a, x, classes, "Ljavax/crypto/" )
display_SEARCH_METHODS( a, x, classes, "Ljavax/crypto/", "generateSecret", "." )

display_OBJECT_CREATED( a, x, "." )
