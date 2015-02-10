#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2010, Anthony Desnos <desnos at t0t0.org>
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

from BeautifulSoup import BeautifulSoup, Tag
import os, sys, re

MANIFEST_PERMISSION_HTML = "docs/reference/android/Manifest.permission.html"

PERMS = {}
PERMS_RE = None

PERMS_API = {}

try :
    import psyco
    psyco.full()
except ImportError :
    pass

class Constant :
    def __init__(self, name, perms, desc_return) :
        self.name = name
        self.perms = perms
        self.desc_return = desc_return

class Function :
    def __init__(self, name, perms, desc_return) :
        self.name = name
        self.perms = perms
        self.desc_return = desc_return

def extractPerms( filename ) :
    soup = BeautifulSoup( open( filename ) )
    s = ""
    for i in soup.findAll("table", attrs={'id' : "constants"}) :
        for j in i.findChildren( "tr" ):
            td = j.findChildren( "td" )
            if td != [] :
                _type = str( td[0].text )
                _name = str( td[1].text )
                _desc = str( td[2].text )

                PERMS[_name] = [ _type, _desc ]
                PERMS_API[_name] = {}
                s += _name + "|"

    #PERMS_RE = re.compile(s[:-1])

def extractInformation( filename ) :
    soup = BeautifulSoup( open( filename ) )

    package = filename[ filename.find("reference/android/") : ][10:-5].replace("//", "/")
    package = package.replace("/", ".")

    for i in soup.findAll('a',  attrs={'name' : re.compile(".")}) :
        next_div = i.findNext("div")

        perms = []
        for perm in PERMS :
            perm_access = next_div.findAll(text=re.compile(perm))
            if perm_access != [] :
                perms.append( perm )
                #print i.name, i.get("name"), perm_access

        if perms != [] :
            element = None
            descs = i.findNext("span", attrs={'class' : 'normal'})
            _descriptor_return = descs.next
            _descriptor_return = _descriptor_return.replace('', '')
            _descriptor_return = _descriptor_return.split()
            _descriptor_return = ' '.join(str(_d)for _d in _descriptor_return)

            if isinstance(descs.next.next, Tag) :
                _descriptor_return += " " + descs.next.next.text

            if len(next_div.findNext("h4").findAll("span")) > 2 :
                element = Function( i.get("name"), perms, _descriptor_return )
            else :
                element = Constant( i.get("name"), perms, _descriptor_return )
            for perm in perms :
                if package not in PERMS_API[ perm ] :
                    PERMS_API[ perm ][ package ] = []
                PERMS_API[ perm ][ package ].append( element )

def save_file( filename ):
    fd = open( filename, "w" )

    fd.write("PERMISSIONS = {\n")
    for i in PERMS_API :
        if len(PERMS_API[ i ]) > 0 :
            fd.write("\"%s\" : {\n" % ( i ))

        for package in PERMS_API[ i ] :
            if len(PERMS_API[ i ][ package ]) > 0 :
                fd.write("\t\"%s\" : [\n" % package)

            for j in PERMS_API[ i ][ package ] :
                if isinstance(j, Function) :
                    fd.write( "\t\t[\"F\"," "\"" + j.name + "\"," + "\"" + j.desc_return + "\"]" + ",\n")
                else :
                    fd.write( "\t\t[\"C\"," "\"" + j.name + "\"," + "\"" + j.desc_return + "\"]" + ",\n")

            if len(PERMS_API[ i ][ package ]) > 0 :
                fd.write("\t],\n")

        if len(PERMS_API[ i ]) > 0 :
            fd.write("},\n\n")

    fd.write("}")
    fd.close()

BASE_DOCS = sys.argv[1]

extractPerms( BASE_DOCS + MANIFEST_PERMISSION_HTML )

ANDROID_PACKAGES = [
                     "accessibilityservice",
                     "accounts",
                     "animation",
                     "app",
                     "appwidget",
                     "bluetooth",
                     "content",
                     "database",
                     "drm",
                     "gesture",
                     "graphics",
                     "hardware",
                     "inputmethodservice",
                     "location",
                     "media",
                     "net",
                     "nfc",
                     "opengl",
                     "os",
                     "preference",
                     "provider",
                     "renderscript",
                     "sax",
                     "service",
                     "speech",
                     "telephony",
                     "text",
                     "util",
                     "view",
                     "webkit",
                     "widget",
                   ]

ANDROID_PACKAGES2 = [
                     "telephony"
]

for i in ANDROID_PACKAGES :
    for root, dirs, files in os.walk( BASE_DOCS + "docs/reference/android/" + i + "/" ) :
        for file in files :
            print "Extracting from %s" %  (root + "/" + file)
            #extractInformation( "/home/pouik/Bureau/android/android-sdk-linux_86/docs/reference/android/accounts/AccountManager.html" )
            extractInformation( root + "/" + file )

#BASE_DOCS + "docs/reference/android/telephony/TelephonyManager.html" )
#extractInformation( BASE_DOCS + "docs/reference/android/net/sip/SipAudioCall.html" ) #android/accounts/Account.html" ) #"docs/reference/android/accounts/AccountManager.html" )

for i in PERMS_API :
    if len(PERMS_API[ i ]) > 0 :
        print "PERMISSION ", i

    for package in PERMS_API[ i ] :
        print "\t package ", package

        for j in PERMS_API[ i ][ package ] :
            if isinstance(j, Function) :
                print "\t\t function : ", j.name
            else :
                print "\t\t constant : ", j.name

save_file( "./dvm_permissions_unformatted.py" )

#for i in soup.findAll('a') : #, attrs={'name' : re.compile("ACTION")}) :
#   if i.get("name") != None :
#      print i.name, i.get("name")#, i.findNextSlibing(text=re.compile("READ_PHONE_STATE"))

#for i in soup.findAll(text=re.compile("READ_PHONE_STATE")) :
#   print i, i.parent.name, i.findPrevious(re.compile('^A')), i.findPreviousSibling(re.compile('^A'))

#   if i.contents != [] :
#      if i.contents[0] == "READ_PHONE_STATE" :
#         print "here", i.parent

#         parent = i.parent
#         while parent.name != "A" :
#            parent = parent.parent
#            print "step", parent

#            if "class" in parent :
#               print "step2", parent["class"]

#            time.sleep( 1 )
#         print "end", previous.name
