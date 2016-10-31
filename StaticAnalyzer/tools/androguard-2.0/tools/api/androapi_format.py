#!/usr/bin/env python

# This file is part of Androguard.
#
# Copyright (C) 2010, Anthony Desnos <desnos at t0t0.org>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, sys, re, string

from dvm_permissions_unformatted import PERMISSIONS
from permissions_by_hand import PERMISSIONS_BY_HAND

BASIC_TYPES = {
   "byte" : "B",
   "char" : "C",
   "double" : "D",
   "float" : "F",
   "int" : "I",
   "long" : "J",
   "short" : "S",
   "boolean" : "B",
   "void" : "V",
}

ADVANCED_TYPES = {
    "String" : "Ljava/lang/String;",
    "List" : "Ljava/util/List;",
    "AccountManagerFuture" : "Landroid/accounts/AccountManagerFuture;",
    "CellLocation" : "Landroid/telephony/CellLocation;",
    "Uri" : "Landroid/net/Uri;",
    "Cursor" : "Landroid/database/Cursor;",
    "Set" : "Ljava/util/Set;",
    "BluetoothServerSocket" : "Landroid/bluetooth/BluetoothServerSocket;",
    "BluetoothSocket" : "Landroid/bluetooth/BluetoothSocket;",
    "DownloadManager.Request" : "Landroid/app/DownloadManager/Request;",
    "PendingIntent" : "Landroid/app/PendingIntent;",
    "SmsManager" : "Landroid/telephony/SmsManager;",
    "Bitmap" : "Landroid/graphics/Bitmap;",
    "IBinder" : "Landroid/os/IBinder;",
}

def translateDescParams( desc_params ):
    desc_params = desc_params.replace(" ", "")
    buff = ""

    for elem in desc_params.split(","):
        if elem != "":
            tab = ""
            if "[" in elem:
                tab = "[" * string.count(elem, "[")

                elem = elem[ : tab.find("[") - 2 ]

            if elem not in BASIC_TYPES:
                if elem in ADVANCED_TYPES:
                    buff += tab + ADVANCED_TYPES[ elem ] + " "
                else:
                    buff += tab + "L" + elem.replace(".", "/") + "; "
            else:
                buff += tab + BASIC_TYPES[ elem ] + " "

    buff = buff[:-1]
    return buff

def translateDescReturn( desc_return ):
    buff = ""
    for elem in desc_return.split(" "):
        tab = ""
        if "[" in elem:
            tab = "[" * string.count(elem, "[")
            elem = elem[ : tab.find("[") - 2 ]

        if elem in BASIC_TYPES:
            buff += tab + BASIC_TYPES[ elem ] + " "
        else:
            if elem in ADVANCED_TYPES:
                buff += tab + ADVANCED_TYPES[ elem ] + " "
            else:
                if "." in elem:
                    buff += tab + "L" + elem.replace(".", "/") + "; "

    buff = buff[:-1]
    return buff

def translateToCLASS( desc_params, desc_return ):
    print desc_params, desc_return,

    buff = "(" + translateDescParams( desc_params[ desc_params.find("(") + 1 : -1 ] ) + ")" + translateDescReturn( desc_return )
    print "----->", buff

    return [ desc_params[ : desc_params.find("(") ], buff ]

def translateToCLASS2( constant_name, desc_return ):
    return [ constant_name, translateDescReturn( desc_return ) ]

PERMISSIONS.update( PERMISSIONS_BY_HAND )

for perm in PERMISSIONS:
    for package in PERMISSIONS[perm]:
        for element in PERMISSIONS[perm][package]:
            if element[0] == "F":
                element.extend( translateToCLASS( element[1], element[2] ) )
            elif element[0] == "C":
                element.extend( translateToCLASS2( element[1], element[2] ) )

with open("./core/bytecodes/api_permissions.py", "w") as fd:
    fd.write("DVM_PERMISSIONS_BY_PERMISSION = {\n")

    for perm in PERMISSIONS:
        fd.write("\"%s\" : {\n" % perm)

        for package in PERMISSIONS[perm]:
            fd.write("\t\"L%s;\" : [\n" % package.replace(".", "/"))

            for element in PERMISSIONS[perm][package]:
                fd.write("\t\t(\"%s\", \"%s\", \"%s\"),\n" % (element[0], element[-2], element[-1]) )

            fd.write("\t],\n")
        fd.write("},\n")
    fd.write("}\n\n")


    fd.write("DVM_PERMISSIONS_BY_ELEMENT = { \n")
    for perm in PERMISSIONS:
        for package in PERMISSIONS[perm]:
            for element in PERMISSIONS[perm][package]:
                fd.write("\t\"L%s;-%s-%s\" : \"%s\",\n" % (package.replace(".", "/"), element[-2], element[-1], perm))
    fd.write("}\n")
