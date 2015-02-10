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


from androguard.core import bytecode
from androguard.core import androconf
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS

import StringIO
from struct import pack, unpack
from xml.sax.saxutils import escape
from zlib import crc32
import re

from xml.dom import minidom

# 0: chilkat
# 1: default python zipfile module
# 2: patch zipfile module
ZIPMODULE = 1

import sys
if sys.hexversion < 0x2070000 :
    try :
        import chilkat
        ZIPMODULE = 0 
        # UNLOCK : change it with your valid key !
        try :
            CHILKAT_KEY = open("key.txt", "rb").read()
        except Exception :
            CHILKAT_KEY = "testme"

    except ImportError :
        ZIPMODULE = 1
else :
    ZIPMODULE = 1 

################################################### CHILKAT ZIP FORMAT #####################################################
class ChilkatZip :
    def __init__(self, raw) :
        self.files = []
        self.zip = chilkat.CkZip()

        self.zip.UnlockComponent( CHILKAT_KEY )

        self.zip.OpenFromMemory( raw, len(raw) )
        
        filename = chilkat.CkString()
        e = self.zip.FirstEntry()
        while e != None :
            e.get_FileName(filename)
            self.files.append( filename.getString() )
            e = e.NextEntry()

    def delete(self, patterns) :
        el = []

        filename = chilkat.CkString()
        e = self.zip.FirstEntry()
        while e != None :
            e.get_FileName(filename)
          
            if re.match(patterns, filename.getString()) != None :
                el.append( e )
            e = e.NextEntry()

        for i in el :
            self.zip.DeleteEntry( i )

    def remplace_file(self, filename, buff) :
        entry = self.zip.GetEntryByName(filename)
        if entry != None :

            obj = chilkat.CkByteData()
            obj.append( buff, len(buff) )
            return entry.ReplaceData( obj )
        return False

    def write(self) :
        obj = chilkat.CkByteData()
        self.zip.WriteToMemory( obj )
        return obj.getBytes()

    def namelist(self) :
        return self.files

    def read(self, elem) :
        e = self.zip.GetEntryByName( elem )
        s = chilkat.CkByteData()

        e.Inflate( s )
        return s.getBytes()


def sign_apk(filename, keystore, storepass):
    from subprocess import Popen, PIPE, STDOUT
    compile = Popen([androconf.CONF["PATH_JARSIGNER"],
                     "-sigalg",
                     "MD5withRSA",
                     "-digestalg",
                     "SHA1",

                     "-storepass",
                     storepass,

                     "-keystore",
                     keystore,

                     filename,
                     "alias_name"],
                    stdout=PIPE, stderr=STDOUT)
    stdout, stderr = compile.communicate()


######################################################## APK FORMAT ########################################################
class APK:
    """
        This class can access to all elements in an APK file

        :param filename: specify the path of the file, or raw data
        :param raw: specify if the filename is a path or raw data (optional)
        :param mode: specify the mode to open the file (optional)
        :param magic_file: specify the magic file (optional)
        :param zipmodule: specify the type of zip module to use (0:chilkat, 1:zipfile, 2:patch zipfile)

        :type filename: string
        :type raw: boolean
        :type mode: string
        :type magic_file: string
        :type zipmodule: int

        :Example:
          APK("myfile.apk")
          APK(open("myfile.apk", "rb").read(), raw=True)
    """
    def __init__(self, filename, raw=False, mode="r", magic_file=None, zipmodule=ZIPMODULE):
        self.filename = filename

        self.xml = {}
        self.axml = {}
        self.arsc = {}

        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.valid_apk = False

        self.files = {}
        self.files_crc32 = {}

        self.magic_file = magic_file

        if raw == True:
            self.__raw = filename
        else:
            fd = open(filename, "rb")
            self.__raw = fd.read()
            fd.close()

        self.zipmodule = zipmodule

        if zipmodule == 0:
            self.zip = ChilkatZip(self.__raw)
        elif zipmodule == 2:
            from androguard.patch import zipfile
            self.zip = zipfile.ZipFile(StringIO.StringIO(self.__raw), mode=mode)
        else:
            import zipfile
            self.zip = zipfile.ZipFile(StringIO.StringIO(self.__raw), mode=mode)

        for i in self.zip.namelist():
            if i == "AndroidManifest.xml":
                self.axml[i] = AXMLPrinter(self.zip.read(i))
                try:
                    self.xml[i] = minidom.parseString(self.axml[i].get_buff())
                except:
                    self.xml[i] = None

                if self.xml[i] != None:
                    self.package = self.xml[i].documentElement.getAttribute("package")
                    self.androidversion["Code"] = self.xml[i].documentElement.getAttribute("android:versionCode")
                    self.androidversion["Name"] = self.xml[i].documentElement.getAttribute("android:versionName")

                    for item in self.xml[i].getElementsByTagName('uses-permission'):
                        self.permissions.append(str(item.getAttribute("android:name")))

                    self.valid_apk = True

        self.get_files_types()

    def get_AndroidManifest(self):
        """
            Return the Android Manifest XML file

            :rtype: xml object
        """
        return self.xml["AndroidManifest.xml"]

    def is_valid_APK(self):
        """
            Return true if the APK is valid, false otherwise

            :rtype: boolean
        """
        return self.valid_apk

    def get_filename(self):
        """
            Return the filename of the APK

            :rtype: string
        """
        return self.filename

    def get_package(self):
        """
            Return the name of the package

            :rtype: string
        """
        return self.package

    def get_androidversion_code(self):
        """
            Return the android version code

            :rtype: string
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self):
        """
            Return the android version name

            :rtype: string
        """
        return self.androidversion["Name"]

    def get_files(self):
        """
            Return the files inside the APK

            :rtype: a list of strings
        """
        return self.zip.namelist()

    def get_files_types(self):
        """
            Return the files inside the APK with their associated types (by using python-magic)

            :rtype: a dictionnary
        """
        try:
            import magic
        except ImportError:
            # no lib magic !
            for i in self.get_files():
                buffer = self.zip.read(i)
                self.files_crc32[i] = crc32(buffer)
                self.files[i] = "Unknown"
            return self.files

        if self.files != {}:
            return self.files

        builtin_magic = 0
        try:
            getattr(magic, "MagicException")
        except AttributeError:
            builtin_magic = 1

        if builtin_magic:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()

            for i in self.get_files():
                buffer = self.zip.read(i)
                self.files[i] = ms.buffer(buffer)
                self.files[i] = self._patch_magic(buffer, self.files[i])
                self.files_crc32[i] = crc32(buffer)
        else:
            m = magic.Magic(magic_file=self.magic_file)
            for i in self.get_files():
                buffer = self.zip.read(i)
                self.files[i] = m.from_buffer(buffer)
                self.files[i] = self._patch_magic(buffer, self.files[i])
                self.files_crc32[i] = crc32(buffer)

        return self.files

    def _patch_magic(self, buffer, orig):
        if ("Zip" in orig) or ("DBase" in orig):
            val = androconf.is_android_raw(buffer)
            if val == "APK":
                if androconf.is_valid_android_raw(buffer):
                  return "Android application package file"
            elif val == "AXML":
                return "Android's binary XML"

        return orig

    def get_files_crc32(self):
        if self.files_crc32 == {}:
            self.get_files_types()

        return self.files_crc32

    def get_files_information(self):
        """
            Return the files inside the APK with their associated types and crc32

            :rtype: string, string, int
        """
        if self.files == {}:
          self.get_files_types()

        for i in self.get_files():
          try:
            yield i, self.files[i], self.files_crc32[i]
          except KeyError:
            yield i, "", ""

    def get_raw(self):
        """
            Return raw bytes of the APK

            :rtype: string
        """
        return self.__raw

    def get_file(self, filename):
        """
            Return the raw data of the specified filename

            :rtype: string
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            return ""

    def get_dex(self):
        """
            Return the raw data of the classes dex file

            :rtype: string
        """
        return self.get_file("classes.dex")

    def get_elements(self, tag_name, attribute):
        """
            Return elements in xml files which match with the tag name and the specific attribute

            :param tag_name: a string which specify the tag name
            :param attribute: a string which specify the attribute
        """
        l = []
        for i in self.xml :
            for item in self.xml[i].getElementsByTagName(tag_name) :
                value = item.getAttribute(attribute)
                value = self.format_value( value )


                l.append( str( value ) )
        return l

    def format_value(self, value) :
        if len(value) > 0 :
            if value[0] == "." : 
                value = self.package + value
            else :
                v_dot = value.find(".")
                if v_dot == 0 :
                    value = self.package + "." + value
                elif v_dot == -1 :
                    value = self.package + "." + value
        return value

    def get_element(self, tag_name, attribute):
        """
            Return element in xml files which match with the tag name and the specific attribute

            :param tag_name: specify the tag name
            :type tag_name: string
            :param attribute: specify the attribute
            :type attribute: string

            :rtype: string
        """
        for i in self.xml :
            for item in self.xml[i].getElementsByTagName(tag_name) :
                value = item.getAttribute(attribute)

                if len(value) > 0 :
                    return value
        return None

    def get_main_activity(self) :
        """
            Return the name of the main activity

            :rtype: string
        """
        for i in self.xml :
            x = set()
            y = set()
            for item in self.xml[i].getElementsByTagName("activity") :
                for sitem in item.getElementsByTagName( "action" ) :
                    val = sitem.getAttribute( "android:name" )
                    if val == "android.intent.action.MAIN" :
                        x.add( item.getAttribute( "android:name" ) )
                   
                for sitem in item.getElementsByTagName( "category" ) :
                    val = sitem.getAttribute( "android:name" )
                    if val == "android.intent.category.LAUNCHER" :
                        y.add( item.getAttribute( "android:name" ) )
                
        z = x.intersection(y)
        if len(z) > 0 :
            return self.format_value(z.pop())
        return None

    def get_activities(self) :
        """
            Return the android:name attribute of all activities

            :rtype: a list of string
        """
        return self.get_elements("activity", "android:name")

    def get_services(self) :
        """
            Return the android:name attribute of all services

            :rtype: a list of string
        """
        return self.get_elements("service", "android:name")

    def get_receivers(self) :
        """
            Return the android:name attribute of all receivers

            :rtype: a list of string
        """
        return self.get_elements("receiver", "android:name")

    def get_providers(self) :
        """
            Return the android:name attribute of all providers

            :rtype: a list of string
        """
        return self.get_elements("provider", "android:name")

    def get_permissions(self) :
        """
            Return permissions

            :rtype: list of string
        """
        return self.permissions

    def get_details_permissions(self) :
        """
            Return permissions with details

            :rtype: list of string
        """
        l = {}

        for i in self.permissions :
            perm = i
            pos = i.rfind(".")

            if pos != -1 :
                perm = i[pos+1:]
            
            try :
                l[ i ] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][ perm ]
            except KeyError :
                l[ i ] = [ "dangerous", "Unknown permission from android reference", "Unknown permission from android reference" ]

        return l

    def get_max_sdk_version(self):
        """
            Return the android:maxSdkVersion attribute

            :rtype: string
        """
        return self.get_element("uses-sdk", "android:maxSdkVersion")

    def get_min_sdk_version(self):
        """
            Return the android:minSdkVersion attribute

            :rtype: string
        """
        return self.get_element("uses-sdk", "android:minSdkVersion")

    def get_target_sdk_version(self) :
        """
            Return the android:targetSdkVersion attribute

            :rtype: string
        """
        return self.get_element( "uses-sdk", "android:targetSdkVersion" )

    def get_libraries(self) :
        """
            Return the android:name attributes for libraries

            :rtype: list
        """
        return self.get_elements( "uses-library", "android:name" )

    def get_certificate(self, filename) :
        """
            Return a certificate object by giving the name in the apk file
        """
        import chilkat

        cert = chilkat.CkCert()
        f = self.get_file( filename )
        
        success = cert.LoadFromBinary(f, len(f))

        return success, cert

    def new_zip(self, filename, deleted_files=None, new_files={}) :
        """
            Create a new zip file

            :param filename: the output filename of the zip
            :param deleted_files: a regex pattern to remove specific file
            :param new_files: a dictionnary of new files

            :type filename: string
            :type deleted_files: None or a string
            :type new_files: a dictionnary (key:filename, value:content of the file)
        """
        if self.zipmodule == 2:
            from androguard.patch import zipfile
            zout = zipfile.ZipFile(filename, 'w')
        else:
            import zipfile
            zout = zipfile.ZipFile(filename, 'w')

        for item in self.zip.infolist():
            if deleted_files != None:
                if re.match(deleted_files, item.filename) == None:
                    if item.filename in new_files:
                        zout.writestr(item, new_files[item.filename])
                    else:
                        buffer = self.zip.read(item.filename)
                        zout.writestr(item, buffer)
        zout.close()

    def get_android_manifest_axml(self):
        """
            Return the :class:`AXMLPrinter` object which corresponds to the AndroidManifest.xml file

            :rtype: :class:`AXMLPrinter`
        """
        try:
            return self.axml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_manifest_xml(self):
        """
            Return the xml object which corresponds to the AndroidManifest.xml file

            :rtype: object
        """
        try:
            return self.xml["AndroidManifest.xml"]
        except KeyError:
            return None

    def get_android_resources(self):
        """
            Return the :class:`ARSCParser` object which corresponds to the resources.arsc file

            :rtype: :class:`ARSCParser`
        """
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            try:
                self.arsc["resources.arsc"] = ARSCParser(self.zip.read("resources.arsc"))
                return self.arsc["resources.arsc"]
            except KeyError:
                return None

    def show(self):
        self.get_files_types()

        print "FILES: "
        for i in self.get_files():
            try:
                print "\t", i, self.files[i], "%x" % self.files_crc32[i]
            except KeyError:
                print "\t", i, "%x" % self.files_crc32[i]

        print "PERMISSIONS: "
        details_permissions = self.get_details_permissions()
        for i in details_permissions:
            print "\t", i, details_permissions[i]
        print "MAIN ACTIVITY: ", self.get_main_activity()
        print "ACTIVITIES: ", self.get_activities()
        print "SERVICES: ", self.get_services()
        print "RECEIVERS: ", self.get_receivers()
        print "PROVIDERS: ", self.get_providers()


def show_Certificate(cert):
    print "Issuer: C=%s, CN=%s, DN=%s, E=%s, L=%s, O=%s, OU=%s, S=%s" % (cert.issuerC(), cert.issuerCN(), cert.issuerDN(), cert.issuerE(), cert.issuerL(), cert.issuerO(), cert.issuerOU(), cert.issuerS())
    print "Subject: C=%s, CN=%s, DN=%s, E=%s, L=%s, O=%s, OU=%s, S=%s" % (cert.subjectC(), cert.subjectCN(), cert.subjectDN(), cert.subjectE(), cert.subjectL(), cert.subjectO(), cert.subjectOU(), cert.subjectS())


######################################################## AXML FORMAT ########################################################
# Translated from http://code.google.com/p/android4me/source/browse/src/android/content/res/AXmlResourceParser.java

UTF8_FLAG = 0x00000100


class StringBlock:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self._cache = {}
        self.header = unpack('<h', buff.read(2))[0]
        self.header_size = unpack('<h', buff.read(2))[0]

        self.chunkSize = unpack('<i', buff.read(4))[0]
        self.stringCount = unpack('<i', buff.read(4))[0]
        self.styleOffsetCount = unpack('<i', buff.read(4))[0]

        self.flags = unpack('<i', buff.read(4))[0]
        self.m_isUTF8 = ((self.flags & UTF8_FLAG) != 0)

        self.stringsOffset = unpack('<i', buff.read(4))[0]
        self.stylesOffset = unpack('<i', buff.read(4))[0]

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_strings = []
        self.m_styles = []

        for i in range(0, self.stringCount):
            self.m_stringOffsets.append(unpack('<i', buff.read(4))[0])

        for i in range(0, self.styleOffsetCount):
            self.m_styleOffsets.append(unpack('<i', buff.read(4))[0])

        size = self.chunkSize - self.stringsOffset
        if self.stylesOffset != 0:
            size = self.stylesOffset - self.stringsOffset

        # FIXME
        if (size % 4) != 0:
            androconf.warning("ooo")

        for i in range(0, size):
            self.m_strings.append(unpack('=b', buff.read(1))[0])

        if self.stylesOffset != 0:
            size = self.chunkSize - self.stylesOffset

            # FIXME
            if (size % 4) != 0:
                androconf.warning("ooo")

            for i in range(0, size / 4):
                self.m_styles.append(unpack('<i', buff.read(4))[0])

    def getString(self, idx):
        if idx in self._cache:
            return self._cache[idx]

        if idx < 0 or not self.m_stringOffsets or idx >= len(self.m_stringOffsets):
            return ""

        offset = self.m_stringOffsets[idx]

        if not self.m_isUTF8:
            length = self.getShort2(self.m_strings, offset)
            offset += 2
            self._cache[idx] = self.decode(self.m_strings, offset, length)
        else:
            offset += self.getVarint(self.m_strings, offset)[1]
            varint = self.getVarint(self.m_strings, offset)

            offset += varint[1]
            length = varint[0]

            self._cache[idx] = self.decode2(self.m_strings, offset, length)

        return self._cache[idx]

    def getStyle(self, idx):
        print idx
        print idx in self.m_styleOffsets, self.m_styleOffsets[idx]

        print self.m_styles[0]

    def decode(self, array, offset, length):
        length = length * 2
        length = length + length % 2

        data = ""

        for i in range(0, length):
            t_data = pack("=b", self.m_strings[offset + i])
            data += unicode(t_data, errors='ignore')
            if data[-2:] == "\x00\x00":
                break

        end_zero = data.find("\x00\x00")
        if end_zero != -1:
            data = data[:end_zero]

        return data.decode("utf-16", 'replace')

    def decode2(self, array, offset, length):
        data = ""

        for i in range(0, length):
            t_data = pack("=b", self.m_strings[offset + i])
            data += unicode(t_data, errors='ignore')

        return data.decode("utf-8", 'replace')

    def getVarint(self, array, offset):
        val = array[offset]
        more = (val & 0x80) != 0
        val &= 0x7f

        if not more:
            return val, 1
        return val << 8 | array[offset + 1] & 0xff, 2

    def getShort(self, array, offset):
        value = array[offset / 4]
        if ((offset % 4) / 2) == 0:
            return value & 0xFFFF
        else:
            return value >> 16

    def getShort2(self, array, offset):
        return (array[offset + 1] & 0xff) << 8 | array[offset] & 0xff

    def show(self):
        print "StringBlock", hex(self.start), hex(self.header), hex(self.header_size), hex(self.chunkSize), hex(self.stringsOffset), self.m_stringOffsets
        for i in range(0, len(self.m_stringOffsets)):
            print i, repr(self.getString(i))

ATTRIBUTE_IX_NAMESPACE_URI  = 0
ATTRIBUTE_IX_NAME           = 1
ATTRIBUTE_IX_VALUE_STRING   = 2
ATTRIBUTE_IX_VALUE_TYPE     = 3
ATTRIBUTE_IX_VALUE_DATA     = 4
ATTRIBUTE_LENGHT            = 5

CHUNK_AXML_FILE             = 0x00080003
CHUNK_RESOURCEIDS           = 0x00080180
CHUNK_XML_FIRST             = 0x00100100
CHUNK_XML_START_NAMESPACE   = 0x00100100
CHUNK_XML_END_NAMESPACE     = 0x00100101
CHUNK_XML_START_TAG         = 0x00100102
CHUNK_XML_END_TAG           = 0x00100103
CHUNK_XML_TEXT              = 0x00100104
CHUNK_XML_LAST              = 0x00100104

START_DOCUMENT              = 0
END_DOCUMENT                = 1
START_TAG                   = 2
END_TAG                     = 3
TEXT                        = 4


class AXMLParser:
    def __init__(self, raw_buff):
        self.reset()

        self.buff = bytecode.BuffHandle(raw_buff)

        self.buff.read(4)
        self.buff.read(4)

        self.sb = StringBlock(self.buff)

        self.m_resourceIDs = []
        self.m_prefixuri = {}
        self.m_uriprefix = {}
        self.m_prefixuriL = []

        self.visited_ns = []

    def reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def next(self):
        self.doNext()
        return self.m_event

    def doNext(self):
        if self.m_event == END_DOCUMENT:
            return

        event = self.m_event

        self.reset()
        while True:
            chunkType = -1

            # Fake END_DOCUMENT event.
            if event == END_TAG:
                pass

            # START_DOCUMENT
            if event == START_DOCUMENT:
                chunkType = CHUNK_XML_START_TAG
            else:
                if self.buff.end():
                    self.m_event = END_DOCUMENT
                    break
                chunkType = unpack('<L', self.buff.read(4))[0]

            if chunkType == CHUNK_RESOURCEIDS:
                chunkSize = unpack('<L', self.buff.read(4))[0]
                # FIXME
                if chunkSize < 8 or chunkSize % 4 != 0:
                    androconf.warning("ooo")

                for i in range(0, chunkSize / 4 - 2):
                    self.m_resourceIDs.append(unpack('<L', self.buff.read(4))[0])

                continue

            # FIXME
            if chunkType < CHUNK_XML_FIRST or chunkType > CHUNK_XML_LAST:
                androconf.warning("ooo")

            # Fake START_DOCUMENT event.
            if chunkType == CHUNK_XML_START_TAG and event == -1:
                self.m_event = START_DOCUMENT
                break

            self.buff.read(4)  # /*chunkSize*/
            lineNumber = unpack('<L', self.buff.read(4))[0]
            self.buff.read(4)  # 0xFFFFFFFF

            if chunkType == CHUNK_XML_START_NAMESPACE or chunkType == CHUNK_XML_END_NAMESPACE:
                if chunkType == CHUNK_XML_START_NAMESPACE:
                    prefix = unpack('<L', self.buff.read(4))[0]
                    uri = unpack('<L', self.buff.read(4))[0]

                    self.m_prefixuri[prefix] = uri
                    self.m_uriprefix[uri] = prefix
                    self.m_prefixuriL.append((prefix, uri))
                    self.ns = uri
                else:
                    self.ns = -1
                    self.buff.read(4)
                    self.buff.read(4)
                    (prefix, uri) = self.m_prefixuriL.pop()
                    #del self.m_prefixuri[ prefix ]
                    #del self.m_uriprefix[ uri ]

                continue

            self.m_lineNumber = lineNumber

            if chunkType == CHUNK_XML_START_TAG:
                self.m_namespaceUri = unpack('<L', self.buff.read(4))[0]
                self.m_name = unpack('<L', self.buff.read(4))[0]

                # FIXME
                self.buff.read(4)  # flags

                attributeCount = unpack('<L', self.buff.read(4))[0]
                self.m_idAttribute = (attributeCount >> 16) - 1
                attributeCount = attributeCount & 0xFFFF
                self.m_classAttribute = unpack('<L', self.buff.read(4))[0]
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1

                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                for i in range(0, attributeCount * ATTRIBUTE_LENGHT):
                    self.m_attributes.append(unpack('<L', self.buff.read(4))[0])

                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGHT):
                    self.m_attributes[i] = self.m_attributes[i] >> 24

                self.m_event = START_TAG
                break

            if chunkType == CHUNK_XML_END_TAG:
                self.m_namespaceUri = unpack('<L', self.buff.read(4))[0]
                self.m_name = unpack('<L', self.buff.read(4))[0]
                self.m_event = END_TAG
                break

            if chunkType == CHUNK_XML_TEXT:
                self.m_name = unpack('<L', self.buff.read(4))[0]

                # FIXME
                self.buff.read(4)
                self.buff.read(4)

                self.m_event = TEXT
                break

    def getPrefixByUri(self, uri):
        try:
            return self.m_uriprefix[uri]
        except KeyError:
            return -1

    def getPrefix(self):
        try:
            return self.sb.getString(self.m_uriprefix[self.m_namespaceUri])
        except KeyError:
            return u''

    def getName(self):
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG) :
            return u''

        return self.sb.getString(self.m_name)

    def getText(self) :
        if self.m_name == -1 or self.m_event != TEXT :
            return u''

        return self.sb.getString(self.m_name)

    def getNamespacePrefix(self, pos):
        prefix = self.m_prefixuriL[pos][0]
        return self.sb.getString(prefix)

    def getNamespaceUri(self, pos):
        uri = self.m_prefixuriL[pos][1]
        return self.sb.getString(uri)

    def getXMLNS(self):
        buff = ""
        for i in self.m_uriprefix:
            if i not in self.visited_ns:
                buff += "xmlns:%s=\"%s\"\n" % (self.sb.getString(self.m_uriprefix[i]), self.sb.getString(self.m_prefixuri[self.m_uriprefix[i]]))
                self.visited_ns.append(i)
        return buff

    def getNamespaceCount(self, pos) :
        pass

    def getAttributeOffset(self, index):
        # FIXME
        if self.m_event != START_TAG:
            androconf.warning("Current event is not START_TAG.")

        offset = index * 5
        # FIXME
        if offset >= len(self.m_attributes):
            androconf.warning("Invalid attribute index")

        return offset

    def getAttributeCount(self):
        if self.m_event != START_TAG:
            return -1

        return len(self.m_attributes) / ATTRIBUTE_LENGHT

    def getAttributePrefix(self, index):
        offset = self.getAttributeOffset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        prefix = self.getPrefixByUri(uri)

        if prefix == -1:
            return ""

        return self.sb.getString(prefix)

    def getAttributeName(self, index) :
        offset = self.getAttributeOffset(index)
        name = self.m_attributes[offset+ATTRIBUTE_IX_NAME]

        if name == -1 :
            return ""

        return self.sb.getString( name )

    def getAttributeValueType(self, index) :
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset+ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index) :
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset+ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index) :
        offset = self.getAttributeOffset(index)
        valueType = self.m_attributes[offset+ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING :
            valueString = self.m_attributes[offset+ATTRIBUTE_IX_VALUE_STRING]
            return self.sb.getString( valueString )
        # WIP
        return ""
        #int valueData=m_attributes[offset+ATTRIBUTE_IX_VALUE_DATA];
        #return TypedValue.coerceToString(valueType,valueData);

TYPE_ATTRIBUTE          = 2
TYPE_DIMENSION          = 5
TYPE_FIRST_COLOR_INT    = 28
TYPE_FIRST_INT          = 16
TYPE_FLOAT              = 4
TYPE_FRACTION           = 6
TYPE_INT_BOOLEAN        = 18
TYPE_INT_COLOR_ARGB4    = 30
TYPE_INT_COLOR_ARGB8    = 28
TYPE_INT_COLOR_RGB4     = 31
TYPE_INT_COLOR_RGB8     = 29
TYPE_INT_DEC            = 16
TYPE_INT_HEX            = 17
TYPE_LAST_COLOR_INT     = 31
TYPE_LAST_INT           = 31
TYPE_NULL               = 0
TYPE_REFERENCE          = 1
TYPE_STRING             = 3

RADIX_MULTS             =   [ 0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010 ]
DIMENSION_UNITS         =   [ "px","dip","sp","pt","in","mm" ]
FRACTION_UNITS          =   [ "%", "%p" ]

COMPLEX_UNIT_MASK        =   15

def complexToFloat(xcomplex):
    return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]

class AXMLPrinter:
    def __init__(self, raw_buff):
        self.axml = AXMLParser(raw_buff)
        self.xmlns = False

        self.buff = u''

        while True:
            _type = self.axml.next()
#           print "tagtype = ", _type

            if _type == START_DOCUMENT:
                self.buff += u'<?xml version="1.0" encoding="utf-8"?>\n'
            elif _type == START_TAG:
                self.buff += u'<' + self.getPrefix(self.axml.getPrefix()) + self.axml.getName() + u'\n'
                self.buff += self.axml.getXMLNS()

                for i in range(0, self.axml.getAttributeCount()):
                    self.buff += "%s%s=\"%s\"\n" % ( self.getPrefix(
                        self.axml.getAttributePrefix(i) ), self.axml.getAttributeName(i), self._escape( self.getAttributeValue( i ) ) )

                self.buff += u'>\n'

            elif _type == END_TAG :
                self.buff += "</%s%s>\n" % ( self.getPrefix( self.axml.getPrefix() ), self.axml.getName() )

            elif _type == TEXT :
                self.buff += "%s\n" % self.axml.getText()

            elif _type == END_DOCUMENT :
                break

    # pleed patch
    def _escape(self, s):
        s = s.replace("&", "&amp;")
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&apos;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        return escape(s)

    def get_buff(self):
        return self.buff.encode('utf-8')

    def get_xml(self):
        return minidom.parseString(self.get_buff()).toprettyxml()

    def get_xml_obj(self):
        return minidom.parseString(self.get_buff())

    def getPrefix(self, prefix):
        if prefix == None or len(prefix) == 0:
            return u''

        return prefix + u':'

    def getAttributeValue(self, index):
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        if _type == TYPE_STRING:
            return self.axml.getAttributeValue(index)

        elif _type == TYPE_ATTRIBUTE:
            return "?%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_REFERENCE:
            return "@%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_FLOAT:
            return "%f" % unpack("=f", pack("=L", _data))[0]

        elif _type == TYPE_INT_HEX:
            return "0x%08X" % _data

        elif _type == TYPE_INT_BOOLEAN:
            if _data == 0:
                return "false"
            return "true"

        elif _type == TYPE_DIMENSION:
            return "%f%s" % (complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type == TYPE_FRACTION:
            return "%f%s" % (complexToFloat(_data) * 100, FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT:
            return "#%08X" % _data

        elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT:
            return "%d" % androconf.long2int(_data)

        return "<0x%X, type 0x%02X>" % (_data, _type)

    def getPackage(self, id):
        if id >> 24 == 1:
            return "android:"
        return ""


RES_NULL_TYPE               = 0x0000
RES_STRING_POOL_TYPE        = 0x0001
RES_TABLE_TYPE              = 0x0002
RES_XML_TYPE                = 0x0003

# Chunk types in RES_XML_TYPE
RES_XML_FIRST_CHUNK_TYPE    = 0x0100
RES_XML_START_NAMESPACE_TYPE= 0x0100
RES_XML_END_NAMESPACE_TYPE  = 0x0101
RES_XML_START_ELEMENT_TYPE  = 0x0102
RES_XML_END_ELEMENT_TYPE    = 0x0103
RES_XML_CDATA_TYPE          = 0x0104
RES_XML_LAST_CHUNK_TYPE     = 0x017f

# This contains a uint32_t array mapping strings in the string
# pool back to resource identifiers.  It is optional.
RES_XML_RESOURCE_MAP_TYPE   = 0x0180

# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE      = 0x0200
RES_TABLE_TYPE_TYPE         = 0x0201
RES_TABLE_TYPE_SPEC_TYPE    = 0x0202


class ARSCParser:
    def __init__(self, raw_buff):
        self.analyzed = False
        self.buff = bytecode.BuffHandle(raw_buff)
        #print "SIZE", hex(self.buff.size())

        self.header = ARSCHeader(self.buff)
        self.packageCount = unpack('<i', self.buff.read(4))[0]

        #print hex(self.packageCount)

        self.stringpool_main = StringBlock(self.buff)

        self.next_header = ARSCHeader(self.buff)
        self.packages = {}
        self.values = {}

        for i in range(0, self.packageCount):
            current_package = ARSCResTablePackage(self.buff)
            package_name = current_package.get_name()

            self.packages[package_name] = []

            mTableStrings = StringBlock(self.buff)
            mKeyStrings = StringBlock(self.buff)

            #self.stringpool_main.show()
            #self.mTableStrings.show()
            #self.mKeyStrings.show()

            self.packages[package_name].append(current_package)
            self.packages[package_name].append(mTableStrings)
            self.packages[package_name].append(mKeyStrings)

            pc = PackageContext(current_package, self.stringpool_main, mTableStrings, mKeyStrings)

            current = self.buff.get_idx()
            while not self.buff.end():
                header = ARSCHeader(self.buff)
                self.packages[package_name].append(header)

                if header.type == RES_TABLE_TYPE_SPEC_TYPE:
                    self.packages[package_name].append(ARSCResTypeSpec(self.buff, pc))

                elif header.type == RES_TABLE_TYPE_TYPE:
                    a_res_type = ARSCResType(self.buff, pc)
                    self.packages[package_name].append(a_res_type)

                    entries = []
                    for i in range(0, a_res_type.entryCount):
                        current_package.mResId = current_package.mResId & 0xffff0000 | i
                        entries.append((unpack('<i', self.buff.read(4))[0], current_package.mResId))

                    self.packages[package_name].append(entries)

                    for entry, res_id in entries:
                        if self.buff.end():
                            break

                        if entry != -1:
                            ate = ARSCResTableEntry(self.buff, res_id, pc)
                            self.packages[package_name].append(ate)

                elif header.type == RES_TABLE_PACKAGE_TYPE:
                    break
                else:
                    androconf.warning("unknown type")
                    break

                current += header.size
                self.buff.set_idx(current)

    def _analyse(self):
        if self.analyzed:
            return

        self.analyzed = True

        for package_name in self.packages:
            self.values[package_name] = {}

            nb = 3
            for header in self.packages[package_name][nb:]:
                if isinstance(header, ARSCHeader):
                    if header.type == RES_TABLE_TYPE_TYPE:
                        a_res_type = self.packages[package_name][nb + 1]

                        if a_res_type.config.get_language() not in self.values[package_name]:
                            self.values[package_name][a_res_type.config.get_language()] = {}
                            self.values[package_name][a_res_type.config.get_language()]["public"] = []

                        c_value = self.values[package_name][a_res_type.config.get_language()]

                        entries = self.packages[package_name][nb + 2]
                        nb_i = 0
                        for entry, res_id in entries:
                            if entry != -1:
                                ate = self.packages[package_name][nb + 3 + nb_i]

                                #print ate.is_public(), a_res_type.get_type(), ate.get_value(), hex(ate.mResId)
                                if ate.get_index() != -1:
                                    c_value["public"].append((a_res_type.get_type(), ate.get_value(), ate.mResId))

                                if a_res_type.get_type() not in c_value:
                                    c_value[a_res_type.get_type()] = []

                                if a_res_type.get_type() == "string":
                                    c_value["string"].append(self.get_resource_string(ate))

                                elif a_res_type.get_type() == "id":
                                    if not ate.is_complex():
                                        c_value["id"].append(self.get_resource_id(ate))

                                elif a_res_type.get_type() == "bool":
                                    if not ate.is_complex():
                                        c_value["bool"].append(self.get_resource_bool(ate))

                                elif a_res_type.get_type() == "integer":
                                    c_value["integer"].append(self.get_resource_integer(ate))

                                elif a_res_type.get_type() == "color":
                                    c_value["color"].append(self.get_resource_color(ate))

                                elif a_res_type.get_type() == "dimen":
                                    c_value["dimen"].append(self.get_resource_dimen(ate))

                                #elif a_res_type.get_type() == "style":
                                #    c_value["style"].append(self.get_resource_style(ate))

                                nb_i += 1
                nb += 1

    def get_resource_string(self, ate):
        return [ate.get_value(), ate.get_key_data()]

    def get_resource_id(self, ate):
        x = [ate.get_value()]
        if ate.key.get_data() == 0:
            x.append("false")
        elif ate.key.get_data() == 1:
            x.append("true")
        return x

    def get_resource_bool(self, ate):
        x = [ate.get_value()]
        if ate.key.get_data() == 0:
            x.append("false")
        elif ate.key.get_data() == -1:
            x.append("true")
        return x

    def get_resource_integer(self, ate):
        return [ate.get_value(), ate.key.get_data()]

    def get_resource_color(self, ate):
        entry_data = ate.key.get_data()
        return [ate.get_value(), "#%02x%02x%02x%02x" % (((entry_data >> 24) & 0xFF), ((entry_data >> 16) & 0xFF), ((entry_data >> 8) & 0xFF), (entry_data & 0xFF))]

    def get_resource_dimen(self, ate):
        try:
            return [ate.get_value(), "%s%s" % (complexToFloat(ate.key.get_data()), DIMENSION_UNITS[ate.key.get_data() & COMPLEX_UNIT_MASK])]
        except Exception, why:
            androconf.warning(why.__str__())
            return [ate.get_value(), ate.key.get_data()]

    # FIXME
    def get_resource_style(self, ate):
        return ["", ""]

    def get_packages_names(self):
        return self.packages.keys()

    def get_locales(self, package_name):
        self._analyse()
        return self.values[package_name].keys()

    def get_types(self, package_name, locale):
        self._analyse()
        return self.values[package_name][locale].keys()

    def get_public_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["public"]:
                buff += '<public type="%s" name="%s" id="0x%08x" />\n' % (i[0], i[1], i[2])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_string_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["string"]:
                buff += '<string name="%s">%s</string>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_strings_resources(self):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'

        buff += "<packages>\n"
        for package_name in self.get_packages_names():
            buff += "<package name=\"%s\">\n" % package_name

            for locale in self.get_locales(package_name):
                buff += "<locale value=%s>\n" % repr(locale)

                buff += '<resources>\n'
                try:
                    for i in self.values[package_name][locale]["string"]:
                        buff += '<string name="%s">%s</string>\n' % (i[0], i[1])
                except KeyError:
                    pass

                buff += '</resources>\n'
                buff += '</locale>\n'

            buff += "</package>\n"

        buff += "</packages>\n"

        return buff.encode('utf-8')

    def get_id_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["id"]:
                if len(i) == 1:
                    buff += '<item type="id" name="%s"/>\n' % (i[0])
                else:
                    buff += '<item type="id" name="%s">%s</item>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_bool_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["bool"]:
                buff += '<bool name="%s">%s</bool>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_integer_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["integer"]:
                buff += '<integer name="%s">%s</integer>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_color_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["color"]:
                buff += '<color name="%s">%s</color>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_dimen_resources(self, package_name, locale='\x00\x00'):
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["dimen"]:
                buff += '<dimen name="%s">%s</dimen>\n' % (i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_id(self, package_name, rid, locale='\x00\x00'):
        self._analyse()

        try:
            for i in self.values[package_name][locale]["public"]:
                if i[2] == rid:
                    return i
        except KeyError:
            return None

    def get_string(self, package_name, name, locale='\x00\x00'):
        self._analyse()

        try:
            for i in self.values[package_name][locale]["string"]:
                if i[0] == name:
                    return i
        except KeyError:
            return None

    def get_items(self, package_name):
        self._analyse()
        return self.packages[package_name]


class PackageContext:
    def __init__(self, current_package, stringpool_main, mTableStrings, mKeyStrings):
        self.stringpool_main = stringpool_main
        self.mTableStrings = mTableStrings
        self.mKeyStrings = mKeyStrings
        self.current_package = current_package

    def get_mResId(self):
        return self.current_package.mResId

    def set_mResId(self, mResId):
        self.current_package.mResId = mResId


class ARSCHeader:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self.type = unpack('<h', buff.read(2))[0]
        self.header_size = unpack('<h', buff.read(2))[0]
        self.size = unpack('<i', buff.read(4))[0]

        #print "ARSCHeader", hex(self.start), hex(self.type), hex(self.header_size), hex(self.size)


class ARSCResTablePackage:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self.id = unpack('<i', buff.read(4))[0]
        self.name = buff.readNullString(256)
        self.typeStrings = unpack('<i', buff.read(4))[0]
        self.lastPublicType = unpack('<i', buff.read(4))[0]
        self.keyStrings = unpack('<i', buff.read(4))[0]
        self.lastPublicKey = unpack('<i', buff.read(4))[0]
        self.mResId = self.id << 24

        #print "ARSCResTablePackage", hex(self.start), hex(self.id), hex(self.mResId), repr(self.name.decode("utf-16", errors='replace')), hex(self.typeStrings), hex(self.lastPublicType), hex(self.keyStrings), hex(self.lastPublicKey)

    def get_name(self):
        name = self.name.decode("utf-16", 'replace')
        name = name[:name.find("\x00")]
        return name


class ARSCResTypeSpec:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent
        self.id = unpack('<b', buff.read(1))[0]
        self.res0 = unpack('<b', buff.read(1))[0]
        self.res1 = unpack('<h', buff.read(2))[0]
        self.entryCount = unpack('<i', buff.read(4))[0]

        #print "ARSCResTypeSpec", hex(self.start), hex(self.id), hex(self.res0), hex(self.res1), hex(self.entryCount), "table:" + self.parent.mTableStrings.getString(self.id - 1)

        self.typespec_entries = []
        for i in range(0, self.entryCount):
            self.typespec_entries.append(unpack('<i', buff.read(4))[0])


class ARSCResType:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent
        self.id = unpack('<b', buff.read(1))[0]
        self.res0 = unpack('<b', buff.read(1))[0]
        self.res1 = unpack('<h', buff.read(2))[0]
        self.entryCount = unpack('<i', buff.read(4))[0]
        self.entriesStart = unpack('<i', buff.read(4))[0]
        self.mResId = (0xff000000 & self.parent.get_mResId()) | self.id << 16
        self.parent.set_mResId(self.mResId)

        #print "ARSCResType", hex(self.start), hex(self.id), hex(self.res0), hex(self.res1), hex(self.entryCount), hex(self.entriesStart), hex(self.mResId), "table:" + self.parent.mTableStrings.getString(self.id - 1)

        self.config = ARSCResTableConfig(buff)

    def get_type(self):
        return self.parent.mTableStrings.getString(self.id - 1)


class ARSCResTableConfig:
    def __init__(self, buff):
        self.start = buff.get_idx()
        self.size = unpack('<i', buff.read(4))[0]
        self.imsi = unpack('<i', buff.read(4))[0]
        self.locale = unpack('<i', buff.read(4))[0]
        self.screenType = unpack('<i', buff.read(4))[0]
        self.input = unpack('<i', buff.read(4))[0]
        self.screenSize = unpack('<i', buff.read(4))[0]
        self.version = unpack('<i', buff.read(4))[0]

        self.screenConfig = 0
        self.screenSizeDp = 0

        if self.size >= 32:
            self.screenConfig = unpack('<i', buff.read(4))[0]

            if self.size >= 36:
                self.screenSizeDp = unpack('<i', buff.read(4))[0]

        self.exceedingSize = self.size - 36
        if self.exceedingSize > 0:
            androconf.warning("too much bytes !")
            self.padding = buff.read(self.exceedingSize)

        #print "ARSCResTableConfig", hex(self.start), hex(self.size), hex(self.imsi), hex(self.locale), repr(self.get_language()), repr(self.get_country()), hex(self.screenType), hex(self.input), hex(self.screenSize), hex(self.version), hex(self.screenConfig), hex(self.screenSizeDp)

    def get_language(self):
        x = self.locale & 0x0000ffff
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)

    def get_country(self):
        x = (self.locale & 0xffff0000) >> 16
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)


class ARSCResTableEntry:
    def __init__(self, buff, mResId, parent=None):
        self.start = buff.get_idx()
        self.mResId = mResId
        self.parent = parent
        self.size = unpack('<h', buff.read(2))[0]
        self.flags = unpack('<h', buff.read(2))[0]
        self.index = unpack('<i', buff.read(4))[0]

        #print "ARSCResTableEntry", hex(self.start), hex(self.mResId), hex(self.size), hex(self.flags), hex(self.index), self.is_complex()#, hex(self.mResId)

        if self.flags & 1:
            self.item = ARSCComplex(buff, parent)
        else:
            self.key = ARSCResStringPoolRef(buff, self.parent)

    def get_index(self):
        return self.index

    def get_value(self):
        return self.parent.mKeyStrings.getString(self.index)

    def get_key_data(self):
        return self.key.get_data_value()

    def is_public(self):
        return self.flags == 0 or self.flags == 2

    def is_complex(self):
        return (self.flags & 1) == 1


class ARSCComplex:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent

        self.id_parent = unpack('<i', buff.read(4))[0]
        self.count = unpack('<i', buff.read(4))[0]

        self.items = []
        for i in range(0, self.count):
            self.items.append((unpack('<i', buff.read(4))[0], ARSCResStringPoolRef(buff, self.parent)))

        #print "ARSCComplex", hex(self.start), self.id_parent, self.count, repr(self.parent.mKeyStrings.getString(self.id_parent))


class ARSCResStringPoolRef:
    def __init__(self, buff, parent=None):
        self.start = buff.get_idx()
        self.parent = parent

        self.skip_bytes = buff.read(3)
        self.data_type = unpack('<b', buff.read(1))[0]
        self.data = unpack('<i', buff.read(4))[0]

        #print "ARSCResStringPoolRef", hex(self.start), hex(self.data_type), hex(self.data)#, "key:" + self.parent.mKeyStrings.getString(self.index), self.parent.stringpool_main.getString(self.data)

    def get_data_value(self):
        return self.parent.stringpool_main.getString(self.data)

    def get_data(self):
        return self.data

    def get_data_type(self):
        return self.data_type
