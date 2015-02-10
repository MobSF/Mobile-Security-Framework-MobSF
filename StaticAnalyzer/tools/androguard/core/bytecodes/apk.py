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


from tools.androguard.core import bytecode
from tools.androguard.core import androconf
from tools.androguard.core.bytecode import SV
from tools.androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS

import zipfile, StringIO
from struct import pack, unpack
from xml.dom import minidom
from xml.sax.saxutils import escape
from zlib import crc32
import re

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

def sign_apk(filename, keystore, storepass) :
    from subprocess import Popen, PIPE, STDOUT
  # jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore tmp/androguard.androtrace tmp/toto.apk alias_name
    compile = Popen([ androconf.CONF["PATH_JARSIGNER"],
                     "-sigalg", 
                     "MD5withRSA", 
                     "-digestalg", 
                     "SHA1", 

                     "-storepass", 
                     storepass,  

                     "-keystore", 
                     keystore, 

                     filename, 

                     "alias_name" ], 
                    stdout=PIPE, stderr=STDOUT)
    stdout, stderr = compile.communicate()

######################################################## APK FORMAT ########################################################
class APK :
    """APK manages apk file format"""
    def __init__(self, filename, raw=False, mode="r") :
        """
            @param filename : specify the path of the file, or raw data
            @param raw : specify (boolean) if the filename is a path or raw data
            @param mode
        """
        self.filename = filename

        self.xml = {}
        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.validAPK = False

        self.files = {}
        self.files_crc32 = {}

        if raw == True :
            self.__raw = filename
        else :
            fd = open( filename, "rb" )
            self.__raw = fd.read()
            fd.close()


        if ZIPMODULE == 0 :
            self.zip = ChilkatZip( self.__raw )
        else :
            self.zip = zipfile.ZipFile( StringIO.StringIO( self.__raw ), mode=mode )
        
        # CHECK if there is only one embedded file
        #self._reload_apk()

        for i in self.zip.namelist() :
            if i == "AndroidManifest.xml" :
                self.xml[i] = minidom.parseString( AXMLPrinter( self.zip.read( i ) ).getBuff() )

                self.package = self.xml[i].documentElement.getAttribute( "package" )
                self.androidversion["Code"] = self.xml[i].documentElement.getAttribute( "android:versionCode" )
                self.androidversion["Name"] = self.xml[i].documentElement.getAttribute( "android:versionName")

                for item in self.xml[i].getElementsByTagName('uses-permission') :
                    self.permissions.append( str( item.getAttribute("android:name") ) )

                self.validAPK = True

    def get_AndroidManifest(self) :
        """
            Return the Android Manifest XML file
        """
        return self.xml["AndroidManifest.xml"]

    def is_valid_APK(self) :
        """
            Return true if APK is valid, false otherwise
        """
        return self.validAPK

    #def _reload_apk(self) :
    #    if len(files) == 1 :
    #        if ".apk" in files[0] :
    #            self.__raw = self.zip.read( files[0] )
    #            if ZIPMODULE == 0 :
    #                self.zip = ChilkatZip( self.__raw )
    #            else :
    #                self.zip = zipfile.ZipFile( StringIO.StringIO( self.__raw ) )

    def get_filename(self) :
        """
            Return the filename of the APK
        """
        return self.filename

    def get_package(self) :
        """
            Return the name of the package
        """
        return self.package

    def get_androidversion_code(self) :
        """
            Return the android version code
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self) :
        """
            Return the android version name 
        """
        return self.androidversion["Name"]

    def get_files(self) :
        """
            Return the files inside the APK
        """
        return self.zip.namelist()

    def get_files_types(self) :
        """
            Return the files inside the APK with their types (by using python-magic)
        """
        try : 
            import magic
        except ImportError :
            for i in self.get_files() :
                buffer = self.zip.read( i )
                self.files_crc32[ i ] = crc32( buffer )
            return self.files

        if self.files != {} :
            return self.files

        builtin_magic = 0
        try :
            getattr(magic, "Magic")
        except AttributeError :
            builtin_magic = 1
                
        if builtin_magic :
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            
            for i in self.get_files() :
                buffer = self.zip.read( i )
                self.files[ i ] = ms.buffer( buffer )
                self.files[ i ] = self.patch_magic(buffer, self.files[ i ])
                self.files_crc32[ i ] = crc32( buffer )
        else :
            m = magic.Magic()
            for i in self.get_files() :
                buffer = self.zip.read( i )
                self.files[ i ] = m.from_buffer( buffer )
                self.files[ i ] = self.patch_magic(buffer, self.files[ i ])
                self.files_crc32[ i ] = crc32( buffer )

        return self.files 

    def patch_magic(self, buffer, orig) :
        if ("Zip" in orig) or ("DBase" in orig) :
            val = androconf.is_android_raw( buffer )
            if val == "APK" :
                return "Android application package file"
            elif val == "AXML" :
                return "Android's binary XML"

        return orig

    def get_files_crc32(self) :
        if self.files_crc32 == {} :
            self.get_files_types()
        
        return self.files_crc32

    def get_files_information(self) :
        if self.files == {} :
            self.get_files_types()

        for i in self.get_files() :
            yield i, self.files[ i ], self.files_crc32[ i ]

    def get_raw(self) :
        """ 
            Return raw bytes of the APK
        """
        return self.__raw

    def get_file(self, filename) :
        """
            Return the raw data of the specified filename
        """
        try :
            return self.zip.read( filename )
        except KeyError :
            return ""

    def get_dex(self) :
        """
            Return the raw data of the classes dex file
        """
        return self.get_file( "classes.dex" )

    def get_elements(self, tag_name, attribute) :
        """
            Return elements in xml files which match with the tag name and the specific attribute

            @param tag_name : a string which specify the tag name
            @param attribute : a string which specify the attribute
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

    def get_element(self, tag_name, attribute) :
        """
            Return element in xml files which match with the tag name and the specific attribute

            @param tag_name : a string which specify the tag name
            @param attribute : a string which specify the attribute
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
        """
        return self.get_elements("activity", "android:name")

    def get_services(self) :
        """
            Return the android:name attribute of all services
        """
        return self.get_elements("service", "android:name")

    def get_receivers(self) :
        """
            Return the android:name attribute of all receivers
        """
        return self.get_elements("receiver", "android:name")

    def get_providers(self) :
        """
            Return the android:name attribute of all providers
        """
        return self.get_elements("provider", "android:name")

    def get_permissions(self) :
        """
            Return permissions
        """
        return self.permissions

    def get_details_permissions(self) :
        """
            Return permissions with details
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

    def get_min_sdk_version(self) :
        """
            Return the android:minSdkVersion attribute
        """
        return self.get_element( "uses-sdk", "android:minSdkVersion" )

    def get_target_sdk_version(self) :
        """
            Return the android:targetSdkVersion attribute
        """
        return self.get_element( "uses-sdk", "android:targetSdkVersion" )

    def get_libraries(self) :
        """
            Return the android:name attributes for libraries
        """
        return self.get_elements( "uses-library", "android:name" )

    def show(self) :
        self.get_files_types()
        
        print "FILES: "
        for i in self.get_files() :
            try :
                print "\t", i, self.files[i], "%x" % self.files_crc32[i]
            except KeyError :
                print "\t", i, "%x" % self.files_crc32[i]

        print "PERMISSIONS: "
        details_permissions = self.get_details_permissions()
        for i in details_permissions :
            print "\t", i, details_permissions[i]
        print "MAIN ACTIVITY: ", self.get_main_activity()
        print "ACTIVITIES: ", self.get_activities()
        print "SERVICES: ", self.get_services()
        print "RECEIVERS: ", self.get_receivers()
        print "PROVIDERS: ", self.get_providers()

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
        zout = zipfile.ZipFile (filename, 'w')

        for item in self.zip.infolist() :
           
            if deleted_files != None :
                if re.match(deleted_files, item.filename) == None :
                    if item.filename in new_files :
                        zout.writestr(item, new_files[item.filename])
                    else :
                        buffer = self.zip.read(item.filename)
                        zout.writestr(item, buffer)
        zout.close()

def show_Certificate(cert) :
    print "Issuer: C=%s, CN=%s, DN=%s, E=%s, L=%s, O=%s, OU=%s, S=%s" % (cert.issuerC(), cert.issuerCN(), cert.issuerDN(), cert.issuerE(), cert.issuerL(), cert.issuerO(), cert.issuerOU(), cert.issuerS())
    print "Subject: C=%s, CN=%s, DN=%s, E=%s, L=%s, O=%s, OU=%s, S=%s" % (cert.subjectC(), cert.subjectCN(), cert.subjectDN(), cert.subjectE(), cert.subjectL(), cert.subjectO(), cert.subjectOU(), cert.subjectS())


######################################################## AXML FORMAT ########################################################
# Translated from http://code.google.com/p/android4me/source/browse/src/android/content/res/AXmlResourceParser.java
class StringBlock :
    def __init__(self, buff) :
        buff.read( 4 )

        self.chunkSize = SV( '<L', buff.read( 4 ) )
        self.stringCount = SV( '<L', buff.read( 4 ) )
        self.styleOffsetCount = SV( '<L', buff.read( 4 ) )
        
        # unused value ?
        buff.read(4) # ?
        
        self.stringsOffset = SV( '<L', buff.read( 4 ) )
        self.stylesOffset = SV( '<L', buff.read( 4 ) )

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_strings = []
        self.m_styles = []

        for i in range(0, self.stringCount.get_value()) :
            self.m_stringOffsets.append( SV( '<L', buff.read( 4 ) ) )

        for i in range(0, self.styleOffsetCount.get_value()) :
            self.m_stylesOffsets.append( SV( '<L', buff.read( 4 ) ) )

        size = self.chunkSize.get_value() - self.stringsOffset.get_value()
        if self.stylesOffset.get_value() != 0 :
            size = self.stylesOffset.get_value() - self.stringsOffset.get_value()

        # FIXME
        if (size%4) != 0 :
            pass

        for i in range(0, size / 4) :
            self.m_strings.append( SV( '=L', buff.read( 4 ) ) )

        if self.stylesOffset.get_value() != 0 :
            size = self.chunkSize.get_value() - self.stringsOffset.get_value()
            
            # FIXME
            if (size%4) != 0 :
                pass

            for i in range(0, size / 4) :
                self.m_styles.append( SV( '=L', buff.read( 4 ) ) )

    def getRaw(self, idx) :
        if idx < 0 or self.m_stringOffsets == [] or idx >= len(self.m_stringOffsets) :
            return None

        offset = self.m_stringOffsets[ idx ].get_value()
        length = self.getShort(self.m_strings, offset)

        data = ""

        while length > 0 :
            offset += 2
            # Unicode character
            data += unichr( self.getShort(self.m_strings, offset) )
            
            # FIXME
            if data[-1] == "&" :
                data = data[:-1]

            length -= 1

        return data

    def getShort(self, array, offset) :
        value = array[offset/4].get_value()
        if ((offset%4)/2) == 0 :
            return value & 0xFFFF
        else :
            return value >> 16

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
class AXMLParser :
    def __init__(self, raw_buff) :
        self.reset()

        self.buff = bytecode.BuffHandle( raw_buff )

        self.buff.read(4)
        self.buff.read(4)

        self.sb = StringBlock( self.buff )

        self.m_resourceIDs = []
        self.m_prefixuri = {}
        self.m_uriprefix = {}
        self.m_prefixuriL = []

    def reset(self) :
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def next(self) :
        self.doNext()
        return self.m_event

    def doNext(self) :
        if self.m_event == END_DOCUMENT :
            return

        event = self.m_event

        self.reset()
        while 1 :
            chunkType = -1

            # Fake END_DOCUMENT event.
            if event == END_TAG :
                pass

            # START_DOCUMENT
            if event == START_DOCUMENT :
                chunkType = CHUNK_XML_START_TAG
            else :
                if self.buff.end() == True :
                    self.m_event = END_DOCUMENT
                    break
                chunkType = SV( '<L', self.buff.read( 4 ) ).get_value()


            if chunkType == CHUNK_RESOURCEIDS :
                chunkSize = SV( '<L', self.buff.read( 4 ) ).get_value()
                # FIXME
                if chunkSize < 8 or chunkSize%4 != 0 :
                    raise("ooo")

                for i in range(0, chunkSize/4-2) :
                    self.m_resourceIDs.append( SV( '<L', self.buff.read( 4 ) ) )

                continue

            # FIXME
            if chunkType < CHUNK_XML_FIRST or chunkType > CHUNK_XML_LAST :
                raise("ooo")

            # Fake START_DOCUMENT event.
            if chunkType == CHUNK_XML_START_TAG and event == -1 :
                self.m_event = START_DOCUMENT
                break

            self.buff.read( 4 ) #/*chunkSize*/
            lineNumber = SV( '<L', self.buff.read( 4 ) ).get_value()
            self.buff.read( 4 ) #0xFFFFFFFF

            if chunkType == CHUNK_XML_START_NAMESPACE or chunkType == CHUNK_XML_END_NAMESPACE :
                if chunkType == CHUNK_XML_START_NAMESPACE :
                    prefix = SV( '<L', self.buff.read( 4 ) ).get_value()
                    uri = SV( '<L', self.buff.read( 4 ) ).get_value()

                    self.m_prefixuri[ prefix ] = uri
                    self.m_uriprefix[ uri ] = prefix
                    self.m_prefixuriL.append( (prefix, uri) )
                else :
                    self.buff.read( 4 )
                    self.buff.read( 4 )
                    (prefix, uri) = self.m_prefixuriL.pop()
                    #del self.m_prefixuri[ prefix ]
                    #del self.m_uriprefix[ uri ]

                continue


            self.m_lineNumber = lineNumber

            if chunkType == CHUNK_XML_START_TAG :
                self.m_namespaceUri = SV( '<L', self.buff.read( 4 ) ).get_value()
                self.m_name = SV( '<L', self.buff.read( 4 ) ).get_value()

                # FIXME
                self.buff.read( 4 ) #flags
                
                attributeCount = SV( '<L', self.buff.read( 4 ) ).get_value()
                self.m_idAttribute = (attributeCount>>16) - 1
                attributeCount = attributeCount & 0xFFFF
                self.m_classAttribute = SV( '<L', self.buff.read( 4 ) ).get_value()
                self.m_styleAttribute = (self.m_classAttribute>>16) - 1

                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                for i in range(0, attributeCount*ATTRIBUTE_LENGHT) :
                    self.m_attributes.append( SV( '<L', self.buff.read( 4 ) ).get_value() )

                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGHT) :
                    self.m_attributes[i] = (self.m_attributes[i]>>24)

                self.m_event = START_TAG
                break

            if chunkType == CHUNK_XML_END_TAG :
                self.m_namespaceUri = SV( '<L', self.buff.read( 4 ) ).get_value()
                self.m_name = SV( '<L', self.buff.read( 4 ) ).get_value()
                self.m_event = END_TAG
                break

            if chunkType == CHUNK_XML_TEXT :
                self.m_name = SV( '<L', self.buff.read( 4 ) ).get_value()
                
                # FIXME
                self.buff.read( 4 ) #?
                self.buff.read( 4 ) #?

                self.m_event = TEXT
                break

    def getPrefixByUri(self, uri) :
        try :
            return self.m_uriprefix[ uri ]
        except KeyError :
            return -1

    def getPrefix(self) :
        try :
            return self.sb.getRaw(self.m_prefixuri[ self.m_namespaceUri ])
        except KeyError :
            return ""

    def getName(self) :
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG) :
            return ""

        return self.sb.getRaw(self.m_name)

    def getText(self) :
        if self.m_name == -1 or self.m_event != TEXT :
            return ""

        return self.sb.getRaw(self.m_name)

    def getNamespacePrefix(self, pos) :
        prefix = self.m_prefixuriL[ pos ][0]
        return self.sb.getRaw( prefix )

    def getNamespaceUri(self, pos) :
        uri = self.m_prefixuriL[ pos ][1]
        return self.sb.getRaw( uri )

    def getXMLNS(self) :
        buff = ""
        
        i = 0
        while 1 :
            try :
                buff += "xmlns:%s=\"%s\"\n" % ( self.getNamespacePrefix( i ), self.getNamespaceUri( i ) )
            except IndexError:
                break
            
            i += 1

        return buff

    def getNamespaceCount(self, pos) :
        pass

    def getAttributeOffset(self, index) :
        # FIXME
        if self.m_event != START_TAG :
            raise("Current event is not START_TAG.")

        offset = index * 5
        # FIXME
        if offset >= len(self.m_attributes) :
            raise("Invalid attribute index")

        return offset

    def getAttributeCount(self) :
        if self.m_event != START_TAG :
            return -1

        return len(self.m_attributes) / ATTRIBUTE_LENGHT

    def getAttributePrefix(self, index) :
        offset = self.getAttributeOffset(index)
        uri = self.m_attributes[offset+ATTRIBUTE_IX_NAMESPACE_URI]

        prefix = self.getPrefixByUri( uri )
        if prefix == -1 :
            return ""

        return self.sb.getRaw( prefix )

    def getAttributeName(self, index) :
        offset = self.getAttributeOffset(index)
        name = self.m_attributes[offset+ATTRIBUTE_IX_NAME]

        if name == -1 :
            return ""

        return self.sb.getRaw( name )

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
            return self.sb.getRaw( valueString )
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
DIMENSION_UNITS         =   [ "px","dip","sp","pt","in","mm","","" ]
FRACTION_UNITS          =   [ "%","%p","","","","","","" ]

COMPLEX_UNIT_MASK        =   15

class AXMLPrinter :
    def __init__(self, raw_buff) :
        self.axml = AXMLParser( raw_buff )
        self.xmlns = False

        self.buff = ""

        while 1 :
            _type = self.axml.next()
#           print "tagtype = ", _type

            if _type == START_DOCUMENT :
                self.buff += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            elif _type == START_TAG :
                self.buff += "<%s%s\n" % ( self.getPrefix( self.axml.getPrefix() ), self.axml.getName() )

                # FIXME : use namespace
                if self.xmlns == False :
                    self.buff += self.axml.getXMLNS()
                    self.xmlns = True

                for i in range(0, self.axml.getAttributeCount()) :
                    self.buff += "%s%s=\"%s\"\n" % ( self.getPrefix(
                        self.axml.getAttributePrefix(i) ), self.axml.getAttributeName(i), self._escape( self.getAttributeValue( i ) ) )

                self.buff += ">\n"

            elif _type == END_TAG :
                self.buff += "</%s%s>\n" % ( self.getPrefix( self.axml.getPrefix() ), self.axml.getName() )

            elif _type == TEXT :
                self.buff += "%s\n" % self.axml.getText()

            elif _type == END_DOCUMENT :
                break

    # pleed patch
    def _escape(self, s) :
        s = s.replace("&","&amp;")
        s = s.replace('"',"&quot;")
        s = s.replace("'","&apos;")
        s = s.replace("<","&lt;")
        s = s.replace(">","&gt;")
      
        return escape(s)


    def getBuff(self) :
        return self.buff.encode("utf-8")

    def getPrefix(self, prefix) :
        if prefix == None or len(prefix) == 0 :
            return ""

        return prefix + ":"

    def getAttributeValue(self, index) :
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        #print _type, _data
        if _type == TYPE_STRING :
            return self.axml.getAttributeValue( index )

        elif _type == TYPE_ATTRIBUTE :
            return "?%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_REFERENCE :
            return "@%s%08X" % (self.getPackage(_data), _data)

        # WIP
        elif _type == TYPE_FLOAT :
            return "%f" % unpack("=f", pack("=L", _data))[0] 

        elif _type == TYPE_INT_HEX :
            return "0x%08X" % _data

        elif _type == TYPE_INT_BOOLEAN :
            if _data == 0 :
                return "false"
            return "true"

        elif _type == TYPE_DIMENSION :
            return "%f%s" % (self.complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type == TYPE_FRACTION :
            return "%f%s" % (self.complexToFloat(_data), FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT :
            return "#%08X" % _data

        elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT :
            return "%d" % androconf.long2int( _data )

        return "<0x%X, type 0x%02X>" % (_data, _type)

    def complexToFloat(self, xcomplex) :
        return (float)(xcomplex & 0xFFFFFF00)*RADIX_MULTS[(xcomplex>>4) & 3];

    def getPackage(self, id) :
        if id >> 24 == 1 :
            return "android:"
        return ""

