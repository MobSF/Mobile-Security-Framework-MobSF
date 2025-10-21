# -*- coding: utf_8 -*-
# flake8: noqa
from .resources import public
from .types import *

from struct import pack, unpack
from xml.sax.saxutils import escape
import collections
from collections import defaultdict

from lxml import etree
import re
import binascii
import io
import logging

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)

# Constants for ARSC Files
# see http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#233
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_FIRST_CHUNK_TYPE          = 0x0100
RES_XML_START_NAMESPACE_TYPE      = 0x0100
RES_XML_END_NAMESPACE_TYPE        = 0x0101
RES_XML_START_ELEMENT_TYPE        = 0x0102
RES_XML_END_ELEMENT_TYPE          = 0x0103
RES_XML_CDATA_TYPE                = 0x0104
RES_XML_LAST_CHUNK_TYPE           = 0x017f

RES_XML_RESOURCE_MAP_TYPE         = 0x0180

RES_TABLE_PACKAGE_TYPE            = 0x0200
RES_TABLE_TYPE_TYPE               = 0x0201
RES_TABLE_TYPE_SPEC_TYPE          = 0x0202
RES_TABLE_LIBRARY_TYPE            = 0x0203
RES_TABLE_OVERLAYABLE_TYPE        = 0x0204
RES_TABLE_OVERLAYABLE_POLICY_TYPE = 0x0205
RES_TABLE_STAGED_ALIAS_TYPE       = 0x0206
# Flags in the STRING Section
SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

# Position of the fields inside an attribute
ATTRIBUTE_IX_NAMESPACE_URI = 0
ATTRIBUTE_IX_NAME = 1
ATTRIBUTE_IX_VALUE_STRING = 2
ATTRIBUTE_IX_VALUE_TYPE = 3
ATTRIBUTE_IX_VALUE_DATA = 4
ATTRIBUTE_LENGTH = 5

# Internally used state variables for AXMLParser
START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4

# Table used to lookup functions to determine the value representation in ARSCParser
TYPE_TABLE = {
    TYPE_ATTRIBUTE: "attribute",
    TYPE_DIMENSION: "dimension",
    TYPE_FLOAT: "float",
    TYPE_FRACTION: "fraction",
    TYPE_INT_BOOLEAN: "int_boolean",
    TYPE_INT_COLOR_ARGB4: "int_color_argb4",
    TYPE_INT_COLOR_ARGB8: "int_color_argb8",
    TYPE_INT_COLOR_RGB4: "int_color_rgb4",
    TYPE_INT_COLOR_RGB8: "int_color_rgb8",
    TYPE_INT_DEC: "int_dec",
    TYPE_INT_HEX: "int_hex",
    TYPE_NULL: "null",
    TYPE_REFERENCE: "reference",
    TYPE_STRING: "string",
}

RADIX_MULTS = [0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

COMPLEX_UNIT_MASK = 0x0F


class ResParserError(Exception):
    """Exception for the parsers"""
    pass


def complexToFloat(xcomplex):
    """
    Convert a complex unit into float
    """
    return float(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]


class StringBlock:
    """
    StringBlock is a CHUNK inside an AXML File: `ResStringPool_header`
    It contains all strings, which are used by referecing to ID's

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#436
    """
    def __init__(self, buff, header):
        """
        :param buff: buffer which holds the string block
        :param header: a instance of :class:`~ARSCHeader`
        """
        self._cache = {}
        self.header = header
        # We already read the header (which was chunk_type and chunk_size
        # Now, we read the string_count:
        self.stringCount = unpack('<I', buff.read(4))[0]
        # style_count
        self.styleCount = unpack('<I', buff.read(4))[0]

        # flags
        self.flags = unpack('<I', buff.read(4))[0]
        self.m_isUTF8 = ((self.flags & UTF8_FLAG) != 0)

        # string_pool_offset
        # The string offset is counted from the beginning of the string section
        self.stringsOffset = unpack('<I', buff.read(4))[0]
        # check if the stringCount is correct
        if (self.stringsOffset - (self.styleCount * 4 + 28)) / 4 != self.stringCount:
            self.stringCount = int((self.stringsOffset - (self.styleCount * 4 + 28)) / 4)

        # style_pool_offset
        # The styles offset is counted as well from the beginning of the string section
        self.stylesOffset = unpack('<I', buff.read(4))[0]

        # Check if they supplied a stylesOffset even if the count is 0:
        if self.styleCount == 0 and self.stylesOffset > 0:
            logger.info("Styles Offset given, but styleCount is zero. "
                     "This is not a problem but could indicate packers.")

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_charbuff = ""
        self.m_styles = []

        # Next, there is a list of string following.
        # This is only a list of offsets (4 byte each)
        for i in range(self.stringCount):
            self.m_stringOffsets.append(unpack('<I', buff.read(4))[0])

        # And a list of styles
        # again, a list of offsets
        for i in range(self.styleCount):
            self.m_styleOffsets.append(unpack('<I', buff.read(4))[0])

        # FIXME it is probably better to parse n strings and not calculate the size
        size = self.header.size - self.stringsOffset

        # if there are styles as well, we do not want to read them too.
        # Only read them, if no
        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.stylesOffset - self.stringsOffset

        if (size % 4) != 0:
            logger.warning("Size of strings is not aligned by four bytes.")

        self.m_charbuff = buff.read(size)

        if self.stylesOffset != 0 and self.styleCount != 0:
            size = self.header.size - self.stylesOffset

            if (size % 4) != 0:
                logger.warning("Size of styles is not aligned by four bytes.")

            for i in range(0, size // 4):
                self.m_styles.append(unpack('<I', buff.read(4))[0])

    def __repr__(self):
        return "<StringPool #strings={}, #styles={}, UTF8={}>".format(self.stringCount, self.styleCount, self.m_isUTF8)

    def __getitem__(self, idx):
        """
        Returns the string at the index in the string table
        """
        return self.getString(idx)

    def __len__(self):
        """
        Get the number of strings stored in this table
        """
        return self.stringCount

    def __iter__(self):
        """
        Iterable over all strings
        """
        for i in range(self.stringCount):
            yield self.getString(i)

    def getString(self, idx):
        """
        Return the string at the index in the string table

        :param idx: index in the string table
        :return: str
        """
        if idx in self._cache:
            return self._cache[idx]

        if idx < 0 or not self.m_stringOffsets or idx > self.stringCount:
            return ""

        offset = self.m_stringOffsets[idx]

        if self.m_isUTF8:
            self._cache[idx] = self._decode8(offset)
        else:
            self._cache[idx] = self._decode16(offset)

        return self._cache[idx]

    def getStyle(self, idx):
        """
        Return the style associated with the index

        :param idx: index of the style
        :return:
        """
        return self.m_styles[idx]

    def _decode8(self, offset):
        """
        Decode an UTF-8 String at the given offset

        :param offset: offset of the string inside the data
        :return: str
        """
        # UTF-8 Strings contain two lengths, as they might differ:
        # 1) the UTF-16 length
        str_len, skip = self._decode_length(offset, 1)
        offset += skip

        # 2) the utf-8 string length
        encoded_bytes, skip = self._decode_length(offset, 1)
        offset += skip

        data = self.m_charbuff[offset: offset + encoded_bytes]

        if self.m_charbuff[offset + encoded_bytes] != 0:
            raise ResParserError("UTF-8 String is not null terminated! At offset={}".format(offset))

        return self._decode_bytes(data, 'utf-8', str_len)

    def _decode16(self, offset):
        """
        Decode an UTF-16 String at the given offset

        :param offset: offset of the string inside the data
        :return: str
        """
        str_len, skip = self._decode_length(offset, 2)
        offset += skip

        # The len is the string len in utf-16 units
        encoded_bytes = str_len * 2

        data = self.m_charbuff[offset: offset + encoded_bytes]

        if self.m_charbuff[offset + encoded_bytes:offset + encoded_bytes + 2] != b"\x00\x00":
            raise ResParserError("UTF-16 String is not null terminated! At offset={}".format(offset))

        return self._decode_bytes(data, 'utf-16', str_len)

    @staticmethod
    def _decode_bytes(data, encoding, str_len):
        """
        Generic decoding with length check.
        The string is decoded from bytes with the given encoding, then the length
        of the string is checked.
        The string is decoded using the "replace" method.

        :param data: bytes
        :param encoding: encoding name ("utf-8" or "utf-16")
        :param str_len: length of the decoded string
        :return: str
        """
        string = data.decode(encoding, 'replace')
        if len(string) != str_len:
            logger.warning("invalid decoded string length")
        return string

    def _decode_length(self, offset, sizeof_char):
        """
        Generic Length Decoding at offset of string

        The method works for both 8 and 16 bit Strings.
        Length checks are enforced:
        * 8 bit strings: maximum of 0x7FFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#692)
        * 16 bit strings: maximum of 0x7FFFFFF bytes (See
        http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#670)

        :param offset: offset into the string data section of the beginning of
        the string
        :param sizeof_char: number of bytes per char (1 = 8bit, 2 = 16bit)
        :returns: tuple of (length, read bytes)
        """
        sizeof_2chars = sizeof_char << 1
        fmt = "<2{}".format('B' if sizeof_char == 1 else 'H')
        highbit = 0x80 << (8 * (sizeof_char - 1))

        length1, length2 = unpack(fmt, self.m_charbuff[offset:(offset + sizeof_2chars)])

        if (length1 & highbit) != 0:
            length = ((length1 & ~highbit) << (8 * sizeof_char)) | length2
            size = sizeof_2chars
        else:
            length = length1
            size = sizeof_char

        # These are true asserts, as the size should never be less than the values
        if sizeof_char == 1:
            assert length <= 0x7FFF, "length of UTF-8 string is too large! At offset={}".format(offset)
        else:
            assert length <= 0x7FFFFFFF, "length of UTF-16 string is too large!  At offset={}".format(offset)

        return length, size

    def show(self):
        """
        Print some information on stdout about the string table
        """
        print("StringBlock(stringsCount=0x%x, "
              "stringsOffset=0x%x, "
              "stylesCount=0x%x, "
              "stylesOffset=0x%x, "
              "flags=0x%x"
              ")" % (self.stringCount,
                     self.stringsOffset,
                     self.styleCount,
                     self.stylesOffset,
                     self.flags))

        if self.stringCount > 0:
            print()
            print("String Table: ")
            for i, s in enumerate(self):
                print("{:08d} {}".format(i, repr(s)))

        if self.styleCount > 0:
            print()
            print("Styles Table: ")
            for i in range(self.styleCount):
                print("{:08d} {}".format(i, repr(self.getStyle(i))))


class AXMLParser:
    """
    AXMLParser reads through all chunks in the AXML file
    and implements a state machine to return information about
    the current chunk, which can then be read by :class:`~AXMLPrinter`.

    An AXML file is a file which contains multiple chunks of data, defined
    by the `ResChunk_header`.
    There is no real file magic but as the size of the first header is fixed
    and the `type` of the `ResChunk_header` is set to `RES_XML_TYPE`, a file
    will usually start with `0x03000800`.
    But there are several examples where the `type` is set to something
    else, probably in order to fool parsers.

    Typically the AXMLParser is used in a loop which terminates if `m_event` is set to `END_DOCUMENT`.
    You can use the `next()` function to get the next chunk.
    Note that not all chunk types are yielded from the iterator! Some chunks are processed in
    the AXMLParser only.
    The parser will set `is_valid()` to False if it parses something not valid.
    Messages what is wrong are logged.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#563
    """
    def __init__(self, raw_buff):
        logger.debug("AXMLParser")

        self._reset()

        self._valid = True
        self.axml_tampered = False
        self.buff = io.BufferedReader(io.BytesIO(raw_buff))
        self.buff_size = self.buff.raw.getbuffer().nbytes

        # Minimum is a single ARSCHeader, which would be a strange edge case...
        if self.buff_size < 8:
            logger.error("Filesize is too small to be a valid AXML file! Filesize: {}".format(self.buff_size))
            self._valid = False
            return

        # This would be even stranger, if an AXML file is larger than 4GB...
        # But this is not possible as the maximum chunk size is a unsigned 4 byte int.
        if self.buff_size > 0xFFFFFFFF:
            logger.error("Filesize is too large to be a valid AXML file! Filesize: {}".format(self.buff_size))
            self._valid = False
            return

        try:
            axml_header = ARSCHeader(self.buff)
            logger.debug("FIRST HEADER {}".format(axml_header))
        except ResParserError as e:
            logger.error("Error parsing first resource header: %s", e)
            self._valid = False
            return

        self.filesize = axml_header.size

        if axml_header.header_size == 28024:
            # Can be a common error: the file is not an AXML but a plain XML
            # The file will then usually start with '<?xm' / '3C 3F 78 6D'
            logger.warning("Header size is 28024! Are you trying to parse a plain XML file?")

        if axml_header.header_size != 8:
            logger.error("This does not look like an AXML file. header size does not equal 8! header size = {}".format(axml_header.header_size))
            self._valid = False
            return

        if self.filesize > self.buff_size:
            logger.error("This does not look like an AXML file. Declared filesize does not match real size: {} vs {}".format(self.filesize, self.buff_size))
            self._valid = False
            return

        if self.filesize < self.buff_size:
            # The file can still be parsed up to the point where the chunk should end.
            self.axml_tampered = True
            logger.warning("Declared filesize ({}) is smaller than total file size ({}). "
                        "Was something appended to the file? Trying to parse it anyways.".format(self.filesize, self.buff.size()))

        # Not that severe of an error, we have plenty files where this is not
        # set correctly
        if axml_header.type != RES_XML_TYPE:
            self.axml_tampered = True
            logger.warning("AXML file has an unusual resource type! "
                           "Malware likes to to such stuff to anti androguard! "
                           "But we try to parse it anyways. Resource Type: 0x{:04x}".format(axml_header.type))

        # Now we parse the STRING POOL
        try:
            header = ARSCHeader(self.buff, expected_type=RES_STRING_POOL_TYPE)
            logger.debug("STRING_POOL {}".format(header))
        except ResParserError as e:
            logger.error("Error parsing resource header of string pool: {}".format(e))
            self._valid = False
            return

        if header.header_size != 0x1C:
            logger.error("This does not look like an AXML file. String chunk header size does not equal 28! header size = {}".format(header.header_size))
            self._valid = False
            return

        self.sb = StringBlock(self.buff, header)

        self.buff.seek(axml_header.header_size + header.size)

        # Stores resource ID mappings, if any
        self.m_resourceIDs = []

        # Store a list of prefix/uri mappings encountered
        self.namespaces = []

    def is_valid(self):
        """
        Get the state of the AXMLPrinter.
        if an error happend somewhere in the process of parsing the file,
        this flag is set to False.
        """
        logger.debug(self._valid)
        return self._valid

    def _reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def __next__(self):
        self._do_next()
        return self.m_event

    def _do_next(self):
        logger.debug("M_EVENT {}".format(self.m_event))

        if self.m_event == END_DOCUMENT:
            return

        self._reset()
        while self._valid:
            # Stop at the declared filesize or at the end of the file
            if self.buff.tell() == self.filesize:
                self.m_event = END_DOCUMENT
                break

            # Again, we read an ARSCHeader
            try:
                possible_types = {256, 257, 258, 259, 260, 384}
                h = ARSCHeader(self.buff, possible_types=possible_types)
                logger.debug("NEXT HEADER {}".format(h))
            except ResParserError as e:
                logger.error("Error parsing resource header: {}".format(e))
                self._valid = False
                return

            # Special chunk: Resource Map. This chunk might be contained inside
            # the file, after the string pool.
            if h.type == RES_XML_RESOURCE_MAP_TYPE:
                logger.debug("AXML contains a RESOURCE MAP")
                # Check size: < 8 bytes mean that the chunk is not complete
                # Should be aligned to 4 bytes.
                if h.size < 8 or (h.size % 4) != 0:
                    logger.error("Invalid chunk size in chunk XML_RESOURCE_MAP")
                    self._valid = False
                    return

                for i in range((h.size - h.header_size) // 4):
                    self.m_resourceIDs.append(unpack('<L', self.buff.read(4))[0])

                continue

            # Parse now the XML chunks.
            # unknown chunk types might cause problems, but we can skip them!
            if h.type < RES_XML_FIRST_CHUNK_TYPE or h.type > RES_XML_LAST_CHUNK_TYPE:
                # h.size is the size of the whole chunk including the header.
                # We read already 8 bytes of the header, thus we need to
                # subtract them.
                logger.error("Not a XML resource chunk type: 0x{:04x}. Skipping {} bytes".format(h.type, h.size))
                self.buff.seek(h.end)
                continue

            # Check that we read a correct header
            if h.header_size != 0x10:
                logger.error("XML Resource Type Chunk header size does not match 16! " \
                "At chunk type 0x{:04x}, declared header size=0x{:04x}, chunk size=0x{:04x}".format(h.type, h.header_size, h.size))
                self.buff.seek(h.end)
                continue

            # Line Number of the source file, only used as meta information
            self.m_lineNumber, = unpack('<L', self.buff.read(4))

            # Comment_Index (usually 0xFFFFFFFF)
            self.m_comment_index, = unpack('<L', self.buff.read(4))

            if self.m_comment_index != 0xFFFFFFFF and h.type in [RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE]:
                logger.warning("Unhandled Comment at namespace chunk: '{}'".format(self.sb[self.m_comment_index]))

            if h.type == RES_XML_START_NAMESPACE_TYPE:
                prefix, = unpack('<L', self.buff.read(4))
                uri, = unpack('<L', self.buff.read(4))

                s_prefix = self.sb[prefix]
                s_uri = self.sb[uri]

                logger.debug("Start of Namespace mapping: prefix {}: '{}' --> uri {}: '{}'".format(prefix, s_prefix, uri, s_uri))

                if s_uri == '':
                    logger.warning("Namespace prefix '{}' resolves to empty URI. "
                                "This might be a packer.".format(s_prefix))

                if (prefix, uri) in self.namespaces:
                    logger.debug("Namespace mapping ({}, {}) already seen! "
                             "This is usually not a problem but could indicate packers or broken AXML compilers.".format(prefix, uri))
                self.namespaces.append((prefix, uri))

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            if h.type == RES_XML_END_NAMESPACE_TYPE:
                # END_PREFIX contains again prefix and uri field
                prefix, = unpack('<L', self.buff.read(4))
                uri, = unpack('<L', self.buff.read(4))

                # We remove the last namespace mapping matching
                if (prefix, uri) in self.namespaces:
                    self.namespaces.remove((prefix, uri))
                else:
                    logger.warning("Reached a NAMESPACE_END without having the namespace stored before? "
                                "Prefix ID: {}, URI ID: {}".format(prefix, uri))

                # We can continue with the next chunk, as we store the namespace
                # mappings for each tag
                continue

            # START_TAG is the start of a new tag.
            if h.type == RES_XML_START_ELEMENT_TYPE:
                # The TAG consists of some fields:
                # * (chunk_size, line_number, comment_index - we read before)
                # * namespace_uri
                # * name
                # * flags
                # * attribute_count
                # * class_attribute
                # After that, there are two lists of attributes, 20 bytes each

                # Namespace URI (String ID)
                self.m_namespaceUri, = unpack('<L', self.buff.read(4))
                # Name of the Tag (String ID)
                self.m_name, = unpack('<L', self.buff.read(4))
                self.at_start, self.at_size = unpack('<HH', self.buff.read(4))
                # Attribute Count
                attributeCount, = unpack('<L', self.buff.read(4))
                # Class Attribute
                self.m_classAttribute, = unpack('<L', self.buff.read(4))

                self.m_idAttribute = (attributeCount >> 16) - 1
                self.m_attribute_count = attributeCount & 0xFFFF
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1
                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                # Now, we parse the attributes.
                # Each attribute has 5 fields of 4 byte
                for i in range(0, self.m_attribute_count):
                    # Each field is linearly parsed into the array
                    # Each Attribute contains:
                    # * Namespace URI (String ID)
                    # * Name (String ID)
                    # * Value
                    # * Type
                    # * Data
                    for j in range(0, ATTRIBUTE_LENGTH):
                        self.m_attributes.append(unpack('<L', self.buff.read(4))[0])
                    if self.at_size != 20:
                        self.buff.read(self.at_size - 20)

                # Then there are class_attributes
                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGTH):
                    self.m_attributes[i] = self.m_attributes[i] >> 24

                self.m_event = START_TAG
                break

            if h.type == RES_XML_END_ELEMENT_TYPE:
                self.m_namespaceUri, = unpack('<L', self.buff.read(4))
                self.m_name, = unpack('<L', self.buff.read(4))

                self.m_event = END_TAG
                break

            if h.type == RES_XML_CDATA_TYPE:
                # The CDATA field is like an attribute.
                # It contains an index into the String pool
                # as well as a typed value.
                # usually, this typed value is set to UNDEFINED

                # ResStringPool_ref data --> uint32_t index
                self.m_name, = unpack('<L', self.buff.read(4))

                # Res_value typedData:
                # uint16_t size
                # uint8_t res0 -> always zero
                # uint8_t dataType
                # uint32_t data
                # For now, we ingore these values
                size, res0, dataType, data = unpack("<HBBL", self.buff.read(8))

                logger.debug("found a CDATA Chunk: "
                          "index={: 6d}, size={: 4d}, res0={: 4d}, dataType={: 4d}, data={: 4d}".format(self.m_name,
                                                                                                        size,
                                                                                                        res0,
                                                                                                        dataType,
                                                                                                        data))

                self.m_event = TEXT
                break

            # Still here? Looks like we read an unknown XML header, try to skip it...
            logger.warning("Unknown XML Chunk: 0x{:04x}, skipping {} bytes.".format(h.type, h.size))
            self.buff.seek(h.end)

    @property
    def name(self):
        """
        Return the String assosciated with the tag name
        """
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG):
            return ''

        return self.sb[self.m_name]

    @property
    def comment(self):
        """
        Return the comment at the current position or None if no comment is given

        This works only for Tags, as the comments of Namespaces are silently dropped.
        Currently, there is no way of retrieving comments of namespaces.
        """
        if self.m_comment_index == 0xFFFFFFFF:
            return None

        return self.sb[self.m_comment_index]

    @property
    def namespace(self):
        """
        Return the Namespace URI (if any) as a String for the current tag
        """
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG):
            return ''

        # No Namespace
        if self.m_namespaceUri == 0xFFFFFFFF:
            return ''

        return self.sb[self.m_namespaceUri]

    @property
    def nsmap(self):
        """
        Returns the current namespace mapping as a dictionary

        there are several problems with the map and we try to guess a few
        things here:

        1) a URI can be mapped by many prefixes, so it is to decide which one to take
        2) a prefix might map to an empty string (some packers)
        3) uri+prefix mappings might be included several times
        4) prefix might be empty
        """

        NSMAP = dict()
        # solve 3) by using a set
        for k, v in set(self.namespaces):
            s_prefix = self.sb[k]
            s_uri = self.sb[v]
            # Solve 2) & 4) by not including
            if s_uri != "" and s_prefix != "":
                # solve 1) by using the last one in the list
                NSMAP[s_prefix] = s_uri

        return NSMAP

    @property
    def text(self):
        """
        Return the String assosicated with the current text
        """
        if self.m_name == -1 or self.m_event != TEXT:
            return ''

        return self.sb[self.m_name]

    def getName(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.name` instead
        """
        return self.name

    def getText(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.text` instead
        """
        return self.text

    def getPrefix(self):
        """
        Legacy only!
        use :py:attr:`~androguard.core.bytecodes.AXMLParser.namespace` instead
        """
        return self.namespace

    def _get_attribute_offset(self, index):
        """
        Return the start inside the m_attributes array for a given attribute
        """
        if self.m_event != START_TAG:
            logger.warning("Current event is not START_TAG.")

        offset = index * ATTRIBUTE_LENGTH
        if offset >= len(self.m_attributes):
            logger.warning("Invalid attribute index")

        return offset

    def getAttributeCount(self):
        """
        Return the number of Attributes for a Tag
        or -1 if not in a tag
        """
        if self.m_event != START_TAG:
            return -1

        return self.m_attribute_count

    def getAttributeUri(self, index):
        """
        Returns the numeric ID for the namespace URI of an attribute
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        return uri

    def getAttributeNamespace(self, index):
        """
        Return the Namespace URI (if any) for the attribute
        """
        logger.debug(index)

        uri = self.getAttributeUri(index)

        # No Namespace
        if uri == 0xFFFFFFFF:
            return ''

        return self.sb[uri]

    def getAttributeName(self, index):
        """
        Returns the String which represents the attribute name
        """
        logger.debug(index)
        offset = self._get_attribute_offset(index)
        name = self.m_attributes[offset + ATTRIBUTE_IX_NAME]

        res = self.sb[name]
        # If the result is a (null) string, we need to look it up.
        if not res or res == ":":
            attr = self.m_resourceIDs[name]
            if attr in public.SYSTEM_RESOURCES['attributes']['inverse']:
                res = 'android:' + public.SYSTEM_RESOURCES['attributes']['inverse'][attr]
            else:
                # Attach the HEX Number, so for multiple missing attributes we do not run
                # into problems.
                res = 'android:UNKNOWN_SYSTEM_ATTRIBUTE_{:08x}'.format(attr)
        return res

    def getAttributeValueType(self, index):
        """
        Return the type of the attribute at the given index

        :param index: index of the attribute
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index):
        """
        Return the data of the attribute at the given index

        :param index: index of the attribute
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index):
        """
        This function is only used to look up strings
        All other work is done by
        :func:`~androguard.core.bytecodes.axml.format_value`
        # FIXME should unite those functions
        :param index: index of the attribute
        :return:
        """
        logger.debug(index)

        offset = self._get_attribute_offset(index)
        valueType = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING:
            valueString = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_STRING]
            return self.sb[valueString]
        return ''


def format_value(_type, _data, lookup_string=lambda ix: "<string>"):
    """
    Format a value based on type and data.
    By default, no strings are looked up and "<string>" is returned.
    You need to define `lookup_string` in order to actually lookup strings from
    the string table.

    :param _type: The numeric type of the value
    :param _data: The numeric data of the value
    :param lookup_string: A function how to resolve strings from integer IDs
    """

    # Function to prepend android prefix for attributes/references from the
    # android library
    fmt_package = lambda x: "android:" if x >> 24 == 1 else ""

    # Function to represent integers
    fmt_int = lambda x: (0x7FFFFFFF & x) - 0x80000000 if x > 0x7FFFFFFF else x

    if _type == TYPE_STRING:
        return lookup_string(_data)

    elif _type == TYPE_ATTRIBUTE:
        return "?{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_REFERENCE:
        return "@{}{:08X}".format(fmt_package(_data), _data)

    elif _type == TYPE_FLOAT:
        return "%f" % unpack("=f", pack("=L", _data))[0]

    elif _type == TYPE_INT_HEX:
        return "0x%08X" % _data

    elif _type == TYPE_INT_BOOLEAN:
        if _data == 0:
            return "false"
        return "true"

    elif _type == TYPE_DIMENSION:
        return "{:f}{}".format(complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

    elif _type == TYPE_FRACTION:
        return "{:f}{}".format(complexToFloat(_data) * 100, FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

    elif TYPE_FIRST_COLOR_INT <= _type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % _data

    elif TYPE_FIRST_INT <= _type <= TYPE_LAST_INT:
        return "%d" % fmt_int(_data)

    return "<0x{:X}, type 0x{:02X}>".format(_data, _type)


class AXMLPrinter:
    """
    Converter for AXML Files into a lxml ElementTree, which can easily be
    converted into XML.

    A Reference Implementation can be found at http://androidxref.com/9.0.0_r3/xref/frameworks/base/tools/aapt/XMLNode.cpp
    """
    __charrange = None
    __replacement = None

    def __init__(self, raw_buff):
        logger.debug("AXMLPrinter")

        self.axml = AXMLParser(raw_buff)

        self.root = None
        self.packerwarning = False
        cur = []

        while self.axml.is_valid():
            _type = next(self.axml)
            logger.debug("DEBUG ARSC TYPE {}".format(_type))

            if _type == START_TAG:
                uri = self._print_namespace(self.axml.namespace)
                uri, name = self._fix_name(uri, self.axml.name)
                tag = "{}{}".format(uri, name)

                comment = self.axml.comment
                if comment:
                    if self.root is None:
                        logger.warning("Can not attach comment with content '{}' without root!".format(comment))
                    else:
                        cur[-1].append(etree.Comment(comment))

                logger.debug("START_TAG: {} (line={})".format(tag, self.axml.m_lineNumber))
                elem = etree.Element(tag, nsmap=self.axml.nsmap)

                for i in range(self.axml.getAttributeCount()):
                    uri = self._print_namespace(self.axml.getAttributeNamespace(i))
                    uri, name = self._fix_name(uri, self.axml.getAttributeName(i))
                    value = self._fix_value(self._get_attribute_value(i))

                    logger.debug("found an attribute: {}{}='{}'".format(uri, name, value.encode("utf-8")))
                    if "{}{}".format(uri, name) in elem.attrib:
                        logger.warning("Duplicate attribute '{}{}'! Will overwrite!".format(uri, name))
                    elem.set("{}{}".format(uri, name), value)

                if self.root is None:
                    self.root = elem
                else:
                    if not cur:
                        # looks like we lost the root?
                        logger.error("No more elements available to attach to! Is the XML malformed?")
                        break
                    cur[-1].append(elem)
                cur.append(elem)

            if _type == END_TAG:
                if not cur:
                    logger.warning("Too many END_TAG! No more elements available to attach to!")

                name = self.axml.name
                uri = self._print_namespace(self.axml.namespace)
                tag = "{}{}".format(uri, name)
                if cur[-1].tag != tag:
                    logger.warning("Closing tag '{}' does not match current stack! At line number: {}. Is the XML malformed?".format(self.axml.name, self.axml.m_lineNumber))
                cur.pop()
            if _type == TEXT:
                logger.debug("TEXT for {}".format(cur[-1]))
                cur[-1].text = self.axml.text
            if _type == END_DOCUMENT:
                # Check if all namespace mappings are closed
                if len(self.axml.namespaces) > 0:
                    logger.warning("Not all namespace mappings were closed! Malformed AXML?")
                break

    def get_buff(self):
        """
        Returns the raw XML file without prettification applied.

        :returns: bytes, encoded as UTF-8
        """
        return self.get_xml(pretty=False)

    def get_xml(self, pretty=True):
        """
        Get the XML as an UTF-8 string

        :returns: bytes encoded as UTF-8
        """
        return etree.tostring(self.root, encoding="utf-8", pretty_print=pretty)

    def get_xml_obj(self):
        """
        Get the XML as an ElementTree object

        :returns: :class:`lxml.etree.Element`
        """
        return self.root

    def is_valid(self):
        """
        Return the state of the AXMLParser.
        If this flag is set to False, the parsing has failed, thus
        the resulting XML will not work or will even be empty.
        """
        return self.axml.is_valid()

    def is_packed(self):
        """
        Returns True if the AXML is likely to be packed

        Packers do some weird stuff and we try to detect it.
        Sometimes the files are not packed but simply broken or compiled with
        some broken version of a tool.
        Some file corruption might also be appear to be a packed file.

        :returns: True if packer detected, False otherwise
        """
        return self.packerwarning

    def _get_attribute_value(self, index):
        """
        Wrapper function for format_value to resolve the actual value of an attribute in a tag
        :param index: index of the current attribute
        :return: formatted value
        """
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        return format_value(_type, _data, lambda _: self.axml.getAttributeValue(index))

    def _fix_name(self, prefix, name):
        """
        Apply some fixes to element named and attribute names.
        Try to get conform to:
        > Like element names, attribute names are case-sensitive and must start with a letter or underscore.
        > The rest of the name can contain letters, digits, hyphens, underscores, and periods.
        See: https://msdn.microsoft.com/en-us/library/ms256152(v=vs.110).aspx

        This function tries to fix some broken namespace mappings.
        In some cases, the namespace prefix is inside the name and not in the prefix field.
        Then, the tag name will usually look like 'android:foobar'.
        If and only if the namespace prefix is inside the namespace mapping and the actual prefix field is empty,
        we will strip the prefix from the attribute name and return the fixed prefix URI instead.
        Otherwise replacement rules will be applied.

        The replacement rules work in that way, that all unwanted characters are replaced by underscores.
        In other words, all characters except the ones listed above are replaced.

        :param name: Name of the attribute or tag
        :param prefix: The existing prefix uri as found in the AXML chunk
        :return: a fixed version of prefix and name
        :rtype: tuple
        """
        if not name[0].isalpha() and name[0] != "_":
            logger.warning("Invalid start for name '{}'. "
                        "XML name must start with a letter.".format(name))
            self.packerwarning = True
            name = "_{}".format(name)
        if name.startswith("android:") and prefix == '' and 'android' in self.axml.nsmap:
            # Seems be a common thing...
            logger.info("Name '{}' starts with 'android:' prefix but 'android' is a known prefix. Replacing prefix.".format(name))
            prefix = self._print_namespace(self.axml.nsmap['android'])
            name = name[len("android:"):]
            # It looks like this is some kind of packer... Not sure though.
            self.packerwarning = True
        elif ":" in name and prefix == '':
            self.packerwarning = True
            embedded_prefix, new_name = name.split(":", 1)
            if embedded_prefix in self.axml.nsmap:
                logger.info("Prefix '{}' is in namespace mapping, assume that it is a prefix.")
                prefix = self._print_namespace(self.axml.nsmap[embedded_prefix])
                name = new_name
            else:
                # Print out an extra warning
                logger.warning("Confused: name contains a unknown namespace prefix: '{}'. "
                            "This is either a broken AXML file or some attempt to break stuff.".format(name))
        if not re.match(r"^[a-zA-Z0-9._-]*$", name):
            logger.warning("Name '{}' contains invalid characters!".format(name))
            self.packerwarning = True
            name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)

        return prefix, name

    def _fix_value(self, value):
        """
        Return a cleaned version of a value
        according to the specification:
        > Char	   ::=   	#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]

        See https://www.w3.org/TR/xml/#charsets

        :param value: a value to clean
        :return: the cleaned value
        """
        if not self.__charrange or not self.__replacement:
            self.__charrange = re.compile('^[\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]*$')
            self.__replacement = re.compile('[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]')

        # Reading string until \x00. This is the same as aapt does.
        if "\x00" in value:
            self.packerwarning = True
            logger.warning("Null byte found in attribute value at position {}: "
                        "Value(hex): '{}'".format(
                value.find("\x00"),
                binascii.hexlify(value.encode("utf-8"))))
            value = value[:value.find("\x00")]

        if not self.__charrange.match(value):
            logger.warning("Invalid character in value found. Replacing with '_'.")
            self.packerwarning = True
            value = self.__replacement.sub('_', value)
        return value

    def _print_namespace(self, uri):
        if uri != "":
            uri = "{{{}}}".format(uri)
        return uri

# See http://aospxref.com/android-13.0.0_r3/xref/frameworks/native/include/android/configuration.h#56

ACONFIGURATION_ORIENTATION_ANY  = 0x0000
ACONFIGURATION_ORIENTATION_PORT = 0x0001
ACONFIGURATION_ORIENTATION_LAND = 0x0002
ACONFIGURATION_ORIENTATION_SQUARE = 0x0003
ACONFIGURATION_TOUCHSCREEN_ANY = 0x0000
ACONFIGURATION_TOUCHSCREEN_NOTOUCH = 0x0001
ACONFIGURATION_TOUCHSCREEN_STYLUS = 0x0002
ACONFIGURATION_TOUCHSCREEN_FINGER = 0x0003
ACONFIGURATION_DENSITY_DEFAULT = 0
ACONFIGURATION_DENSITY_LOW = 120
ACONFIGURATION_DENSITY_MEDIUM = 160
ACONFIGURATION_DENSITY_TV = 213
ACONFIGURATION_DENSITY_HIGH = 240
ACONFIGURATION_DENSITY_XHIGH = 320
ACONFIGURATION_DENSITY_XXHIGH = 480
ACONFIGURATION_DENSITY_XXXHIGH = 640
ACONFIGURATION_DENSITY_ANY = 0xfffe
ACONFIGURATION_DENSITY_NONE = 0xffff
ACONFIGURATION_KEYBOARD_ANY  = 0x0000
ACONFIGURATION_KEYBOARD_NOKEYS = 0x0001
ACONFIGURATION_KEYBOARD_QWERTY = 0x0002
ACONFIGURATION_KEYBOARD_12KEY = 0x0003
ACONFIGURATION_NAVIGATION_ANY  = 0x0000
ACONFIGURATION_NAVIGATION_NONAV = 0x0001
ACONFIGURATION_NAVIGATION_DPAD = 0x0002
ACONFIGURATION_NAVIGATION_TRACKBALL = 0x0003
ACONFIGURATION_NAVIGATION_WHEEL = 0x0004
ACONFIGURATION_KEYSHIDDEN_ANY = 0x0000
ACONFIGURATION_KEYSHIDDEN_NO = 0x0001
ACONFIGURATION_KEYSHIDDEN_YES = 0x0002
ACONFIGURATION_KEYSHIDDEN_SOFT = 0x0003
ACONFIGURATION_NAVHIDDEN_ANY = 0x0000
ACONFIGURATION_NAVHIDDEN_NO = 0x0001
ACONFIGURATION_NAVHIDDEN_YES = 0x0002
ACONFIGURATION_SCREENSIZE_ANY = 0x00
ACONFIGURATION_SCREENSIZE_SMALL = 0x01
ACONFIGURATION_SCREENSIZE_NORMAL = 0x02
ACONFIGURATION_SCREENSIZE_LARGE = 0x03
ACONFIGURATION_SCREENSIZE_XLARGE = 0x04
ACONFIGURATION_SCREENLONG_ANY = 0x00
ACONFIGURATION_SCREENLONG_NO = 0x1
ACONFIGURATION_SCREENLONG_YES = 0x2
ACONFIGURATION_SCREENROUND_ANY = 0x00
ACONFIGURATION_SCREENROUND_NO = 0x1
ACONFIGURATION_SCREENROUND_YES = 0x2
ACONFIGURATION_WIDE_COLOR_GAMUT_ANY = 0x00
ACONFIGURATION_WIDE_COLOR_GAMUT_NO = 0x1
ACONFIGURATION_WIDE_COLOR_GAMUT_YES = 0x2
ACONFIGURATION_HDR_ANY = 0x00
ACONFIGURATION_HDR_NO = 0x1
ACONFIGURATION_HDR_YES = 0x2
ACONFIGURATION_UI_MODE_TYPE_ANY = 0x00
ACONFIGURATION_UI_MODE_TYPE_NORMAL = 0x01
ACONFIGURATION_UI_MODE_TYPE_DESK = 0x02
ACONFIGURATION_UI_MODE_TYPE_CAR = 0x03
ACONFIGURATION_UI_MODE_TYPE_TELEVISION = 0x04
ACONFIGURATION_UI_MODE_TYPE_APPLIANCE = 0x05
ACONFIGURATION_UI_MODE_TYPE_WATCH = 0x06
ACONFIGURATION_UI_MODE_TYPE_VR_HEADSET = 0x07
ACONFIGURATION_UI_MODE_NIGHT_ANY = 0x00
ACONFIGURATION_UI_MODE_NIGHT_NO = 0x1
ACONFIGURATION_UI_MODE_NIGHT_YES = 0x2
ACONFIGURATION_SCREEN_WIDTH_DP_ANY = 0x0000
ACONFIGURATION_SCREEN_HEIGHT_DP_ANY = 0x0000
ACONFIGURATION_SMALLEST_SCREEN_WIDTH_DP_ANY = 0x0000
ACONFIGURATION_LAYOUTDIR_ANY = 0x00
ACONFIGURATION_LAYOUTDIR_LTR = 0x01
ACONFIGURATION_LAYOUTDIR_RTL = 0x02
ACONFIGURATION_MCC = 0x0001
ACONFIGURATION_MNC = 0x0002
ACONFIGURATION_LOCALE = 0x0004
ACONFIGURATION_TOUCHSCREEN = 0x0008
ACONFIGURATION_KEYBOARD = 0x0010
ACONFIGURATION_KEYBOARD_HIDDEN = 0x0020
ACONFIGURATION_NAVIGATION = 0x0040
ACONFIGURATION_ORIENTATION = 0x0080
ACONFIGURATION_DENSITY = 0x0100
ACONFIGURATION_SCREEN_SIZE = 0x0200
ACONFIGURATION_VERSION = 0x0400
ACONFIGURATION_SCREEN_LAYOUT = 0x0800
ACONFIGURATION_UI_MODE = 0x1000
ACONFIGURATION_SMALLEST_SCREEN_SIZE = 0x2000
ACONFIGURATION_LAYOUTDIR = 0x4000
ACONFIGURATION_SCREEN_ROUND = 0x8000
ACONFIGURATION_COLOR_MODE = 0x10000
ACONFIGURATION_MNC_ZERO = 0xffff

# See http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#946

ORIENTATION_ANY = ACONFIGURATION_ORIENTATION_ANY
ORIENTATION_PORT = ACONFIGURATION_ORIENTATION_PORT
ORIENTATION_LAND = ACONFIGURATION_ORIENTATION_LAND
ORIENTATION_SQUARE = ACONFIGURATION_ORIENTATION_SQUARE

TOUCHSCREEN_ANY = ACONFIGURATION_TOUCHSCREEN_ANY
TOUCHSCREEN_NOTOUCH = ACONFIGURATION_TOUCHSCREEN_NOTOUCH
TOUCHSCREEN_STYLUS = ACONFIGURATION_TOUCHSCREEN_STYLUS
TOUCHSCREEN_FINGER = ACONFIGURATION_TOUCHSCREEN_FINGER

DENSITY_DEFAULT = ACONFIGURATION_DENSITY_DEFAULT
DENSITY_LOW = ACONFIGURATION_DENSITY_LOW
DENSITY_MEDIUM = ACONFIGURATION_DENSITY_MEDIUM
DENSITY_TV = ACONFIGURATION_DENSITY_TV
DENSITY_HIGH = ACONFIGURATION_DENSITY_HIGH
DENSITY_XHIGH = ACONFIGURATION_DENSITY_XHIGH
DENSITY_XXHIGH = ACONFIGURATION_DENSITY_XXHIGH
DENSITY_XXXHIGH = ACONFIGURATION_DENSITY_XXXHIGH
DENSITY_ANY = ACONFIGURATION_DENSITY_ANY
DENSITY_NONE = ACONFIGURATION_DENSITY_NONE

KEYBOARD_ANY = ACONFIGURATION_KEYBOARD_ANY
KEYBOARD_NOKEYS = ACONFIGURATION_KEYBOARD_NOKEYS
KEYBOARD_QWERTY = ACONFIGURATION_KEYBOARD_QWERTY
KEYBOARD_12KEY = ACONFIGURATION_KEYBOARD_12KEY

NAVIGATION_ANY = ACONFIGURATION_NAVIGATION_ANY
NAVIGATION_NONAV = ACONFIGURATION_NAVIGATION_NONAV
NAVIGATION_DPAD = ACONFIGURATION_NAVIGATION_DPAD
NAVIGATION_TRACKBALL = ACONFIGURATION_NAVIGATION_TRACKBALL
NAVIGATION_WHEEL = ACONFIGURATION_NAVIGATION_WHEEL

MASK_KEYSHIDDEN = 0x0003
KEYSHIDDEN_ANY = ACONFIGURATION_KEYSHIDDEN_ANY
KEYSHIDDEN_NO = ACONFIGURATION_KEYSHIDDEN_NO
KEYSHIDDEN_YES = ACONFIGURATION_KEYSHIDDEN_YES
KEYSHIDDEN_SOFT = ACONFIGURATION_KEYSHIDDEN_SOFT

MASK_NAVHIDDEN = 0x000c
SHIFT_NAVHIDDEN = 2
NAVHIDDEN_ANY = ACONFIGURATION_NAVHIDDEN_ANY << SHIFT_NAVHIDDEN
NAVHIDDEN_NO = ACONFIGURATION_NAVHIDDEN_NO << SHIFT_NAVHIDDEN
NAVHIDDEN_YES = ACONFIGURATION_NAVHIDDEN_YES << SHIFT_NAVHIDDEN

SCREENWIDTH_ANY = 0
SCREENHEIGHT_ANY = 0
SDKVERSION_ANY = 0
MINORVERSION_ANY = 0

MASK_SCREENSIZE = 0x0f
SCREENSIZE_ANY = ACONFIGURATION_SCREENSIZE_ANY
SCREENSIZE_SMALL = ACONFIGURATION_SCREENSIZE_SMALL
SCREENSIZE_NORMAL = ACONFIGURATION_SCREENSIZE_NORMAL
SCREENSIZE_LARGE = ACONFIGURATION_SCREENSIZE_LARGE
SCREENSIZE_XLARGE = ACONFIGURATION_SCREENSIZE_XLARGE

MASK_SCREENLONG = 0x30
SHIFT_SCREENLONG = 4
SCREENLONG_ANY = ACONFIGURATION_SCREENLONG_ANY << SHIFT_SCREENLONG
SCREENLONG_NO = ACONFIGURATION_SCREENLONG_NO << SHIFT_SCREENLONG
SCREENLONG_YES = ACONFIGURATION_SCREENLONG_YES << SHIFT_SCREENLONG

MASK_LAYOUTDIR = 0xC0
SHIFT_LAYOUTDIR = 6
LAYOUTDIR_ANY = ACONFIGURATION_LAYOUTDIR_ANY << SHIFT_LAYOUTDIR
LAYOUTDIR_LTR = ACONFIGURATION_LAYOUTDIR_LTR << SHIFT_LAYOUTDIR
LAYOUTDIR_RTL = ACONFIGURATION_LAYOUTDIR_RTL << SHIFT_LAYOUTDIR

MASK_UI_MODE_TYPE = 0x0f
UI_MODE_TYPE_ANY = ACONFIGURATION_UI_MODE_TYPE_ANY
UI_MODE_TYPE_NORMAL = ACONFIGURATION_UI_MODE_TYPE_NORMAL
UI_MODE_TYPE_DESK = ACONFIGURATION_UI_MODE_TYPE_DESK
UI_MODE_TYPE_CAR = ACONFIGURATION_UI_MODE_TYPE_CAR
UI_MODE_TYPE_TELEVISION = ACONFIGURATION_UI_MODE_TYPE_TELEVISION
UI_MODE_TYPE_APPLIANCE = ACONFIGURATION_UI_MODE_TYPE_APPLIANCE
UI_MODE_TYPE_WATCH = ACONFIGURATION_UI_MODE_TYPE_WATCH
UI_MODE_TYPE_VR_HEADSET = ACONFIGURATION_UI_MODE_TYPE_VR_HEADSET

MASK_UI_MODE_NIGHT = 0x30
SHIFT_UI_MODE_NIGHT = 4
UI_MODE_NIGHT_ANY = ACONFIGURATION_UI_MODE_NIGHT_ANY << SHIFT_UI_MODE_NIGHT
UI_MODE_NIGHT_NO = ACONFIGURATION_UI_MODE_NIGHT_NO << SHIFT_UI_MODE_NIGHT
UI_MODE_NIGHT_YES = ACONFIGURATION_UI_MODE_NIGHT_YES << SHIFT_UI_MODE_NIGHT

MASK_SCREENROUND = 0x03
SCREENROUND_ANY = ACONFIGURATION_SCREENROUND_ANY
SCREENROUND_NO = ACONFIGURATION_SCREENROUND_NO
SCREENROUND_YES = ACONFIGURATION_SCREENROUND_YES

MASK_WIDE_COLOR_GAMUT = 0x03
WIDE_COLOR_GAMUT_ANY = ACONFIGURATION_WIDE_COLOR_GAMUT_ANY
WIDE_COLOR_GAMUT_NO = ACONFIGURATION_WIDE_COLOR_GAMUT_NO
WIDE_COLOR_GAMUT_YES = ACONFIGURATION_WIDE_COLOR_GAMUT_YES

MASK_HDR = 0x0c
SHIFT_HDR = 2
HDR_ANY = ACONFIGURATION_HDR_ANY << SHIFT_HDR
HDR_NO = ACONFIGURATION_HDR_NO << SHIFT_HDR
HDR_YES = ACONFIGURATION_HDR_YES << SHIFT_HDR


class ARSCParser:
    """
    Parser for resource.arsc files

    The ARSC File is, like the binary XML format, a chunk based format.
    Both formats are actually identical but use different chunks in order to store the data.

    The most outer chunk in the ARSC file is a chunk of type RES_TABLE_TYPE.
    Inside this chunk is a StringPool and at least one package.

    Each package is a chunk of type RES_TABLE_PACKAGE_TYPE.
    It contains again many more chunks.
    """
    def __init__(self, raw_buff):
        """
        :param bytes raw_buff: the raw bytes of the file
        """
        self.buff = io.BufferedReader(io.BytesIO(raw_buff))
        self.buff_size = self.buff.raw.getbuffer().nbytes

        if self.buff_size < 8 or self.buff_size > 0xFFFFFFFF:
            raise ResParserError("Invalid file size {} for a resources.arsc file!".format(self.buff.size()))

        self.analyzed = False
        self._resolved_strings = None
        self.packages = defaultdict(list)
        self.values = {}
        self.resource_values = defaultdict(defaultdict)
        self.resource_configs = defaultdict(lambda: defaultdict(set))
        self.resource_keys = defaultdict(lambda: defaultdict(defaultdict))
        self.stringpool_main = None

        # First, there is a ResTable_header.
        self.header = ARSCHeader(self.buff, expected_type=RES_TABLE_TYPE)

        # More sanity checks...
        if self.header.header_size != 12:
            logger.warning("The ResTable_header has an unexpected header size! Expected 12 bytes, got {}.".format(self.header.header_size))

        if self.header.size > self.buff_size:
            raise ResParserError("The file seems to be truncated. Refuse to parse the file! Filesize: {}, declared size: {}".format(self.buff_size, self.header.size))

        if self.header.size < self.buff_size:
            logger.warning("The Resource file seems to have data appended to it. Filesize: {}, declared size: {}".format(self.buff_size, self.header.size))

        # The ResTable_header contains the packageCount, i.e. the number of ResTable_package
        self.packageCount = unpack('<I', self.buff.read(4))[0]

        # Even more sanity checks...
        if self.packageCount < 1:
            logger.warning("The number of packages is smaller than one. There should be at least one package!")

        logger.debug("Parsed ResTable_header with {} package(s) inside.".format(self.packageCount))

        # skip to the start of the first chunk's data, skipping trailing header bytes (there should be none)
        self.buff.seek(self.header.start + self.header.header_size)

        # Now parse the data:
        # We should find one ResStringPool_header and one or more ResTable_package chunks inside
        while self.buff.tell() <= self.header.end - ARSCHeader.SIZE:
            res_header = ARSCHeader(self.buff)

            if res_header.end > self.header.end:
                # this inner chunk crosses the boundary of the table chunk
                logger.warning("Invalid chunk found! It is larger than the outer chunk: %s", res_header)
                break

            if res_header.type == RES_STRING_POOL_TYPE:
                # There should be only one StringPool per resource table.
                if self.stringpool_main:
                    logger.warning("Already found a ResStringPool_header, but there should be only one! Will not parse the Pool again.")
                else:
                    self.stringpool_main = StringBlock(self.buff, res_header)
                    logger.debug("Found the main string pool: %s", self.stringpool_main)

            elif res_header.type == RES_TABLE_PACKAGE_TYPE:
                if len(self.packages) > self.packageCount:
                    raise ResParserError("Got more packages ({}) than expected ({})".format(len(self.packages), self.packageCount))

                current_package = ARSCResTablePackage(self.buff, res_header)
                package_name = current_package.get_name()

                # After the Header, we have the resource type symbol table
                self.buff.seek(current_package.header.start + current_package.typeStrings)
                type_sp_header = ARSCHeader(self.buff, expected_type=RES_STRING_POOL_TYPE)
                mTableStrings = StringBlock(self.buff, type_sp_header)

                # Next, we should have the resource key symbol table
                self.buff.seek(current_package.header.start + current_package.keyStrings)
                key_sp_header = ARSCHeader(self.buff, expected_type=RES_STRING_POOL_TYPE)
                mKeyStrings = StringBlock(self.buff, key_sp_header)

                # Add them to the dict of read packages
                self.packages[package_name].append(current_package)
                self.packages[package_name].append(mTableStrings)
                self.packages[package_name].append(mKeyStrings)

                pc = PackageContext(current_package, self.stringpool_main, mTableStrings, mKeyStrings)
                logger.debug("Constructed a PackageContext: %s", pc)

                # skip to the first header in this table package chunk
                # FIXME is this correct? We have already read the first two sections!
                # self.buff.set_idx(res_header.start + res_header.header_size)
                # this looks more like we want: (???)
                # FIXME it looks like that the two string pools we have read might not be concatenated to each other,
                # thus jumping to the sum of the sizes might not be correct...
                next_idx = res_header.start + res_header.header_size + type_sp_header.size + key_sp_header.size

                if next_idx != self.buff.tell():
                    # If this happens, we have a testfile ;)
                    logger.error("This looks like an odd resources.arsc file!")
                    logger.error("Please report this error including the file you have parsed!")
                    logger.error("next_idx = {}, current buffer position = {}".format(next_idx, self.buff.tell()))
                    logger.error("Please open a issue at https://github.com/androguard/androguard/issues")
                    logger.error("Thank you!")

                self.buff.seek(next_idx)

                # Read all other headers
                while self.buff.tell() <= res_header.end - ARSCHeader.SIZE:
                    pkg_chunk_header = ARSCHeader(self.buff)
                    logger.debug("Found a header: {}".format(pkg_chunk_header))
                    if pkg_chunk_header.start + pkg_chunk_header.size > res_header.end:
                        # we are way off the package chunk; bail out
                        break

                    self.packages[package_name].append(pkg_chunk_header)

                    if pkg_chunk_header.type == RES_TABLE_TYPE_SPEC_TYPE:
                        self.packages[package_name].append(ARSCResTypeSpec(self.buff, pc))

                    elif pkg_chunk_header.type == RES_TABLE_TYPE_TYPE:
                        # Parse a RES_TABLE_TYPE
                        # http://androidxref.com/9.0.0_r3/xref/frameworks/base/tools/aapt2/format/binary/BinaryResourceParser.cpp#311
                        a_res_type = ARSCResType(self.buff, pc)
                        self.packages[package_name].append(a_res_type)
                        self.resource_configs[package_name][a_res_type].add(a_res_type.config)

                        logger.debug("Config: {}".format(a_res_type.config))

                        entries = []
                        for i in range(0, a_res_type.entryCount):
                            current_package.mResId = current_package.mResId & 0xffff0000 | i
                            entries.append((unpack('<i', self.buff.read(4))[0], current_package.mResId))

                        self.packages[package_name].append(entries)

                        for entry, res_id in entries:
                            if entry != -1:
                                ate = ARSCResTableEntry(self.buff, res_id, pc)
                                self.packages[package_name].append(ate)
                                if ate.is_weak():
                                    # FIXME we are not sure how to implement the FLAG_WEAK!
                                    # We saw the following: There is just a single Res_value after the ARSCResTableEntry
                                    # and then comes the next ARSCHeader.
                                    # Therefore we think this means all entries are somehow replicated?
                                    # So we do some kind of hack here. We set the idx to the entry again...
                                    # Now we will read all entries!
                                    # Not sure if this is a good solution though
                                    self.buff.seek(ate.start)
                    elif pkg_chunk_header.type == RES_TABLE_LIBRARY_TYPE:
                        logger.warning("RES_TABLE_LIBRARY_TYPE chunk is not supported")
                    else:
                        # Unknown / not-handled chunk type
                        logger.warning("Unknown chunk type encountered inside RES_TABLE_PACKAGE: %s", pkg_chunk_header)

                    # skip to the next chunk
                    self.buff.seek(pkg_chunk_header.end)
            else:
                # Unknown / not-handled chunk type
                logger.warning("Unknown chunk type encountered: %s", res_header)

            # move to the next resource chunk
            self.buff.seek(res_header.end)

    def _analyse(self):
        if self.analyzed:
            return

        self.analyzed = True

        for package_name in self.packages:
            self.values[package_name] = {}

            nb = 3
            while nb < len(self.packages[package_name]):
                header = self.packages[package_name][nb]
                if isinstance(header, ARSCHeader):
                    if header.type == RES_TABLE_TYPE_TYPE:
                        a_res_type = self.packages[package_name][nb + 1]

                        locale = a_res_type.config.get_language_and_region()

                        c_value = self.values[package_name].setdefault(locale, {"public": []})

                        entries = self.packages[package_name][nb + 2]
                        nb_i = 0
                        for entry, res_id in entries:
                            if entry != -1:
                                ate = self.packages[package_name][nb + 3 + nb_i]

                                self.resource_values[ate.mResId][a_res_type.config] = ate
                                self.resource_keys[package_name][a_res_type.get_type()][ate.get_value()] = ate.mResId

                                if ate.get_index() != -1:
                                    c_value["public"].append(
                                        (a_res_type.get_type(), ate.get_value(),
                                         ate.mResId))

                                if a_res_type.get_type() not in c_value:
                                    c_value[a_res_type.get_type()] = []

                                if a_res_type.get_type() == "string":
                                    c_value["string"].append(
                                        self.get_resource_string(ate))

                                elif a_res_type.get_type() == "id":
                                    if not ate.is_complex():
                                        c_value["id"].append(
                                            self.get_resource_id(ate))

                                elif a_res_type.get_type() == "bool":
                                    if not ate.is_complex():
                                        c_value["bool"].append(
                                            self.get_resource_bool(ate))

                                elif a_res_type.get_type() == "integer":
                                    c_value["integer"].append(
                                        self.get_resource_integer(ate))

                                elif a_res_type.get_type() == "color":
                                    c_value["color"].append(
                                        self.get_resource_color(ate))

                                elif a_res_type.get_type() == "dimen":
                                    c_value["dimen"].append(
                                        self.get_resource_dimen(ate))

                                nb_i += 1
                        nb += 3 + nb_i - 1  # -1 to account for the nb+=1 on the next line
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
        return [
            ate.get_value(),
            "#{:02x}{:02x}{:02x}{:02x}".format(
                ((entry_data >> 24) & 0xFF),
                ((entry_data >> 16) & 0xFF),
                ((entry_data >> 8) & 0xFF),
                (entry_data & 0xFF))
        ]

    def get_resource_dimen(self, ate):
        try:
            return [
                ate.get_value(), "{}{}".format(
                    complexToFloat(ate.key.get_data()),
                    DIMENSION_UNITS[ate.key.get_data() & COMPLEX_UNIT_MASK])
            ]
        except IndexError:
            logger.debug("Out of range dimension unit index for {}: {}".format(
                complexToFloat(ate.key.get_data()),
                ate.key.get_data() & COMPLEX_UNIT_MASK))
            return [ate.get_value(), ate.key.get_data()]

    # FIXME
    def get_resource_style(self, ate):
        return ["", ""]

    def get_packages_names(self):
        """
        Retrieve a list of all package names, which are available
        in the given resources.arsc.
        """
        return list(self.packages.keys())

    def get_locales(self, package_name):
        """
        Retrieve a list of all available locales in a given packagename.

        :param package_name: the package name to get locales of
        """
        self._analyse()
        return list(self.values[package_name].keys())

    def get_types(self, package_name, locale='\x00\x00'):
        """
        Retrieve a list of all types which are available in the given
        package and locale.

        :param package_name: the package name to get types of
        :param locale: the locale to get types of (default: '\x00\x00')
        """
        self._analyse()
        return list(self.values[package_name][locale].keys())

    def get_public_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'public'.

        The public resources table contains the IDs for each item.

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """

        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["public"]:
                buff += '<public type="{}" name="{}" id="0x{:08x}" />\n'.format(
                    i[0], i[1], i[2])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_string_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'string'.

        Read more about string resources:
        https://developer.android.com/guide/topics/resources/string-resource.html

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["string"]:
                if any(map(i[1].__contains__, '<&>')):
                    value = '<![CDATA[%s]]>' % i[1]
                else:
                    value = i[1]
                buff += '<string name="{}">{}</string>\n'.format(i[0], value)
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_strings_resources(self):
        """
        Get the XML (as string) of all resources of type 'string'.
        This is a combined variant, which has all locales and all package names
        stored.
        """
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
                        buff += '<string name="{}">{}</string>\n'.format(i[0], escape(i[1]))
                except KeyError:
                    pass

                buff += '</resources>\n'
                buff += '</locale>\n'

            buff += "</package>\n"

        buff += "</packages>\n"

        return buff.encode('utf-8')

    def get_id_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'id'.

        Read more about ID resources:
        https://developer.android.com/guide/topics/resources/more-resources.html#Id

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["id"]:
                if len(i) == 1:
                    buff += '<item type="id" name="%s"/>\n' % (i[0])
                else:
                    buff += '<item type="id" name="{}">{}</item>\n'.format(i[0],
                                                                       escape(i[1]))
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_bool_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'bool'.

        Read more about bool resources:
        https://developer.android.com/guide/topics/resources/more-resources.html#Bool

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["bool"]:
                buff += '<bool name="{}">{}</bool>\n'.format(i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_integer_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'integer'.

        Read more about integer resources:
        https://developer.android.com/guide/topics/resources/more-resources.html#Integer

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["integer"]:
                buff += '<integer name="{}">{}</integer>\n'.format(i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_color_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'color'.

        Read more about color resources:
        https://developer.android.com/guide/topics/resources/more-resources.html#Color

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["color"]:
                buff += '<color name="{}">{}</color>\n'.format(i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_dimen_resources(self, package_name, locale='\x00\x00'):
        """
        Get the XML (as string) of all resources of type 'dimen'.

        Read more about Dimension resources:
        https://developer.android.com/guide/topics/resources/more-resources.html#Dimension

        :param package_name: the package name to get the resources for
        :param locale: the locale to get the resources for (default: '\x00\x00')
        """
        self._analyse()

        buff = '<?xml version="1.0" encoding="utf-8"?>\n'
        buff += '<resources>\n'

        try:
            for i in self.values[package_name][locale]["dimen"]:
                buff += '<dimen name="{}">{}</dimen>\n'.format(i[0], i[1])
        except KeyError:
            pass

        buff += '</resources>\n'

        return buff.encode('utf-8')

    def get_id(self, package_name, rid, locale='\x00\x00'):
        """
        Returns the tuple (resource_type, resource_name, resource_id)
        for the given resource_id.

        :param package_name: package name to query
        :param rid: the resource_id
        :param locale: specific locale
        :return: tuple of (resource_type, resource_name, resource_id)
        """
        self._analyse()

        try:
            for i in self.values[package_name][locale]["public"]:
                if i[2] == rid:
                    return i
        except KeyError:
            pass
        return None, None, None

    class ResourceResolver:
        """
        Resolves resources by ID and configuration.
        This resolver deals with complex resources as well as with references.
        """
        def __init__(self, android_resources, config=None):
            """
            :param ARSCParser android_resources: A resource parser
            :param ARSCResTableConfig config: The desired configuration or None to resolve all.
            """
            self.resources = android_resources
            self.wanted_config = config

        def resolve(self, res_id):
            """
            the given ID into the Resource and returns a list of matching resources.

            :param int res_id: numerical ID of the resource
            :return: a list of tuples of (ARSCResTableConfig, str)
            """
            result = []
            self._resolve_into_result(result, res_id, self.wanted_config)
            return result

        def _resolve_into_result(self, result, res_id, config):
            # First: Get all candidates
            configs = self.resources.get_res_configs(res_id, config)

            for config, ate in configs:
                # deconstruct them and check if more candidates are generated
                self.put_ate_value(result, ate, config)

        def put_ate_value(self, result, ate, config):
            """
            Put a ResTableEntry into the list of results
            :param list result: results array
            :param ARSCResTableEntry ate:
            :param ARSCResTableConfig config:
            :return:
            """
            if ate.is_complex():
                complex_array = []
                result.append((config, complex_array))
                for _, item in ate.item.items:
                    self.put_item_value(complex_array, item, config, ate, complex_=True)
            else:
                self.put_item_value(result, ate.key, config, ate, complex_=False)

        def put_item_value(self, result, item, config, parent, complex_):
            """
            Put the tuple (ARSCResTableConfig, resolved string) into the result set

            :param list result: the result set
            :param ARSCResStringPoolRef item:
            :param ARSCResTableConfig config:
            :param ARSCResTableEntry parent: the originating entry
            :param bool complex_: True if the originating :class:`ARSCResTableEntry` was complex
            :return:
            """
            if item.is_reference():
                res_id = item.get_data()
                if res_id:
                    # Infinite loop detection:
                    # TODO should this stay here or should be detect the loop much earlier?
                    if res_id == parent.mResId:
                        logger.warning("Infinite loop detected at resource item {}. It references itself!".format(parent))
                        return

                    self._resolve_into_result(result, item.get_data(), self.wanted_config)
            else:
                if complex_:
                    result.append(item.format_value())
                else:
                    result.append((config, item.format_value()))

    def get_resolved_res_configs(self, rid, config=None):
        """
        Return a list of resolved resource IDs with their corresponding configuration.
        It has a similar return type as :meth:`get_res_configs` but also handles complex entries
        and references.
        Also instead of returning :class:`ARSCResTableEntry` in the tuple, the actual values are resolved.

        This is the preferred way of resolving resource IDs to their resources.

        :param int rid: the numerical ID of the resource
        :param ARSCTableResConfig config: the desired configuration or None to retrieve all
        :return: A list of tuples of (ARSCResTableConfig, str)
        """
        resolver = ARSCParser.ResourceResolver(self, config)
        return resolver.resolve(rid)

    def get_resolved_strings(self):
        self._analyse()
        if self._resolved_strings:
            return self._resolved_strings

        r = {}
        for package_name in self.get_packages_names():
            r[package_name] = {}
            k = {}

            for locale in self.values[package_name]:
                v_locale = locale
                if v_locale == '\x00\x00':
                    v_locale = 'DEFAULT'

                r[package_name][v_locale] = {}

                try:
                    for i in self.values[package_name][locale]["public"]:
                        if i[0] == 'string':
                            r[package_name][v_locale][i[2]] = None
                            k[i[1]] = i[2]
                except KeyError:
                    pass

                try:
                    for i in self.values[package_name][locale]["string"]:
                        if i[0] in k:
                            r[package_name][v_locale][k[i[0]]] = i[1]
                except KeyError:
                    pass

        self._resolved_strings = r
        return r

    def get_res_configs(self, rid, config=None, fallback=True):
        """
        Return the resources found with the ID `rid` and select
        the right one based on the configuration, or return all if no configuration was set.

        But we try to be generous here and at least try to resolve something:
        This method uses a fallback to return at least one resource (the first one in the list)
        if more than one items are found and the default config is used and no default entry could be found.

        This is usually a bad sign (i.e. the developer did not follow the android documentation:
        https://developer.android.com/guide/topics/resources/localization.html#failing2)
        In practise an app might just be designed to run on a single locale and thus only has those locales set.

        You can disable this fallback behaviour, to just return exactly the given result.

        :param rid: resource id as int
        :param config: a config to resolve from, or None to get all results
        :param fallback: Enable the fallback for resolving default configuration (default: True)
        :return: a list of ARSCResTableConfig: ARSCResTableEntry
        """
        self._analyse()

        if not rid:
            raise ValueError("'rid' should be set")
        if not isinstance(rid, int):
            raise ValueError("'rid' must be an int")

        if rid not in self.resource_values:
            logger.warning("The requested rid '0x{:08x}' could not be found in the list of resources.".format(rid))
            return []

        res_options = self.resource_values[rid]
        if len(res_options) > 1 and config:
            if config in res_options:
                return [(config, res_options[config])]
            elif fallback and config == ARSCResTableConfig.default_config():
                logger.warning("No default resource config could be found for the given rid '0x{:08x}', using fallback!".format(rid))
                return [list(self.resource_values[rid].items())[0]]
            else:
                return []
        else:
            return list(res_options.items())

    def get_string(self, package_name, name, locale='\x00\x00'):
        self._analyse()

        try:
            for i in self.values[package_name][locale]["string"]:
                if i[0] == name:
                    return i
        except KeyError:
            return None

    def get_res_id_by_key(self, package_name, resource_type, key):
        try:
            return self.resource_keys[package_name][resource_type][key]
        except KeyError:
            return None

    def get_items(self, package_name):
        self._analyse()
        return self.packages[package_name]

    def get_type_configs(self, package_name, type_name=None):
        if package_name is None:
            package_name = self.get_packages_names()[0]
        result = collections.defaultdict(list)

        for res_type, configs in list(self.resource_configs[package_name].items()):
            if res_type.get_package_name() == package_name and (
                            type_name is None or res_type.get_type() == type_name):
                result[res_type.get_type()].extend(configs)

        return result

    @staticmethod
    def parse_id(name):
        """
        Resolves an id from a binary XML file in the form "@[package:]DEADBEEF"
        and returns a tuple of package name and resource id.
        If no package name was given, i.e. the ID has the form "@DEADBEEF",
        the package name is set to None.

        Raises a ValueError if the id is malformed.

        :param name: the string of the resource, as in the binary XML file
        :return: a tuple of (resource_id, package_name).
        """

        if not name.startswith('@'):
            raise ValueError("Not a valid resource ID, must start with @: '{}'".format(name))

        # remove @
        name = name[1:]

        package = None
        if ':' in name:
            package, res_id = name.split(':', 1)
        else:
            res_id = name

        if len(res_id) != 8:
            raise ValueError("Numerical ID is not 8 characters long: '{}'".format(res_id))

        try:
            return int(res_id, 16), package
        except ValueError:
            raise ValueError("ID is not a hex ID: '{}'".format(res_id))

    def get_resource_xml_name(self, r_id, package=None):
        """
        Returns the XML name for a resource, including the package name if package is None.
        A full name might look like `@com.example:string/foobar`
        Otherwise the name is only looked up in the specified package and is returned without
        the package name.
        The same example from about without the package name will read as `@string/foobar`.

        If the ID could not be found, `None` is returned.

        A description of the XML name can be found here:
        https://developer.android.com/guide/topics/resources/providing-resources#ResourcesFromXml

        :param r_id: numerical ID if the resource
        :param package: package name
        :return: XML name identifier
        """
        if package:
            resource, name, i_id = self.get_id(package, r_id)
            if not i_id:
                return None
            return "@{}/{}".format(resource, name)
        else:
            for p in self.get_packages_names():
                r, n, i_id = self.get_id(p, r_id)
                if i_id:
                    # found the resource in this package
                    package = p
                    resource = r
                    name = n
                    break
            if not package:
                return None
            else:
                return "@{}:{}/{}".format(package, resource, name)


class PackageContext:
    def __init__(self, current_package, stringpool_main, mTableStrings, mKeyStrings):
        """
        :param ARSCResTablePackage current_package:
        :param StringBlock stringpool_main:
        :param StringBlock mTableStrings:
        :param StringBlock mKeyStrings:
        """
        self.stringpool_main = stringpool_main
        self.mTableStrings = mTableStrings
        self.mKeyStrings = mKeyStrings
        self.current_package = current_package

    def get_mResId(self):
        return self.current_package.mResId

    def set_mResId(self, mResId):
        self.current_package.mResId = mResId

    def get_package_name(self):
        return self.current_package.get_name()

    def __repr__(self):
        return "<PackageContext {}, {}, {}, {}>".format(self.current_package,
                                                        self.stringpool_main,
                                                        self.mTableStrings,
                                                        self.mKeyStrings)


class ARSCHeader:
    """
    Object which contains a Resource Chunk.
    This is an implementation of the `ResChunk_header`.

    It will throw an :class:`ResParserError` if the header could not be read successfully.

    It is not checked if the data is outside the buffer size nor if the current
    chunk fits into the parent chunk (if any)!

    The parameter `expected_type` can be used to immediately check the header for the type or raise a :class:`ResParserError`.
    This is useful if you know what type of chunk must follow.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#196
    :raises: ResParserError
    """

    # This is the minimal size such a header must have. There might be other header data too!
    SIZE = 2 + 2 + 4

    def __init__(self, buff, expected_type=None, possible_types=None):
        """
        :param androguard.core.bytecode.BuffHandle buff: the buffer set to the position where the header starts.
        :param int expected_type: the type of the header which is expected.
        """
        self.start = buff.tell()
        # Make sure we do not read over the buffer:
        if buff.raw.getbuffer().nbytes < self.start + self.SIZE:
            raise ResParserError("Can not read over the buffer size! Offset={}".format(self.start))

        # Checking for dummy data between elements
        if possible_types:
            while True:
                cur_pos = buff.tell()
                self._type, self._header_size, self._size = unpack('<HHL', buff.read(self.SIZE))

                # cases where packers set the EndNamespace with zero size: check we are the end and add the prefix + uri
                if self._size < self.SIZE and (buff.raw.getbuffer().nbytes == cur_pos + self._header_size + 4 + 4):
                    self._size = 24

                if cur_pos == 0 or (
                        self._type in possible_types and self._header_size >= self.SIZE and self._size > self.SIZE):
                    break
                buff.seek(cur_pos)
                buff.read(1)
                logger.warning("Appears that dummy data are found between elements!")
        else:
            self._type, self._header_size, self._size = unpack('<HHL', buff.read(self.SIZE))

        if expected_type and self._type != expected_type:
            raise ResParserError("Header type is not equal the expected type: Got 0x{:04x}, wanted 0x{:04x}".format(self._type, expected_type))

        # Assert that the read data will fit into the chunk.
        # The total size must be equal or larger than the header size
        if self._header_size < self.SIZE:
            raise ResParserError(
                "declared header size is smaller than required size of {}! Offset={}".format(self.SIZE, self.start))
        if self._size < self.SIZE:
            raise ResParserError(
                "declared chunk size is smaller than required size of {}! Offset={}".format(self.SIZE, self.start))
        if self._size < self._header_size:
            raise ResParserError(
                "declared chunk size ({}) is smaller than header size ({})! Offset={}".format(self._size,
                                                                                              self._header_size,
                                                                                              self.start))

    @property
    def type(self):
        """
        Type identifier for this chunk
        """
        return self._type

    @property
    def header_size(self):
        """
        Size of the chunk header (in bytes).  Adding this value to
        the address of the chunk allows you to find its associated data
        (if any).
        """
        return self._header_size

    @property
    def size(self):
        """
        Total size of this chunk (in bytes).  This is the chunkSize plus
        the size of any data associated with the chunk.  Adding this value
        to the chunk allows you to completely skip its contents (including
        any child chunks).  If this value is the same as chunkSize, there is
        no data associated with the chunk.
        """
        return self._size

    @property
    def end(self):
        """
        Get the absolute offset inside the file, where the chunk ends.
        This is equal to `ARSCHeader.start + ARSCHeader.size`.
        """
        return self.start + self.size

    def __repr__(self):
        return "<ARSCHeader idx='0x{:08x}' type='{}' header_size='{}' size='{}'>".format(self.start,
                                                                                         self.type,
                                                                                         self.header_size,
                                                                                         self.size)


class ARSCResTablePackage:
    """
    A `ResTable_package`

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#861
    """
    def __init__(self, buff, header):
        self.header = header
        self.start = buff.tell()
        self.id = unpack('<I', buff.read(4))[0]
        self.name = buff.read(256)
        self.typeStrings = unpack('<I', buff.read(4))[0]
        self.lastPublicType = unpack('<I', buff.read(4))[0]
        self.keyStrings = unpack('<I', buff.read(4))[0]
        self.lastPublicKey = unpack('<I', buff.read(4))[0]
        self.mResId = self.id << 24

    def get_name(self):
        name = self.name.decode("utf-16", 'replace')
        name = name[:name.find("\x00")]
        return name


class ARSCResTypeSpec:
    """
    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1327
    """
    def __init__(self, buff, parent=None):
        self.start = buff.tell()
        self.parent = parent
        self.id = unpack('<B', buff.read(1))[0]
        self.res0 = unpack('<B', buff.read(1))[0]
        self.res1 = unpack('<H', buff.read(2))[0]
        # TODO: https://github.com/androguard/androguard/issues/1014 | Properly account for the cases where res0/1 are not zero
        try:
            if self.res0 != 0:
                logger.warning("res0 must be zero!")
            if self.res1 != 0:
                logger.warning("res1 must be zero!")
            self.entryCount = unpack('<I', buff.read(4))[0]

            self.typespec_entries = []
            for i in range(0, self.entryCount):
                self.typespec_entries.append(unpack('<I', buff.read(4))[0])
        except Exception as e:
            logger.error(e)

class ARSCResType:
    """
    This is a `ResTable_type` without it's `ResChunk_header`.
    It contains a `ResTable_config`

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1364
    """
    def __init__(self, buff, parent=None):
        self.start = buff.tell()
        self.parent = parent

        self.id = unpack('<B', buff.read(1))[0]
        # TODO there is now FLAG_SPARSE: http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1401
        self.flags, = unpack('<B', buff.read(1))
        self.reserved = unpack('<H', buff.read(2))[0]
        if self.reserved != 0:
            raise ResParserError("reserved must be zero!")
        self.entryCount = unpack('<I', buff.read(4))[0]
        self.entriesStart = unpack('<I', buff.read(4))[0]

        self.mResId = (0xff000000 & self.parent.get_mResId()) | self.id << 16
        self.parent.set_mResId(self.mResId)

        self.config = ARSCResTableConfig(buff)

        logger.debug("Parsed {}".format(self))

    def get_type(self):
        return self.parent.mTableStrings.getString(self.id - 1)

    def get_package_name(self):
        return self.parent.get_package_name()

    def __repr__(self):
        return "<ARSCResType(start=0x%x, id=0x%x, flags=0x%x, entryCount=%d, entriesStart=0x%x, mResId=0x%x, %s)>" % (
            self.start,
            self.id,
            self.flags,
            self.entryCount,
            self.entriesStart,
            self.mResId,
            "table:" + self.parent.mTableStrings.getString(self.id - 1)
        )


class ARSCResTableConfig:
    """
    ARSCResTableConfig contains the configuration for specific resource selection.
    This is used on the device to determine which resources should be loaded
    based on different properties of the device like locale or displaysize.

    See the definition of `ResTable_config` in
    http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#911
    """
    @classmethod
    def default_config(cls):
        if not hasattr(cls, 'DEFAULT'):
            cls.DEFAULT = ARSCResTableConfig(None)
        return cls.DEFAULT

    def __init__(self, buff=None, **kwargs):
        if buff is not None:
            self.start = buff.tell()

            # uint32_t
            self.size = unpack('<I', buff.read(4))[0]

            # union: uint16_t mcc, uint16_t mnc
            # 0 means any
            self.imsi = unpack('<I', buff.read(4))[0]

            # uint32_t as chars \0\0 means any
            # either two 7bit ASCII representing the ISO-639-1 language code
            # or a single 16bit LE value representing ISO-639-2 3 letter code
            self.locale = unpack('<I', buff.read(4))[0]

            # struct of:
            # uint8_t orientation
            # uint8_t touchscreen
            # uint16_t density
            self.screenType = unpack('<I', buff.read(4))[0]

            # struct of
            # uint8_t keyboard
            # uint8_t navigation
            # uint8_t inputFlags
            # uint8_t inputPad0
            self.input = unpack('<I', buff.read(4))[0]

            # struct of
            # uint16_t screenWidth
            # uint16_t screenHeight
            self.screenSize = unpack('<I', buff.read(4))[0]

            # struct of
            # uint16_t sdkVersion
            # uint16_t minorVersion  which should be always 0, as the meaning is not defined
            self.version = unpack('<I', buff.read(4))[0]

            # The next three fields seems to be optional
            if self.size >= 32:
                # struct of
                # uint8_t screenLayout
                # uint8_t uiMode
                # uint16_t smallestScreenWidthDp
                self.screenConfig, = unpack('<I', buff.read(4))
            else:
                logger.debug("This file does not have a screenConfig! size={}".format(self.size))
                self.screenConfig = 0

            if self.size >= 36:
                # struct of
                # uint16_t screenWidthDp
                # uint16_t screenHeightDp
                self.screenSizeDp, = unpack('<I', buff.read(4))
            else:
                logger.debug("This file does not have a screenSizeDp! size={}".format(self.size))
                self.screenSizeDp = 0

            if self.size >= 40:
                self.localeScript = buff.read(4)

            if self.size >= 44:
                self.localeVariant = buff.read(8)

            if self.size >= 52:
                # struct of
                # uint8_t screenLayout2
                # uint8_t colorMode
                # uint16_t screenConfigPad2
                self.screenConfig2, = unpack("<I", buff.read(4))
            else:
                logger.debug("This file does not have a screenConfig2! size={}".format(self.size))
                self.screenConfig2 = 0

            self.exceedingSize = self.size - (buff.tell() - self.start)
            if self.exceedingSize > 0:
                logger.debug("Skipping padding bytes!")
                self.padding = buff.read(self.exceedingSize)

        else:
            self.start = 0
            self.size = 0
            self.imsi = \
                ((kwargs.pop('mcc', 0) & 0xffff) << 0) + \
                ((kwargs.pop('mnc', 0) & 0xffff) << 16)

            self.locale = 0
            for char_ix, char in kwargs.pop('locale', "")[0:4]:
                self.locale += (ord(char) << (char_ix * 8))

            self.screenType = \
                ((kwargs.pop('orientation', 0) & 0xff) << 0) + \
                ((kwargs.pop('touchscreen', 0) & 0xff) << 8) + \
                ((kwargs.pop('density', 0) & 0xffff) << 16)

            self.input = \
                ((kwargs.pop('keyboard', 0) & 0xff) << 0) + \
                ((kwargs.pop('navigation', 0) & 0xff) << 8) + \
                ((kwargs.pop('inputFlags', 0) & 0xff) << 16) + \
                ((kwargs.pop('inputPad0', 0) & 0xff) << 24)

            self.screenSize = \
                ((kwargs.pop('screenWidth', 0) & 0xffff) << 0) + \
                ((kwargs.pop('screenHeight', 0) & 0xffff) << 16)

            self.version = \
                ((kwargs.pop('sdkVersion', 0) & 0xffff) << 0) + \
                ((kwargs.pop('minorVersion', 0) & 0xffff) << 16)

            self.screenConfig = \
                ((kwargs.pop('screenLayout', 0) & 0xff) << 0) + \
                ((kwargs.pop('uiMode', 0) & 0xff) << 8) + \
                ((kwargs.pop('smallestScreenWidthDp', 0) & 0xffff) << 16)

            self.screenSizeDp = \
                ((kwargs.pop('screenWidthDp', 0) & 0xffff) << 0) + \
                ((kwargs.pop('screenHeightDp', 0) & 0xffff) << 16)

            # TODO add this some day...
            self.screenConfig2 = 0

            self.exceedingSize = 0

    def _unpack_language_or_region(self, char_in, char_base):
        char_out = ""
        if char_in[0] & 0x80:
            first = char_in[1] & 0x1f
            second = ((char_in[1] & 0xe0) >> 5) + ((char_in[0] & 0x03) << 3)
            third = (char_in[0] & 0x7c) >> 2
            char_out += chr(first + char_base)
            char_out += chr(second + char_base)
            char_out += chr(third + char_base)
        else:
            if char_in[0]:
                char_out += chr(char_in[0])
            if char_in[1]:
                char_out += chr(char_in[1])
        return char_out

    def get_language_and_region(self):
        """
        Returns the combined language+region string or \x00\x00 for the default locale
        :return:
        """
        if self.locale != 0:
            _language = self._unpack_language_or_region([self.locale & 0xff, (self.locale & 0xff00) >> 8, ], ord('a'))
            _region = self._unpack_language_or_region([(self.locale & 0xff0000) >> 16, (self.locale & 0xff000000) >> 24, ], ord('0'))
            return (_language + "-r" + _region) if _region else _language
        return "\x00\x00"

    def get_config_name_friendly(self):
        """
        Here for legacy reasons.

        use :meth:`~get_qualifier` instead.
        """
        return self.get_qualifier()

    def get_qualifier(self):
        """
        Return resource name qualifier for the current configuration.
        for example
        * `ldpi-v4`
        * `hdpi-v4`

        All possible qualifiers are listed in table 2 of https://developer.android.com/guide/topics/resources/providing-resources

        You can find how android process this at http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#3243

        :return: str
        """
        res = []

        mcc = self.imsi & 0xFFFF
        mnc = (self.imsi & 0xFFFF0000) >> 16
        if mcc != 0:
            res.append("mcc%d" % mcc)
        if mnc != 0:
            res.append("mnc%d" % mnc)

        if self.locale != 0:
            res.append(self.get_language_and_region())

        screenLayout = self.screenConfig & 0xff
        if (screenLayout & MASK_LAYOUTDIR) != 0:
            if screenLayout & MASK_LAYOUTDIR == LAYOUTDIR_LTR:
                res.append("ldltr")
            elif screenLayout & MASK_LAYOUTDIR == LAYOUTDIR_RTL:
                res.append("ldrtl")
            else:
                res.append("layoutDir_%d" % (screenLayout & MASK_LAYOUTDIR))

        smallestScreenWidthDp = (self.screenConfig & 0xFFFF0000) >> 16
        if smallestScreenWidthDp != 0:
            res.append("sw%ddp" % smallestScreenWidthDp)

        screenWidthDp = self.screenSizeDp & 0xFFFF
        screenHeightDp = (self.screenSizeDp & 0xFFFF0000) >> 16
        if screenWidthDp != 0:
            res.append("w%ddp" % screenWidthDp)
        if screenHeightDp != 0:
            res.append("h%ddp" % screenHeightDp)

        if (screenLayout & MASK_SCREENSIZE) != SCREENSIZE_ANY:
            if screenLayout & MASK_SCREENSIZE == SCREENSIZE_SMALL:
                res.append("small")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_NORMAL:
                res.append("normal")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_LARGE:
                res.append("large")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_XLARGE:
                res.append("xlarge")
            else:
                res.append("screenLayoutSize_%d" % (screenLayout & MASK_SCREENSIZE))
        if (screenLayout & MASK_SCREENLONG) != 0:
            if screenLayout & MASK_SCREENLONG == SCREENLONG_NO:
                res.append("notlong")
            elif screenLayout & MASK_SCREENLONG == SCREENLONG_YES:
                res.append("long")
            else:
                res.append("screenLayoutLong_%d" % (screenLayout & MASK_SCREENLONG))

        screenLayout2 = self.screenConfig2 & 0xff
        if (screenLayout2 & MASK_SCREENROUND) != 0:
            if screenLayout2 & MASK_SCREENROUND == SCREENROUND_NO:
                res.append("notround")
            elif screenLayout2 & MASK_SCREENROUND == SCREENROUND_YES:
                res.append("round")
            else:
                res.append("screenRound_%d" % (screenLayout2 & MASK_SCREENROUND))

        colorMode = (self.screenConfig2 & 0xff00) >> 8
        if (colorMode & MASK_WIDE_COLOR_GAMUT) != 0:
            if colorMode & MASK_WIDE_COLOR_GAMUT == WIDE_COLOR_GAMUT_NO:
                res.append("nowidecg")
            elif colorMode & MASK_WIDE_COLOR_GAMUT == WIDE_COLOR_GAMUT_YES:
                res.append("widecg")
            else:
                res.append("wideColorGamut_%d" % (colorMode & MASK_WIDE_COLOR_GAMUT))

        if (colorMode & MASK_HDR) != 0:
            if colorMode & MASK_HDR == HDR_NO:
                res.append("lowdr")
            elif colorMode & MASK_HDR == HDR_YES:
                res.append("highdr")
            else:
                res.append("hdr_%d" % (colorMode & MASK_HDR))

        orientation = self.screenType & 0xff
        if orientation != ORIENTATION_ANY:
            if orientation == ORIENTATION_PORT:
                res.append("port")
            elif orientation == ORIENTATION_LAND:
                res.append("land")
            elif orientation == ORIENTATION_SQUARE:
                res.append("square")
            else:
                res.append("orientation_%d" % orientation)

        uiMode = (self.screenConfig & 0xff00) >> 8
        if (uiMode & MASK_UI_MODE_TYPE) != UI_MODE_TYPE_ANY:
            ui_mode = uiMode & MASK_UI_MODE_TYPE
            if ui_mode == UI_MODE_TYPE_DESK:
                res.append("desk")
            elif ui_mode == UI_MODE_TYPE_CAR:
                res.append("car")
            elif ui_mode == UI_MODE_TYPE_TELEVISION:
                res.append("television")
            elif ui_mode == UI_MODE_TYPE_APPLIANCE:
                res.append("appliance")
            elif ui_mode == UI_MODE_TYPE_WATCH:
                res.append("watch")
            elif ui_mode == UI_MODE_TYPE_VR_HEADSET:
                res.append("vrheadset")
            else:
                res.append("uiModeType_%d" % ui_mode)

        if (uiMode & MASK_UI_MODE_NIGHT) != 0:
            if uiMode & MASK_UI_MODE_NIGHT == UI_MODE_NIGHT_NO:
                res.append("notnight")
            elif uiMode & MASK_UI_MODE_NIGHT == UI_MODE_NIGHT_YES:
                res.append("night")
            else:
                res.append("uiModeNight_%d" % (uiMode & MASK_UI_MODE_NIGHT))

        density = (self.screenType & 0xffff0000) >> 16
        if density != DENSITY_DEFAULT:
            if density == DENSITY_LOW:
                res.append("ldpi")
            elif density == DENSITY_MEDIUM:
                res.append("mdpi")
            elif density == DENSITY_TV:
                res.append("tvdpi")
            elif density == DENSITY_HIGH:
                res.append("hdpi")
            elif density == DENSITY_XHIGH:
                res.append("xhdpi")
            elif density == DENSITY_XXHIGH:
                res.append("xxhdpi")
            elif density == DENSITY_XXXHIGH:
                res.append("xxxhdpi")
            elif density == DENSITY_NONE:
                res.append("nodpi")
            elif density == DENSITY_ANY:
                res.append("anydpi")
            else:
                res.append("%ddpi" % (density))

        touchscreen = (self.screenType & 0xff00) >> 8
        if touchscreen != TOUCHSCREEN_ANY:
            if touchscreen == TOUCHSCREEN_NOTOUCH:
                res.append("notouch")
            elif touchscreen == TOUCHSCREEN_FINGER:
                res.append("finger")
            elif touchscreen == TOUCHSCREEN_STYLUS:
                res.append("stylus")
            else:
                res.append("touchscreen_%d" % touchscreen)

        keyboard = self.input & 0xff
        navigation = (self.input & 0xff00) >> 8
        inputFlags = (self.input & 0xff0000) >> 16

        if inputFlags & MASK_KEYSHIDDEN != 0:
            input_flags = inputFlags & MASK_KEYSHIDDEN
            if input_flags == KEYSHIDDEN_NO:
                res.append("keysexposed")
            elif input_flags == KEYSHIDDEN_YES:
                res.append("keyshidden")
            elif input_flags == KEYSHIDDEN_SOFT:
                res.append("keyssoft")

        if keyboard != KEYBOARD_ANY:
            if keyboard == KEYBOARD_NOKEYS:
                res.append("nokeys")
            elif keyboard == KEYBOARD_QWERTY:
                res.append("qwerty")
            elif keyboard == KEYBOARD_12KEY:
                res.append("12key")
            else:
                res.append("keyboard_%d" % keyboard)

        if inputFlags & MASK_NAVHIDDEN != 0:
            input_flags = inputFlags & MASK_NAVHIDDEN
            if input_flags == NAVHIDDEN_NO:
                res.append("navexposed")
            elif input_flags == NAVHIDDEN_YES:
                res.append("navhidden")
            else:
                res.append("inputFlagsNavHidden_%d" % input_flags)

        if navigation != NAVIGATION_ANY:
            if navigation == NAVIGATION_NONAV:
                res.append("nonav")
            elif navigation == NAVIGATION_DPAD:
                res.append("dpad")
            elif navigation == NAVIGATION_TRACKBALL:
                res.append("trackball")
            elif navigation == NAVIGATION_WHEEL:
                res.append("wheel")
            else:
                res.append("navigation_%d" % navigation)

        screenSize = self.screenSize
        if screenSize != 0:
            screenWidth = self.screenSize & 0xffff
            screenHeight = (self.screenSize & 0xffff0000) >> 16
            res.append("%dx%d" % (screenWidth, screenHeight))

        version = self.version
        if version != 0:
            sdkVersion = self.version & 0xffff
            minorVersion = (self.version & 0xffff0000) >> 16
            res.append("v%d" % sdkVersion)
            if minorVersion != 0:
                res.append(".%d" % minorVersion)

        return "-".join(res)

    def get_language(self):
        x = self.locale & 0x0000ffff
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)

    def get_country(self):
        x = (self.locale & 0xffff0000) >> 16
        return chr(x & 0x00ff) + chr((x & 0xff00) >> 8)

    def get_density(self):
        x = ((self.screenType >> 16) & 0xffff)
        return x

    def is_default(self):
        """
        Test if this is a default resource, which matches all

        This is indicated that all fields are zero.
        :return: True if default, False otherwise
        """
        return all(map(lambda x: x == 0, self._get_tuple()))

    def _get_tuple(self):
        return (
            self.imsi,
            self.locale,
            self.screenType,
            self.input,
            self.screenSize,
            self.version,
            self.screenConfig,
            self.screenSizeDp,
            self.screenConfig2,
        )

    def __hash__(self):
        return hash(self._get_tuple())

    def __eq__(self, other):
        return self._get_tuple() == other._get_tuple()

    def __repr__(self):
        return "<ARSCResTableConfig '{}'={}>".format(self.get_qualifier(), repr(self._get_tuple()))


class ARSCResTableEntry:
    """
    A `ResTable_entry`.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1458
    """
    # If set, this is a complex entry, holding a set of name/value
    # mappings.  It is followed by an array of ResTable_map structures.
    FLAG_COMPLEX = 1

    # If set, this resource has been declared public, so libraries
    # are allowed to reference it.
    FLAG_PUBLIC = 2

    # If set, this is a weak resource and may be overriden by strong
    # resources of the same name/type. This is only useful during
    # linking with other resource tables.
    FLAG_WEAK = 4

    def __init__(self, buff, mResId, parent=None):
        self.start = buff.tell()
        self.mResId = mResId
        self.parent = parent

        self.size = unpack('<H', buff.read(2))[0]
        self.flags = unpack('<H', buff.read(2))[0]
        # This is a ResStringPool_ref
        self.index = unpack('<I', buff.read(4))[0]

        if self.is_complex():
            self.item = ARSCComplex(buff, parent)
        else:
            # If FLAG_COMPLEX is not set, a Res_value structure will follow
            self.key = ARSCResStringPoolRef(buff, self.parent)

        if self.is_weak():
            logger.debug("Parsed {}".format(self))

    def get_index(self):
        return self.index

    def get_value(self):
        return self.parent.mKeyStrings.getString(self.index)

    def get_key_data(self):
        return self.key.get_data_value()

    def is_public(self):
        return (self.flags & self.FLAG_PUBLIC) != 0

    def is_complex(self):
        return (self.flags & self.FLAG_COMPLEX) != 0

    def is_weak(self):
        return (self.flags & self.FLAG_WEAK) != 0

    def __repr__(self):
        return "<ARSCResTableEntry idx='0x{:08x}' mResId='0x{:08x}' size='{}' flags='0x{:02x}' index='0x{:x}' holding={}>".format(
            self.start,
            self.mResId,
            self.size,
            self.flags,
            self.index,
            self.item if self.is_complex() else self.key)


class ARSCComplex:
    """
    This is actually a `ResTable_map_entry`

    It contains a set of {name: value} mappings, which are of type `ResTable_map`.
    A `ResTable_map` contains two items: `ResTable_ref` and `Res_value`.

    See http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1485 for `ResTable_map_entry`
    and http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1498 for `ResTable_map`
    """
    def __init__(self, buff, parent=None):
        self.start = buff.tell()
        self.parent = parent

        self.id_parent = unpack('<I', buff.read(4))[0]
        self.count = unpack('<I', buff.read(4))[0]

        self.items = []
        # Parse self.count number of `ResTable_map`
        # these are structs of ResTable_ref and Res_value
        # ResTable_ref is a uint32_t.
        for i in range(0, self.count):
            self.items.append((unpack('<I', buff.read(4))[0], ARSCResStringPoolRef(buff, self.parent)))

    def __repr__(self):
        return "<ARSCComplex idx='0x{:08x}' parent='{}' count='{}'>".format(self.start, self.id_parent, self.count)


class ARSCResStringPoolRef:
    """
    This is actually a `Res_value`
    It holds information about the stored resource value

    See: http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#262
    """
    def __init__(self, buff, parent=None):
        self.start = buff.tell()
        self.parent = parent

        self.size, = unpack("<H", buff.read(2))
        self.res0, = unpack("<B", buff.read(1))
        try:
            if self.res0 != 0:
                logger.warning("res0 must be always zero!")
            self.data_type = unpack('<B', buff.read(1))[0]
            # data is interpreted according to data_type
            self.data = unpack('<I', buff.read(4))[0]
        except Exception as e:
            logger.error(e)

    def get_data_value(self):
        return self.parent.stringpool_main.getString(self.data)

    def get_data(self):
        return self.data

    def get_data_type(self):
        return self.data_type

    def get_data_type_string(self):
        return TYPE_TABLE[self.data_type]

    def format_value(self):
        """
        Return the formatted (interpreted) data according to `data_type`.
        """
        return format_value(
            self.data_type,
            self.data,
            self.parent.stringpool_main.getString
        )

    def is_reference(self):
        """
        Returns True if the Res_value is actually a reference to another resource
        """
        return self.data_type == TYPE_REFERENCE

    def __repr__(self):
        return "<ARSCResStringPoolRef idx='0x{:08x}' size='{}' type='{}' data='0x{:08x}'>".format(
            self.start,
            self.size,
            TYPE_TABLE.get(self.data_type, "0x%x" % self.data_type),
            self.data)


def get_arsc_info(arscobj):
    """
    Return a string containing all resources packages ordered by packagename, locale and type.

    :param arscobj: :class:`~ARSCParser`
    :return: a string
    """
    buff = ""
    for package in arscobj.get_packages_names():
        buff += package + ":\n"
        for locale in arscobj.get_locales(package):
            buff += "\t" + repr(locale) + ":\n"
            for ttype in arscobj.get_types(package, locale):
                buff += "\t\t" + ttype + ":\n"
                try:
                    tmp_buff = getattr(arscobj, "get_" + ttype + "_resources")(
                        package, locale).decode("utf-8", 'replace').split("\n")
                    for i in tmp_buff:
                        buff += "\t\t\t" + i + "\n"
                except AttributeError:
                    pass
    return buff