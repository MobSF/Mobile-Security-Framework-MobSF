# -*- coding: utf_8 -*-
# flake8: noqa
"""This file is from apkinspector licensed under the Apache License 2.0."""
import io
import zlib
import struct
from typing import Dict


def extract_file_based_on_header_info(apk_file, local_header_info, central_directory_info):
    """
    Extracts a single file from the apk_file based on the information provided from the offset and the header_info.
    It takes into account that the compression method provided might not be STORED or DEFLATED! The returned
    'indicator', shows what compression method was used. Besides the standard STORED/DEFLATE it may return
    'DEFLATED_TAMPERED', which means that the compression method found was not DEFLATED(8) but it should have been,
    and 'STORED_TAMPERED' which means that the compression method found was not STORED(0) but should have been.

    :param apk_file: The APK file e.g. with open('test.apk', 'rb') as apk_file
    :type apk_file: bytesIO
    :param local_header_info: The local header dictionary info for that specific filename
    :type local_header_info: dict
    :param central_directory_info: The central directory entry for that specific filename
    :type central_directory_info: dict
    :return: Returns the actual extracted data for that file along with an indication of whether a static analysis evasion technique was used or not.
    :rtype: set(bytes, str)
    """
    filename_length = local_header_info["file_name_length"]
    if local_header_info["compressed_size"] == 0 or local_header_info["uncompressed_size"] == 0:
        compressed_size = central_directory_info["compressed_size"]
        uncompressed_size = central_directory_info["uncompressed_size"]
    else:
        compressed_size = local_header_info["compressed_size"]
        uncompressed_size = local_header_info["uncompressed_size"]

    extra_field_length = local_header_info["extra_field_length"]
    compression_method = local_header_info["compression_method"]
    # Skip the offset + local header to reach the compressed data
    local_header_size = 30  # Size of the local header in bytes
    offset = central_directory_info["relative_offset_of_local_file_header"]
    apk_file.seek(offset + local_header_size + filename_length + extra_field_length)
    if compression_method == 0:  # Stored (no compression)
        uncompressed_data = apk_file.read(uncompressed_size)
        extracted_data = uncompressed_data
        indicator = 'STORED'
    elif compression_method == 8:
        compressed_data = apk_file.read(compressed_size)
        # -15 for windows size due to raw stream with no header or trailer
        extracted_data = zlib.decompress(compressed_data, -15)
        indicator = 'DEFLATED'
    else:
        try:
            cur_loc = apk_file.tell()
            compressed_data = apk_file.read(compressed_size)
            extracted_data = zlib.decompress(compressed_data, -15)
            indicator = 'DEFLATED_TAMPERED'
        except:
            apk_file.seek(cur_loc)
            compressed_data = apk_file.read(uncompressed_size)
            extracted_data = compressed_data
            indicator = 'STORED_TAMPERED'
    return extracted_data, indicator


class EndOfCentralDirectoryRecord:
    """
    A class to provide details about the end of central directory record.
    """
    def __init__(self, signature, number_of_this_disk, disk_where_central_directory_starts,
                 number_of_central_directory_records_on_this_disk,
                 total_number_of_central_directory_records, size_of_central_directory,
                 offset_of_start_of_central_directory, comment_length, comment):
        self.signature = signature
        self.number_of_this_disk = number_of_this_disk
        self.disk_where_central_directory_starts = disk_where_central_directory_starts
        self.number_of_central_directory_records_on_this_disk = number_of_central_directory_records_on_this_disk
        self.total_number_of_central_directory_records = total_number_of_central_directory_records
        self.size_of_central_directory = size_of_central_directory
        self.offset_of_start_of_central_directory = offset_of_start_of_central_directory
        self.comment_length = comment_length
        self.comment = comment

    @classmethod
    def parse(cls, apk_file):
        """
        Method to locate the "end of central directory record signature" as the first step of the correct process of
        reading a ZIP archive. Should be noted that certain APKs do not follow the zip specification and declare multiple
        "end of central directory records". For this reason the search for the corresponding signature of the eocd starts
        from the end of the apk.

        :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
        :type apk_file: bytesIO
        :return: Returns the end of central directory record with all the information available if the corresponding signature is found. If not, then it returns None.
        :rtype: EndOfCentralDirectoryRecord or None
        """
        chunk_size = 1024
        offset = 0
        signature_offset = -1
        file_size = apk_file.seek(0, 2)
        while offset < file_size:
            position = file_size - offset - chunk_size
            if position < 0:
                position = 0
            apk_file.seek(position)
            chunk = apk_file.read(chunk_size)
            if not chunk:
                break
            signature_offset = chunk.rfind(b'\x50\x4b\x05\x06')  # end of Central Directory File Header signature
            if signature_offset != -1:
                eo_central_directory_offset = position + signature_offset
                break  # Found End of central directory record (EOCD) signature
            offset += chunk_size
        if signature_offset == -1:
            raise ValueError("End of central directory record (EOCD) signature not found")
        apk_file.seek(eo_central_directory_offset)

        signature = apk_file.read(4)
        number_of_this_disk = struct.unpack('<H', apk_file.read(2))[0]
        disk_where_central_directory_starts = struct.unpack('<H', apk_file.read(2))[0]
        number_of_central_directory_records_on_this_disk = struct.unpack('<H', apk_file.read(2))[0]
        total_number_of_central_directory_records = struct.unpack('<H', apk_file.read(2))[0]
        size_of_central_directory = struct.unpack('<I', apk_file.read(4))[0]
        offset_of_start_of_central_directory = struct.unpack('<I', apk_file.read(4))[0]
        comment_length = struct.unpack('<H', apk_file.read(2))[0]
        comment = struct.unpack(f'<{comment_length}s', apk_file.read(comment_length))[0].decode('utf-8', 'ignore')
        return cls(
            signature,
            number_of_this_disk,
            disk_where_central_directory_starts,
            number_of_central_directory_records_on_this_disk,
            total_number_of_central_directory_records,
            size_of_central_directory,
            offset_of_start_of_central_directory,
            comment_length,
            comment
        )

    def to_dict(self):
        """
        Represent the class as a dictionary.

        :return: returns the dictionary
        :rtype: dict
        """
        return {
            "signature": self.signature,
            "number_of_this_disk": self.number_of_this_disk,
            "disk_where_central_directory_starts": self.disk_where_central_directory_starts,
            "number_of_central_directory_records_on_this_disk": self.number_of_central_directory_records_on_this_disk,
            "total_number_of_central_directory_records": self.total_number_of_central_directory_records,
            "size_of_central_directory": self.size_of_central_directory,
            "offset_of_start_of_central_directory": self.offset_of_start_of_central_directory,
            "comment_length": self.comment_length,
            "comment": self.comment
        }

    @classmethod
    def from_dict(cls, entry_dict):
        """
        Convert a dictionary back to an instance of the class.

        :param entry_dict: the dictionary
        :type entry_dict: dict
        :return: the instance of the class
        :rtype: EndOfCentralDirectoryRecord
        """
        return cls(**entry_dict)


class CentralDirectoryEntry:
    """
    A class representing each entry in the central directory.
    """
    def __init__(self, version_made_by, version_needed_to_extract, general_purpose_bit_flag,
                 compression_method, file_last_modification_time, file_last_modification_date,
                 crc32_of_uncompressed_data, compressed_size, uncompressed_size, file_name_length,
                 extra_field_length, file_comment_length, disk_number_where_file_starts,
                 internal_file_attributes, external_file_attributes, relative_offset_of_local_file_header,
                 filename, extra_field, file_comment, offset_in_central_directory):
        self.version_made_by = version_made_by
        self.version_needed_to_extract = version_needed_to_extract
        self.general_purpose_bit_flag = general_purpose_bit_flag
        self.compression_method = compression_method
        self.file_last_modification_time = file_last_modification_time
        self.file_last_modification_date = file_last_modification_date
        self.crc32_of_uncompressed_data = crc32_of_uncompressed_data
        self.compressed_size = compressed_size
        self.uncompressed_size = uncompressed_size
        self.file_name_length = file_name_length
        self.extra_field_length = extra_field_length
        self.file_comment_length = file_comment_length
        self.disk_number_where_file_starts = disk_number_where_file_starts
        self.internal_file_attributes = internal_file_attributes
        self.external_file_attributes = external_file_attributes
        self.relative_offset_of_local_file_header = relative_offset_of_local_file_header
        self.filename = filename
        self.extra_field = extra_field
        self.file_comment = file_comment
        self.offset_in_central_directory = offset_in_central_directory

    def to_dict(self):
        """
        Represent the class as a dictionary.

        :return: returns the dictionary
        :rtype: dict
        """
        return {
            "version_made_by": self.version_made_by,
            "version_needed_to_extract": self.version_needed_to_extract,
            "general_purpose_bit_flag": self.general_purpose_bit_flag,
            "compression_method": self.compression_method,
            "file_last_modification_time": self.file_last_modification_time,
            "file_last_modification_date": self.file_last_modification_date,
            "crc32_of_uncompressed_data": self.crc32_of_uncompressed_data,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "file_name_length": self.file_name_length,
            "extra_field_length": self.extra_field_length,
            "file_comment_length": self.file_comment_length,
            "disk_number_where_file_starts": self.disk_number_where_file_starts,
            "internal_file_attributes": self.internal_file_attributes,
            "external_file_attributes": self.external_file_attributes,
            "relative_offset_of_local_file_header": self.relative_offset_of_local_file_header,
            "filename": self.filename,
            "extra_field": self.extra_field,
            "file_comment": self.file_comment,
            "offset_in_central_directory": self.offset_in_central_directory
        }

    @classmethod
    def from_dict(cls, entry_dict):
        """
        Convert a dictionary back to an instance of the class.

        :param entry_dict: the dictionary
        :type entry_dict: dict
        :return: the instance of the class
        :rtype: CentralDirectoryEntry
        """
        return cls(**entry_dict)


class CentralDirectory:
    """
    The CentralDirectory containing all the CentralDirectoryEntry entries discovered.
    The entries are listed as a dictionary where the filename is the key.
    """
    def __init__(self, entries):
        self.entries = entries

    @classmethod
    def parse(cls, apk_file, eocd: EndOfCentralDirectoryRecord = None):
        """
        Method that is used to parse the central directory header according to the specification
        https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT
        based on the offset provided by the end of central directory record: eocd.offset_of_start_of_central_directory.

        :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
        :type apk_file: bytesIO
        :param eocd: End of central directory record
        :type eocd: EndOfCentralDirectoryRecord
        :return: Returns a dictionary with all the entries discovered. The filename of each entry is used as the key. Besides the fields defined by the specification, each entry has an additional field named 'Offset in the central directory header', which includes the offset of the entry in the central directory itself.
        :rtype: CentralDirectory
        """
        if not eocd:
            eocd = EndOfCentralDirectoryRecord.parse(apk_file)
        apk_file.seek(eocd.offset_of_start_of_central_directory)
        if apk_file.tell() != eocd.offset_of_start_of_central_directory:
            raise ValueError(f"Failed to find the offset for the central directory within the file!")

        central_directory_entries = {}
        while True:
            c_offset = apk_file.tell()
            signature = apk_file.read(4)
            if signature != b'\x50\x4b\x01\x02':
                break  # Reached the end of the central directory
            version_made_by = struct.unpack('<H', apk_file.read(2))[0]
            version_needed_to_extract = struct.unpack('<H', apk_file.read(2))[0]
            general_purpose_bit_flag = struct.unpack('<H', apk_file.read(2))[0]
            compression_method = struct.unpack('<H', apk_file.read(2))[0]
            file_last_modification_time = struct.unpack('<H', apk_file.read(2))[0]
            file_last_modification_date = struct.unpack('<H', apk_file.read(2))[0]
            crc32_of_uncompressed_data = struct.unpack('<I', apk_file.read(4))[0]
            compressed_size = struct.unpack('<I', apk_file.read(4))[0]
            uncompressed_size = struct.unpack('<I', apk_file.read(4))[0]
            file_name_length = struct.unpack('<H', apk_file.read(2))[0]
            extra_field_length = struct.unpack('<H', apk_file.read(2))[0]
            file_comment_length = struct.unpack('<H', apk_file.read(2))[0]
            disk_number_where_file_starts = struct.unpack('<H', apk_file.read(2))[0]
            internal_file_attributes = struct.unpack('<H', apk_file.read(2))[0]
            external_file_attributes = struct.unpack('<I', apk_file.read(4))[0]
            relative_offset_of_local_file_header = struct.unpack('<I', apk_file.read(4))[0]
            filename = struct.unpack(f'<{file_name_length}s', apk_file.read(file_name_length))[0].decode('utf-8')
            extra_field = struct.unpack(f'<{extra_field_length}s', apk_file.read(extra_field_length))[0].decode('utf-8',
                                                                                                                'ignore')
            file_comment = struct.unpack(f'<{file_comment_length}s', apk_file.read(file_comment_length))[0].decode(
                'utf-8', 'ignore')
            offset_in_central_directory = c_offset

            central_directory_entry = CentralDirectoryEntry(
                version_made_by, version_needed_to_extract, general_purpose_bit_flag, compression_method,
                file_last_modification_time, file_last_modification_date, crc32_of_uncompressed_data,
                compressed_size, uncompressed_size, file_name_length, extra_field_length, file_comment_length,
                disk_number_where_file_starts, internal_file_attributes, external_file_attributes,
                relative_offset_of_local_file_header, filename, extra_field, file_comment,
                offset_in_central_directory
            )
            central_directory_entries[central_directory_entry.filename] = central_directory_entry

        return cls(central_directory_entries)

    def to_dict(self):
        """
        Represent the class as a dictionary.

        :return: returns the dictionary
        :rtype: dict
        """
        return {filename: entry.to_dict() for filename, entry in self.entries.items()}

    @classmethod
    def from_dict(cls, entry_dict):
        """
        Convert a dictionary back to an instance of the class.

        :param entry_dict: the dictionary
        :type entry_dict: dict
        :return: the instance of the class
        :rtype: CentralDirectory
        """
        entries = {}
        for filename, entry_data in entry_dict.items():
            entry_instance = CentralDirectoryEntry.from_dict(entry_data)
            entries[filename] = entry_instance
        return cls(entries=entries)


class LocalHeaderRecord:
    """
    The local header for each entry discovered.
    """
    def __init__(self, version_needed_to_extract, general_purpose_bit_flag,
                 compression_method, file_last_modification_time, file_last_modification_date,
                 crc32_of_uncompressed_data, compressed_size, uncompressed_size, file_name_length,
                 extra_field_length, filename, extra_field):

        self.version_needed_to_extract = version_needed_to_extract
        self.general_purpose_bit_flag = general_purpose_bit_flag
        self.compression_method = compression_method
        self.file_last_modification_time = file_last_modification_time
        self.file_last_modification_date = file_last_modification_date
        self.crc32_of_uncompressed_data = crc32_of_uncompressed_data
        self.compressed_size = compressed_size
        self.uncompressed_size = uncompressed_size
        self.file_name_length = file_name_length
        self.extra_field_length = extra_field_length
        self.filename = filename
        self.extra_field = extra_field

    @classmethod
    def parse(cls, apk_file, entry_of_interest: CentralDirectoryEntry):
        """
        Method that attempts to read the local file header according to the specification https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.9.TXT.

        :param apk_file: The already read/loaded data of the APK file e.g. with open('test.apk', 'rb') as apk_file
        :type apk_file: bytesIO
        :param entry_of_interest: The central directory header of the specific entry of interest
        :type entry_of_interest: CentralDirectoryEntry
        :return: Returns a dictionary with the local header information or None if it failed to find the header.
        :rtype: LocalHeaderRecord or None
        """
        apk_file.seek(entry_of_interest.relative_offset_of_local_file_header)
        header_signature = apk_file.read(4)

        if not header_signature == b'\x50\x4b\x03\x04':
            print(f"Does not seem to be the start of a local header!")
            return None
        else:
            version_needed_to_extract = struct.unpack('<H', apk_file.read(2))[0]
            general_purpose_bit_flag = struct.unpack('<H', apk_file.read(2))[0]
            compression_method = struct.unpack('<H', apk_file.read(2))[0]
            file_last_modification_time = struct.unpack('<H', apk_file.read(2))[0]
            file_last_modification_date = struct.unpack('<H', apk_file.read(2))[0]
            crc32_of_uncompressed_data = struct.unpack('<I', apk_file.read(4))[0]
            compressed_size = struct.unpack('<I', apk_file.read(4))[0]
            uncompressed_size = struct.unpack('<I', apk_file.read(4))[0]
            file_name_length = struct.unpack('<H', apk_file.read(2))[0]
            extra_field_length = struct.unpack('<H', apk_file.read(2))[0]
            filename = struct.unpack(f'<{file_name_length}s', apk_file.read(file_name_length))[0].decode('utf-8')
            extra_field = struct.unpack(f'<{extra_field_length}s', apk_file.read(extra_field_length))[0].decode('utf-8',
                                                                                                                'ignore')
        return cls(
            version_needed_to_extract, general_purpose_bit_flag, compression_method,
            file_last_modification_time, file_last_modification_date, crc32_of_uncompressed_data,
            compressed_size, uncompressed_size, file_name_length, extra_field_length,
            filename, extra_field)

    def to_dict(self):
        """
        Represent the class as a dictionary.

        :return: returns the dictionary
        :rtype: dict
        """
        return {
            "version_needed_to_extract": self.version_needed_to_extract,
            "general_purpose_bit_flag": self.general_purpose_bit_flag,
            "compression_method": self.compression_method,
            "file_last_modification_time": self.file_last_modification_time,
            "file_last_modification_date": self.file_last_modification_date,
            "crc32_of_uncompressed_data": self.crc32_of_uncompressed_data,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "file_name_length": self.file_name_length,
            "extra_field_length": self.extra_field_length,
            "filename": self.filename,
            "extra_field": self.extra_field
        }

    @classmethod
    def from_dict(cls, entry_dict):
        """
        Convert a dictionary back to an instance of the class.

        :param entry_dict: the dictionary
        :type entry_dict: dict
        :return: the instance of the class
        :rtype: LocalHeaderRecord
        """
        return cls(**entry_dict)


class ZipEntry:
    """
    Is the actual APK represented as a composition of the previous classes, which are: the EndOfCentralDirectoryRecord, the CentralDirectory and a dictionary of values of LocalHeaderRecord.
    """
    def __init__(self, zip_bytes, eocd: EndOfCentralDirectoryRecord, central_directory: CentralDirectory,
                 local_headers: Dict[str, LocalHeaderRecord]):
        self.zip = zip_bytes
        self.eocd = eocd
        self.central_directory = central_directory
        self.local_headers = local_headers

    @classmethod
    def parse(cls, inc_apk, raw: bool = True):
        """
        Method to start processing an APK. The raw (bytes) APK may be passed or the path to it.

        :param inc_apk: the incoming apk, either path or bytes
        :type inc_apk: str or bytesIO
        :param raw: boolean flag to specify whether it is the raw apk in bytes or not
        :type raw: bool
        :return: returns the instance of the class
        :rtype: ZipEntry
        """
        if raw:
            apk_file = inc_apk
        else:
            with open(inc_apk, 'rb') as apk:
                apk_file = io.BytesIO(apk.read())
        eocd = EndOfCentralDirectoryRecord.parse(apk_file)
        central_directory = CentralDirectory.parse(apk_file, eocd)
        local_headers = {}
        for entry in central_directory.entries:
            local_header_entry = LocalHeaderRecord.parse(apk_file, central_directory.entries[entry])
            local_headers[local_header_entry.filename] = local_header_entry
        return cls(apk_file, eocd, central_directory, local_headers)

    @classmethod
    def parse_single(cls, apk_file, filename, eocd: EndOfCentralDirectoryRecord = None,
                     central_directory: CentralDirectory = None):
        """
        Similar to parse, but instead of parsing the entire APK, it only targets the specified file.

        :param apk_file: The apk file expected raw
        :type apk_file: io.TextIOWrapper
        :param filename: the filename of the file to be parsed
        :type filename: str
        :param eocd: Optionally, the instance of the end of central directory from the APK
        :type eocd: EndOfCentralDirectoryRecord(, optional)
        :param central_directory: Optionally, the instance of the central directory record
        :type central_directory: CentralDirectory(, optional)
        :return: returns the instance of the class
        :rtype: ZipEntry
        """
        if not eocd or not central_directory:
            eocd = EndOfCentralDirectoryRecord.parse(apk_file)
            central_directory = CentralDirectory.parse(apk_file, eocd)
        local_header = {filename: LocalHeaderRecord.parse(apk_file, central_directory.entries[filename])}
        return cls(apk_file, eocd, central_directory, local_header)

    def to_dict(self):
        """
        Represent the class as a dictionary.

        :return: returns the dictionary
        :rtype: dict
        """
        return {
            "end_of_central_directory": self.eocd.to_dict(),
            "central_directory": self.central_directory.to_dict(),
            "local_headers": {filename: entry.to_dict() for filename, entry in self.local_headers.items()}
        }

    def get_central_directory_entry_dict(self, filename):
        """
        Method to retrieve the central directory entry for a specific filename.

        :param filename: the filename of the file to search for in the central directory
        :type filename: str
        :return: returns a dictionary of the central directory entry or None if the filename is not found
        :rtype: dict
        """
        if filename in self.central_directory.entries:
            return self.central_directory.entries[filename].to_dict()
        else:
            raise KeyError(f"Key: {filename} was not found within the central directory entries!")

    def get_local_header_dict(self, filename):
        """
        Method to retrieve the local header of a specific filename.

        :param filename: the filename of the entry to search for among the local headers
        :type filename: str
        :return: returns a ditionary of the local header entry or None if the filename is not found
        :rtype: dict
        """
        if filename in self.local_headers:
            return self.local_headers[filename].to_dict()
        else:
            raise KeyError(f"Key: {filename} was not found within the local headers list!")

    def read(self, name, save: bool = False):
        """
        Method to utilize the extract module and extract a single entry from the APK based on the filename.

        :param name: the name of the file to be read/extracted
        :type name: str
        :param save: boolean to define whether the extracted file should be saved as well or not
        :type save: bool(, optional)
        :return: returns the raw bytes of the filename that was extracted
        :rtype: bytes
        """
        extracted_file = extract_file_based_on_header_info(self.zip, self.get_local_header_dict(name),
                                                           self.get_central_directory_entry_dict(name))[0]
        # if save:
        #     save_data_to_file(f"EXTRACTED_{name}", extracted_file)
        return extracted_file

    def infolist(self) -> Dict[str, CentralDirectoryEntry]:
        """
        List of information about the entries in the central directory.

        :return: returns a dictionary where the keys are the filenames and the values are each an instance of the CentralDirectoryEntry
        :rtype: dict
        """
        return self.central_directory.entries

    def namelist(self):
        """
        List of the filenames included in the central directory.

        :return: returns the list of the filenames
        :rtype: list
        """
        return [vl for vl in self.central_directory.to_dict()]
