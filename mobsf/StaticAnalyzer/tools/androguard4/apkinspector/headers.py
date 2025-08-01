# -*- coding: utf_8 -*-
# flake8: noqa
# ApkInspector - Nov 24, 2024 - 293ab2d89ab9ce011c7dbbc5df3c876172875a1c
import io
import os
import struct
from typing import Dict

from .extract import extract_file_based_on_header_info, extract_all_files_from_central_directory
from .helpers import pretty_print_header, save_to_json, save_data_to_file


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
            position = max(0, file_size - offset - chunk_size)
            apk_file.seek(position)
            chunk = apk_file.read(chunk_size)
            if not chunk:
                break
            signature_offset = chunk.rfind(b'\x50\x4b\x05\x06')  # EOCD signature
            if signature_offset != -1:
                eo_central_directory_offset = position + signature_offset
                break  # Found EOCD signature
            # Adjust offset to overlap by 4 bytes
            offset += chunk_size - 4

        if signature_offset == -1:
            raise ValueError(
                "End of central directory record (EOCD) signature not found")
        apk_file.seek(eo_central_directory_offset)

        signature = apk_file.read(4)
        number_of_this_disk = struct.unpack('<H', apk_file.read(2))[0]
        disk_where_central_directory_starts = struct.unpack('<H', apk_file.read(2))[0]
        number_of_central_directory_records_on_this_disk = struct.unpack('<H', apk_file.read(2))[
            0]
        total_number_of_central_directory_records = struct.unpack('<H', apk_file.read(2))[
            0]
        size_of_central_directory = struct.unpack('<I', apk_file.read(4))[0]
        offset_of_start_of_central_directory = struct.unpack('<I', apk_file.read(4))[0]
        comment_length = struct.unpack('<H', apk_file.read(2))[0]
        comment = struct.unpack(f'<{comment_length}s', apk_file.read(comment_length))[
            0].decode('utf-8', 'ignore')
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
            raise ValueError(
                f"Failed to find the offset for the central directory within the file!")

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
            relative_offset_of_local_file_header = struct.unpack('<I', apk_file.read(4))[
                0]
            filename = struct.unpack(f'<{file_name_length}s', apk_file.read(file_name_length))[
                0].decode('utf-8', 'ignore')
            extra_field = struct.unpack(f'<{extra_field_length}s', apk_file.read(
                extra_field_length))[0].decode('utf-8', 'ignore')
            file_comment = struct.unpack(f'<{file_comment_length}s', apk_file.read(
                file_comment_length))[0].decode('utf-8', 'ignore')
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
            try:
                filename = struct.unpack(f'<{file_name_length}s', apk_file.read(file_name_length))[
                    0].decode('utf-8', 'ignore')
                extra_field = struct.unpack(f'<{extra_field_length}s', apk_file.read(
                    extra_field_length))[0].decode('utf-8', 'ignore')
            except:
                filename = entry_of_interest.filename
                extra_field = entry_of_interest.extra_field
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
            local_header_entry = LocalHeaderRecord.parse(
                apk_file, central_directory.entries[entry])
            local_headers[local_header_entry.filename] = local_header_entry
        return cls(apk_file, eocd, central_directory, local_headers)

    @classmethod
    def parse_single(cls, apk_file, filename, eocd: EndOfCentralDirectoryRecord = None,
                     central_directory: CentralDirectory = None):
        """
        Similar to parse, but instead of parsing the entire APK, it only targets the specified file.

        :param apk_file: The apk file expected raw
        :type apk_file: bytesIO
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
        local_header = {filename: LocalHeaderRecord.parse(
            apk_file, central_directory.entries[filename])}
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
            raise KeyError(
                f"Key: {filename} was not found within the central directory entries!")

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
            raise KeyError(
                f"Key: {filename} was not found within the local headers list!")

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
        if save:
            save_data_to_file(f"EXTRACTED_{name}", extracted_file)
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

    def extract_all(self, extract_path, apk_name):
        """
        Extracts all the contents of the APK.

        :param extract_path: where to extract it
        :type extract_path: str
        :param apk_name: the name of the apk
        :type apk_name: str
        """
        output_path = os.path.join(extract_path, apk_name)
        if not extract_all_files_from_central_directory(self.zip, self.to_dict()["central_directory"],
                                                        self.to_dict()["local_headers"], output_path):
            print(f"Extraction successful for: {apk_name}")


def print_headers_of_filename(cd_h_of_file, local_header_of_file):
    """
    Prints out the details for both the central directory header and the local file header. Useful for the CLI.

    :param cd_h_of_file: central directory header of a filename as it may be retrieved from headers_of_filename
    :type cd_h_of_file: dict
    :param local_header_of_file: local header dictionary of a filename as it may be retrieved from headers_of_filename
    :type local_header_of_file: dict
    """
    if not cd_h_of_file or not local_header_of_file:
        print("Are you sure the filename exists?")
        return
    pretty_print_header("CENTRAL DIRECTORY")
    for k in cd_h_of_file:
        if k == 'Relative offset of local file header' or k == 'Offset in the central directory header':
            print(f"{k:40} : {hex(int(cd_h_of_file[k]))} | {cd_h_of_file[k]}")
        else:
            print(f"{k:40} : {cd_h_of_file[k]}")
    pretty_print_header("LOCAL HEADER")
    for k in local_header_of_file:
        print(f"{k:40} : {local_header_of_file[k]}")


def show_and_save_info_of_headers(entries, apk_name, header_type: str, export: bool, show: bool):
    """
    Print information for each entry for the central directory header and allow to possibly export to JSON.

    :param entries: The dictionary with all the entries for the central directory
    :type entries: dict
    :param apk_name: String with the name of the APK, so it can be used for the export.
    :type apk_name: str
    :param header_type: What type of header that is, either central_directory or local, to be used for the export
    :type header_type: str
    :param export: Boolean for exporting or not to JSON
    :type export: bool
    :param show: Boolean for printing or not the entries
    :type show: bool
    """
    if show:
        for entry in entries:
            pretty_print_header(entry)
            print(entries[entry])
    if export:
        save_to_json(f"{apk_name}_{header_type}_header.json", entries)
