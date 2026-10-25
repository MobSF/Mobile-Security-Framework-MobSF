# -*- coding: utf_8 -*-
# flake8: noqa
import zlib
import os

from mobsf.MobSF.exceptions import PathTraversalError, ZipBombError


# Keep this fallback in sync with MobSF.settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE.
DEFAULT_MAX_UNCOMPRESSED_SIZE = 400 * 1024 * 1024


def _max_uncompressed_size():
    """Get MobSF's ZIP member limit without requiring Django at import time."""
    try:
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        return settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE
    except (ImportError, ImproperlyConfigured):
        return DEFAULT_MAX_UNCOMPRESSED_SIZE


def _decompress_deflated(compressed_data, max_size):
    """Decompress a raw DEFLATE stream with a hard output ceiling."""
    decompressor = zlib.decompressobj(-15)
    extracted_data = decompressor.decompress(
        compressed_data,
        max_size + 1,
    )
    if len(extracted_data) > max_size or decompressor.unconsumed_tail:
        raise ZipBombError(
            'Decompressed ZIP member exceeds the configured size limit')
    if not decompressor.eof:
        raise zlib.error('Incomplete or truncated DEFLATE stream')
    return extracted_data


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

    max_uncompressed_size = _max_uncompressed_size()
    if uncompressed_size > max_uncompressed_size:
        raise ZipBombError(
            'ZIP member exceeds the configured size limit')

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
        extracted_data = _decompress_deflated(
            compressed_data,
            max_uncompressed_size,
        )
        indicator = 'DEFLATED'
    elif compressed_size == uncompressed_size:
        compressed_data = apk_file.read(uncompressed_size)
        extracted_data = compressed_data
        indicator = 'STORED_TAMPERED'
    else:
        cur_loc = apk_file.tell()
        try:
            compressed_data = apk_file.read(compressed_size)
            extracted_data = _decompress_deflated(
                compressed_data,
                max_uncompressed_size,
            )
            indicator = 'DEFLATED_TAMPERED'
        except zlib.error:
            apk_file.seek(cur_loc)
            compressed_data = apk_file.read(uncompressed_size)
            extracted_data = compressed_data
            indicator = 'STORED_TAMPERED'
    return extracted_data, indicator


def extract_all_files_from_central_directory(apk_file, central_directory_entries, local_header_entries, output_dir):
    """
    Extracts all files from an APK based on the entries detected in the central_directory_entries.

    :param apk_file: The APK file e.g. with open('test.apk', 'rb') as apk_file
    :type apk_file: bytesIO
    :param central_directory_entries: The dictionary with all the entries for the central directory
    :type central_directory_entries: dict
    :param local_header_entries: The dictionary with all the local header entries
    :type local_header_entries: dict
    :param output_dir: The output directory where to save the files.
    :type output_dir: str
    :return: Returns 0 if no errors, 1 if an exception and 2 if the output directory already exists
    :rtype: int
    """
    try:
        # Check if the output directory already exists
        if os.path.exists(output_dir):
            print("Extraction aborted. Output directory already exists.")
            return 2
        # Create the output directory or overwrite if it already exists
        os.makedirs(output_dir, exist_ok=True)
        # Iterate over central directory entries
        for filename, cd_header_info in central_directory_entries.items():
            if not filename:
                # to account for the cases where an empty filename entry is added
                continue
            # Extract the file using the local header information
            extracted_data = \
                extract_file_based_on_header_info(
                    apk_file, local_header_entries[filename], cd_header_info)[0]
            # Construct the output file path
            output_path = os.path.realpath(os.path.join(output_dir, filename))
            abs_output_dir = os.path.realpath(output_dir)
            common_path = os.path.commonpath((
                os.path.normcase(abs_output_dir),
                os.path.normcase(output_path),
            ))
            if common_path != os.path.normcase(abs_output_dir):
                raise PathTraversalError('Attempted Path Traversal in APK Zip Entry')
            # Create directories if necessary
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            # Write the extracted data to the output file
            with open(output_path, 'wb') as output_file:
                output_file.write(extracted_data)
        return 0
    except Exception as e:
        print(f"Error extracting files: {e}")
        return 1
