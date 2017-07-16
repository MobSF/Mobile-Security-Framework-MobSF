#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Apply gzip/deflate to separate chunks of data."""

import struct
import zlib

GZIP_HEADER = (
    '\037\213'             # magic header
    '\010'                 # compression method
    '\000'                 # flags (none)
    '\000\000\000\000'     # packed time (use zero)
    '\002'
    '\377')


def compress_chunks(uncompressed_chunks, use_gzip):
  """Compress a list of data with gzip or deflate.

  The returned chunks may be used with HTTP chunked encoding.

  Args:
    uncompressed_chunks: a list of strings
       (e.g. ["this is the first chunk", "and the second"])
    use_gzip: if True, compress with gzip. Otherwise, use deflate.

  Returns:
    [compressed_chunk_1, compressed_chunk_2, ...]
  """
  if use_gzip:
    size = 0
    crc = zlib.crc32("") & 0xffffffffL
    compressor = zlib.compressobj(
        6, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
  else:
    compressor = zlib.compressobj()
  compressed_chunks = []
  last_index = len(uncompressed_chunks) - 1
  for index, data in enumerate(uncompressed_chunks):
    chunk = ''
    if use_gzip:
      size += len(data)
      crc = zlib.crc32(data, crc) & 0xffffffffL
      if index == 0:
        chunk += GZIP_HEADER
    chunk += compressor.compress(data)
    if index < last_index:
      chunk += compressor.flush(zlib.Z_SYNC_FLUSH)
    else:
      chunk += (compressor.flush(zlib.Z_FULL_FLUSH) +
                compressor.flush())
      if use_gzip:
        chunk += (struct.pack("<L", long(crc)) +
                  struct.pack("<L", long(size)))
    compressed_chunks.append(chunk)
  return compressed_chunks


def uncompress_chunks(compressed_chunks, use_gzip):
  """Uncompress a list of data compressed with gzip or deflate.

  Args:
    compressed_chunks: a list of compressed data
    use_gzip: if True, uncompress with gzip. Otherwise, use deflate.

  Returns:
    [uncompressed_chunk_1, uncompressed_chunk_2, ...]
  """
  if use_gzip:
    decompress = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress
  else:
    decompress = zlib.decompressobj(-zlib.MAX_WBITS).decompress
  return [decompress(c) for c in compressed_chunks]
