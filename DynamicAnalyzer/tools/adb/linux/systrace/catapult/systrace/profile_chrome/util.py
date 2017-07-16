# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import gzip
import os
import time
import zipfile


def ArchiveFiles(host_files, output):
  with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
    for host_file in host_files:
      z.write(host_file)
      os.unlink(host_file)

def CompressFile(host_file, output):
  with gzip.open(output, 'wb') as out, open(host_file, 'rb') as input_file:
    out.write(input_file.read())
  os.unlink(host_file)

def ArchiveData(trace_results, output):
  with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
    for result in trace_results:
      trace_file = result.source_name + GetTraceTimestamp()
      WriteDataToCompressedFile(result.raw_data, trace_file)
      z.write(trace_file)
      os.unlink(trace_file)

def WriteDataToCompressedFile(data, output):
  with gzip.open(output, 'wb') as out:
    out.write(data)

def GetTraceTimestamp():
  return time.strftime('%Y-%m-%d-%H%M%S', time.localtime())
