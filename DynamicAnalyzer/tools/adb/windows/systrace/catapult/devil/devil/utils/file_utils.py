# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os


def MergeFiles(dest_file, source_files):
  """Merge list of files into single destination file.

  Args:
    dest_file: File to be written to.
    source_files: List of files to be merged. Will be merged in the order they
        appear in the list.
  """
  if not os.path.exists(os.path.dirname(dest_file)):
    os.makedirs(os.path.dirname(dest_file))
  try:
    with open(dest_file, 'w') as dest_f:
      for source_file in source_files:
        with open(source_file, 'r') as source_f:
          dest_f.write(source_f.read())
  except Exception as e:  # pylint: disable=broad-except
    # Something went wrong when creating dest_file. Cleaning up.
    try:
      os.remove(dest_file)
    except OSError:
      pass
    raise e


