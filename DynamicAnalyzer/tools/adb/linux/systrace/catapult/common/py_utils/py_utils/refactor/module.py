# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_utils.refactor import annotated_symbol


class Module(object):

  def __init__(self, file_path):
    self._file_path = file_path

    with open(self._file_path, 'r') as f:
      self._snippet = annotated_symbol.Annotate(f)

  @property
  def file_path(self):
    return self._file_path

  @property
  def modified(self):
    return self._snippet.modified

  def FindAll(self, snippet_type):
    return self._snippet.FindAll(snippet_type)

  def FindChildren(self, snippet_type):
    return self._snippet.FindChildren(snippet_type)

  def Write(self):
    """Write modifications to the file."""
    if not self.modified:
      return

    # Stringify before opening the file for writing.
    # If we fail, we won't truncate the file.
    string = str(self._snippet)
    with open(self._file_path, 'w') as f:
      f.write(string)
