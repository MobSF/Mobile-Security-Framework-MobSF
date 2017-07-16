# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os


_next_file_id = 0


class FileHandle(object):
  def __init__(self, temp_file=None, absolute_path=None):
    """Constructs a FileHandle object.

    This constructor should not be used by the user; rather it is preferred to
    use the module-level GetAbsPath and FromTempFile functions.

    Args:
      temp_file: An instance of a temporary file object.
      absolute_path: A path; should not be passed if tempfile is and vice-versa.
      extension: A string that specifies the file extension. It must starts with
        ".".
    """
    # Exactly one of absolute_path or temp_file must be specified.
    assert (absolute_path is None) != (temp_file is None)
    self._temp_file = temp_file
    self._absolute_path = absolute_path

    global _next_file_id
    self._id = _next_file_id
    _next_file_id += 1

  @property
  def id(self):
    return self._id

  @property
  def extension(self):
    return os.path.splitext(self.GetAbsPath())[1]

  def GetAbsPath(self):
    """Returns the path to the pointed-to file relative to the given start path.

    Args:
      start: A string representing a starting path.
    Returns:
      A string giving the relative path from path to this file.
    """
    if self._temp_file:
      self._temp_file.close()
      return self._temp_file.name
    else:
      return self._absolute_path


def FromTempFile(temp_file):
  """Constructs a FileHandle pointing to a temporary file.

  Returns:
    A FileHandle referring to a named temporary file.
  """
  return FileHandle(temp_file)


def FromFilePath(path):
  """Constructs a FileHandle from an absolute file path.

  Args:
    path: A string giving the absolute path to a file.
  Returns:
    A FileHandle referring to the file at the specified path.
  """
  return FileHandle(None, os.path.abspath(path))
