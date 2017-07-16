# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from dependency_manager import exceptions
from dependency_manager import dependency_manager_util


class ArchiveInfo(object):

  def __init__(self, archive_file, unzip_path, path_within_archive):
    """ Container for the information needed to unzip a downloaded archive.

    Args:
        archive_path: Path to the archive file.
        unzip_path: Path to unzip the archive into. Assumes that this path
            is unique for the archive.
        path_within_archive: Specify if and how to handle zip archives
            downloaded from cloud_storage. Expected values:
                None: Do not unzip the file downloaded from cloud_storage.
                '.': Unzip the file downloaded from cloud_storage. The
                    unzipped file/folder is the expected dependency.
                file_path: Unzip the file downloaded from cloud_storage.
                    |file_path| is the path to the expected dependency,
                    relative to the unzipped archive path.
    """
    self._archive_file = archive_file
    self._unzip_path = unzip_path
    self._path_within_archive = path_within_archive
    self._dependency_path = os.path.join(
        self._unzip_path, self._path_within_archive)
    if not self._has_minimum_data:
      raise ValueError(
          'Not enough information specified to initialize an archive info.'
          ' %s' % self)

  def GetUnzippedPath(self):
    if self.ShouldUnzipArchive():
      # TODO(aiolos): Replace UnzipFile with zipfile.extractall once python
      # version 2.7.4 or later can safely be assumed.
      dependency_manager_util.UnzipArchive(
          self._archive_file, self._unzip_path)
      if self.ShouldUnzipArchive():
        raise exceptions.ArchiveError(
            "Expected path '%s' was not extracted from archive '%s'." %
            (self._dependency_path, self._archive_file))
    return self._dependency_path

  def ShouldUnzipArchive(self):
    if not self._has_minimum_data:
      raise exceptions.ArchiveError(
          'Missing needed info to unzip archive. Known data: %s',
          self.data_string)
    return not os.path.exists(self._dependency_path)

  @property
  def _has_minimum_data(self):
    return all([self._archive_file, self._unzip_path,
                self._dependency_path])

  def __repr__(self):
    return (
        'ArchiveInfo(archive_file=%s, unzip_path=%s, path_within_archive=%s, '
        'dependency_path =%s)' % (
            self._archive_file, self._unzip_path, self._path_within_archive,
            self._dependency_path))

