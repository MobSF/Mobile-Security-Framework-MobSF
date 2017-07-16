# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from py_utils import cloud_storage


CloudStorageError = cloud_storage.CloudStorageError


class UnsupportedConfigFormatError(ValueError):
  def __init__(self, config_type, config_file):
    if not config_type:
      message = ('The json file at %s is unsupported by the dependency_manager '
                 'due to no specified config type' % config_file)
    else:
      message = ('The json file at %s has config type %s, which is unsupported '
                 'by the dependency manager.' % (config_file, config_type))
    super(UnsupportedConfigFormatError, self).__init__(message)


class EmptyConfigError(ValueError):
  def __init__(self, file_path):
    super(EmptyConfigError, self).__init__('Empty config at %s.' % file_path)


class FileNotFoundError(Exception):
  def __init__(self, file_path):
    super(FileNotFoundError, self).__init__('No file found at %s' % file_path)


class NoPathFoundError(Exception):
  def __init__(self, dependency, platform):
    super(NoPathFoundError, self).__init__(
        'No file could be found locally, and no file to download from cloud '
        'storage for %s on platform %s' % (dependency, platform))


class ReadWriteError(Exception):
  pass


class CloudStorageUploadConflictError(CloudStorageError):
  def __init__(self, bucket, path):
    super(CloudStorageUploadConflictError, self).__init__(
        'File location %s already exists in bucket %s' % (path, bucket))


class ArchiveError(Exception):
  def __init__(self, msg):
    super(ArchiveError, self).__init__(msg)

