# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os

from py_utils import cloud_storage

from dependency_manager import exceptions


BACKUP_PATH_EXTENSION = 'old'


class CloudStorageUploader(object):
  def __init__(self, bucket, remote_path, local_path, cs_backup_path=None):
    if not bucket or not remote_path or not local_path:
      raise ValueError(
          'Attempted to partially initialize upload data with bucket %s, '
          'remote_path %s, and local_path %s', bucket, remote_path, local_path)
    if not os.path.exists(local_path):
      raise ValueError('Attempting to initilize UploadInfo with missing '
                       'local path %s', local_path)

    self._cs_bucket = bucket
    self._cs_remote_path = remote_path
    self._local_path = local_path
    self._cs_backup_path = (cs_backup_path or
                            '%s.%s' % (self._cs_remote_path,
                                       BACKUP_PATH_EXTENSION))
    self._updated = False
    self._backed_up = False

  def Upload(self, force=False):
    """Upload all pending files and then write the updated config to disk.

    Will attempt to copy files existing in the upload location to a backup
    location in the same bucket in cloud storage if |force| is True.

    Args:
      force: True if files should be uploaded to cloud storage even if a
          file already exists in the upload location.

    Raises:
      CloudStorageUploadConflictError: If |force| is False and the potential
          upload location of a file already exists.
      CloudStorageError: If copying an existing file to the backup location
          or uploading the new file fails.
    """
    if cloud_storage.Exists(self._cs_bucket, self._cs_remote_path):
      if not force:
        #pylint: disable=nonstandard-exception
        raise exceptions.CloudStorageUploadConflictError(self._cs_bucket,
                                                         self._cs_remote_path)
        #pylint: enable=nonstandard-exception
      logging.debug('A file already exists at upload path %s in self.cs_bucket'
                    ' %s', self._cs_remote_path, self._cs_bucket)
      try:
        cloud_storage.Copy(self._cs_bucket, self._cs_bucket,
                           self._cs_remote_path, self._cs_backup_path)
        self._backed_up = True
      except cloud_storage.CloudStorageError:
        logging.error('Failed to copy existing file %s in cloud storage bucket '
                      '%s to backup location %s', self._cs_remote_path,
                      self._cs_bucket, self._cs_backup_path)
        raise

    try:
      cloud_storage.Insert(
          self._cs_bucket, self._cs_remote_path, self._local_path)
    except cloud_storage.CloudStorageError:
      logging.error('Failed to upload %s to %s in cloud_storage bucket %s',
                    self._local_path, self._cs_remote_path, self._cs_bucket)
      raise
    self._updated = True

  def Rollback(self):
    """Attempt to undo the previous call to Upload.

    Does nothing if no previous call to Upload was made, or if nothing was
    successfully changed.

    Returns:
      True iff changes were successfully rolled back.
    Raises:
      CloudStorageError: If copying the backed up file to its original
          location or removing the uploaded file fails.
    """
    cloud_storage_changed = False
    if self._backed_up:
      cloud_storage.Copy(self._cs_bucket, self._cs_bucket, self._cs_backup_path,
                         self._cs_remote_path)
      cloud_storage_changed = True
      self._cs_backup_path = None
    elif self._updated:
      cloud_storage.Delete(self._cs_bucket, self._cs_remote_path)
      cloud_storage_changed = True
    self._updated = False
    return cloud_storage_changed

  def __eq__(self, other, msg=None):
    if type(self) != type(other):
      return False
    return (self._local_path == other._local_path and
            self._cs_remote_path == other._cs_remote_path and
            self._cs_bucket == other._cs_bucket)

