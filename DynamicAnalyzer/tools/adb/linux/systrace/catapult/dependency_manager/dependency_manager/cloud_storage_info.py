# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno
import os
import stat

from py_utils import cloud_storage

from dependency_manager import exceptions

class CloudStorageInfo(object):
  def __init__(self, cs_bucket, cs_hash, download_path, cs_remote_path,
               version_in_cs=None, archive_info=None):
    """ Container for the information needed to download a dependency from
        cloud storage.

    Args:
          cs_bucket: The cloud storage bucket the dependency is located in.
          cs_hash: The hash of the file stored in cloud storage.
          download_path: Where the file should be downloaded to.
          cs_remote_path: Where the file is stored in the cloud storage bucket.
          version_in_cs: The version of the file stored in cloud storage.
          archive_info: An instance of ArchiveInfo if this dependency is an
              archive. Else None.
    """
    self._download_path = download_path
    self._cs_remote_path = cs_remote_path
    self._cs_bucket = cs_bucket
    self._cs_hash = cs_hash
    self._version_in_cs = version_in_cs
    self._archive_info = archive_info
    if not self._has_minimum_data:
      raise ValueError(
          'Not enough information specified to initialize a cloud storage info.'
          ' %s' % self)

  def DependencyExistsInCloudStorage(self):
    return cloud_storage.Exists(self._cs_bucket, self._cs_remote_path)

  def GetRemotePath(self):
    """Gets the path to a downloaded version of the dependency.

    May not download the file if it has already been downloaded.
    Will unzip the downloaded file if a non-empty archive_info was passed in at
    init.

    Returns: A path to an executable that was stored in cloud_storage, or None
       if not found.

    Raises:
        CredentialsError: If cloud_storage credentials aren't configured.
        PermissionError: If cloud_storage credentials are configured, but not
            with an account that has permission to download the needed file.
        NotFoundError: If the needed file does not exist where expected in
            cloud_storage or the downloaded zip file.
        ServerError: If an internal server error is hit while downloading the
            needed file.
        CloudStorageError: If another error occured while downloading the remote
            path.
        FileNotFoundError: If the download was otherwise unsuccessful.
    """
    if not self._has_minimum_data:
      return None

    download_dir = os.path.dirname(self._download_path)
    if not os.path.exists(download_dir):
      try:
        os.makedirs(download_dir)
      except OSError as e:
        # The logic above is racy, and os.makedirs will raise an OSError if
        # the directory exists.
        if e.errno != errno.EEXIST:
          raise

    dependency_path = self._download_path
    cloud_storage.GetIfHashChanged(
        self._cs_remote_path, self._download_path, self._cs_bucket,
        self._cs_hash)
    if not os.path.exists(dependency_path):
      raise exceptions.FileNotFoundError(dependency_path)

    if self.has_archive_info:
      dependency_path = self._archive_info.GetUnzippedPath()
    else:
      mode = os.stat(dependency_path).st_mode
      os.chmod(dependency_path, mode | stat.S_IXUSR)
    return os.path.abspath(dependency_path)

  @property
  def version_in_cs(self):
    return self._version_in_cs

  @property
  def _has_minimum_data(self):
    return all([self._cs_bucket, self._cs_remote_path, self._download_path,
                self._cs_hash])


  @property
  def has_archive_info(self):
    return bool(self._archive_info)

  def __repr__(self):
    return (
        'CloudStorageInfo(download_path=%s, cs_remote_path=%s, cs_bucket=%s, '
        'cs_hash=%s, version_in_cs=%s, archive_info=%s)' % (
            self._download_path, self._cs_remote_path, self._cs_bucket,
            self._cs_hash, self._version_in_cs, self._archive_info))
