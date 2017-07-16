# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import stat
import unittest

import mock
from pyfakefs import fake_filesystem_unittest
from py_utils import cloud_storage

from dependency_manager import archive_info
from dependency_manager import cloud_storage_info
from dependency_manager import exceptions

class CloudStorageInfoTest(unittest.TestCase):
  def testInitCloudStorageInfoErrors(self):
    # Must specify cloud storage information atomically.
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      None, None, None, None)
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      'cs_bucket', None, None, None)
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      None, 'cs_hash', None, None)
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      None, None, 'download_path', None)
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      None, None, None, 'cs_remote_path')
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      None, 'cs_hash', 'download_path', 'cs_remote_path')
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      'cs_bucket', None, 'download_path', 'cs_remote_path')
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      'cs_bucket', 'cs_hash', None, 'cs_remote_path')
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      'cs_bucket', 'cs_hash', 'download_path', None)

  def testInitWithVersion(self):
    self.assertRaises(
        ValueError, cloud_storage_info.CloudStorageInfo, None, None, None,
        'cs_remote_path', version_in_cs='version_in_cs')
    self.assertRaises(
        ValueError, cloud_storage_info.CloudStorageInfo, None, 'cs_hash',
        'download_path', 'cs_remote_path', version_in_cs='version_in_cs')

    cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'download_path', 'cs_remote_path',
        version_in_cs='version_in_cs')
    self.assertEqual('cs_hash', cs_info._cs_hash)
    self.assertEqual('cs_bucket', cs_info._cs_bucket)
    self.assertEqual('cs_remote_path', cs_info._cs_remote_path)
    self.assertEqual('download_path', cs_info._download_path)
    self.assertEqual('version_in_cs', cs_info._version_in_cs)

  def testInitWithArchiveInfoErrors(self):
    zip_info = archive_info.ArchiveInfo(
        'download_path', 'unzip_location', 'path_within_archive')
    self.assertRaises(
        ValueError, cloud_storage_info.CloudStorageInfo, None, None, None, None,
        archive_info=zip_info)
    self.assertRaises(
        ValueError, cloud_storage_info.CloudStorageInfo, None, None, None,
        'cs_remote_path', archive_info=zip_info)
    self.assertRaises(
        ValueError, cloud_storage_info.CloudStorageInfo, 'cs_bucket', 'cs_hash',
        None, 'cs_remote_path', archive_info=zip_info)
    self.assertRaises(ValueError, cloud_storage_info.CloudStorageInfo,
                      'cs_bucket', 'cs_hash',
                      'cs_remote_path', None, version_in_cs='version',
                      archive_info=zip_info)


  def testInitWithArchiveInfo(self):
    zip_info = archive_info.ArchiveInfo(
        'download_path', 'unzip_location', 'path_within_archive')
    cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'download_path', 'cs_remote_path',
        archive_info=zip_info)
    self.assertEqual('cs_hash', cs_info._cs_hash)
    self.assertEqual('cs_bucket', cs_info._cs_bucket)
    self.assertEqual('cs_remote_path', cs_info._cs_remote_path)
    self.assertEqual('download_path', cs_info._download_path)
    self.assertEqual(zip_info, cs_info._archive_info)
    self.assertFalse(cs_info._version_in_cs)

  def testInitWithVersionAndArchiveInfo(self):
    zip_info = archive_info.ArchiveInfo(
        'download_path', 'unzip_location', 'path_within_archive')
    cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket', 'cs_hash', 'download_path',
        'cs_remote_path', version_in_cs='version_in_cs',
        archive_info=zip_info)
    self.assertEqual('cs_hash', cs_info._cs_hash)
    self.assertEqual('cs_bucket', cs_info._cs_bucket)
    self.assertEqual('cs_remote_path', cs_info._cs_remote_path)
    self.assertEqual('download_path', cs_info._download_path)
    self.assertEqual(zip_info, cs_info._archive_info)
    self.assertEqual('version_in_cs', cs_info._version_in_cs)

  def testInitMinimumCloudStorageInfo(self):
    cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket',
        'cs_hash', 'download_path',
        'cs_remote_path')
    self.assertEqual('cs_hash', cs_info._cs_hash)
    self.assertEqual('cs_bucket', cs_info._cs_bucket)
    self.assertEqual('cs_remote_path', cs_info._cs_remote_path)
    self.assertEqual('download_path', cs_info._download_path)
    self.assertFalse(cs_info._version_in_cs)
    self.assertFalse(cs_info._archive_info)


class TestGetRemotePath(fake_filesystem_unittest.TestCase):
  def setUp(self):
    self.setUpPyfakefs()
    self.config_path = '/test/dep_config.json'
    self.fs.CreateFile(self.config_path, contents='{}')
    self.download_path = '/foo/download_path'
    self.fs.CreateFile(
        self.download_path, contents='1010110', st_mode=stat.S_IWOTH)
    self.cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket', 'cs_hash', self.download_path, 'cs_remote_path',
        version_in_cs='1.2.3.4',)

  def tearDown(self):
    self.tearDownPyfakefs()

  @mock.patch(
      'py_utils.cloud_storage.GetIfHashChanged')
  def testGetRemotePathNoArchive(self, cs_get_mock):
    def _GetIfHashChangedMock(cs_path, download_path, bucket, file_hash):
      del cs_path, bucket, file_hash
      if not os.path.exists(download_path):
        self.fs.CreateFile(download_path, contents='1010001010101010110101')
    cs_get_mock.side_effect = _GetIfHashChangedMock
    # All of the needed information is given, and the downloaded path exists
    # after calling cloud storage.
    self.assertEqual(
        os.path.abspath(self.download_path),
        self.cs_info.GetRemotePath())
    self.assertTrue(os.stat(self.download_path).st_mode & stat.S_IXUSR)

    # All of the needed information is given, but the downloaded path doesn't
    # exists after calling cloud storage.
    self.fs.RemoveObject(self.download_path)
    cs_get_mock.side_effect = [True]
    self.assertRaises(
        exceptions.FileNotFoundError, self.cs_info.GetRemotePath)

  @mock.patch(
      'dependency_manager.dependency_manager_util.UnzipArchive')
  @mock.patch(
      'dependency_manager.cloud_storage_info.cloud_storage.GetIfHashChanged') # pylint: disable=line-too-long
  def testGetRemotePathWithArchive(self, cs_get_mock, unzip_mock):
    def _GetIfHashChangedMock(cs_path, download_path, bucket, file_hash):
      del cs_path, bucket, file_hash
      if not os.path.exists(download_path):
        self.fs.CreateFile(download_path, contents='1010001010101010110101')
    cs_get_mock.side_effect = _GetIfHashChangedMock

    unzip_path = os.path.join(
        os.path.dirname(self.download_path), 'unzip_dir')
    path_within_archive = os.path.join('path', 'within', 'archive')
    dep_path = os.path.join(unzip_path, path_within_archive)
    def _UnzipFileMock(archive_file, unzip_location, tmp_location=None):
      del archive_file, tmp_location
      self.fs.CreateFile(dep_path)
      self.fs.CreateFile(os.path.join(unzip_location, 'extra', 'path'))
      self.fs.CreateFile(os.path.join(unzip_location, 'another_extra_path'))
    unzip_mock.side_effect = _UnzipFileMock

    self.assertFalse(os.path.exists(dep_path))
    zip_info = archive_info.ArchiveInfo(
        self.download_path, unzip_path, path_within_archive)
    self.cs_info = cloud_storage_info.CloudStorageInfo(
        'cs_bucket', 'cs_hash', self.download_path, 'cs_remote_path',
        version_in_cs='1.2.3.4', archive_info=zip_info)

    self.assertFalse(unzip_mock.called)
    self.assertEqual(
        os.path.abspath(dep_path),
        self.cs_info.GetRemotePath())
    self.assertTrue(os.path.exists(dep_path))
    self.assertTrue(stat.S_IMODE(os.stat(os.path.abspath(dep_path)).st_mode) &
                    (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR))
    unzip_mock.assert_called_once_with(self.download_path, unzip_path)

    # Should not need to unzip a second time, but should return the same path.
    unzip_mock.reset_mock()
    self.assertTrue(os.path.exists(dep_path))
    self.assertEqual(
        os.path.abspath(dep_path),
        self.cs_info.GetRemotePath())
    self.assertTrue(stat.S_IMODE(os.stat(os.path.abspath(dep_path)).st_mode) &
                    (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR))
    self.assertFalse(unzip_mock.called)


  @mock.patch(
      'py_utils.cloud_storage.GetIfHashChanged')
  def testGetRemotePathCloudStorageErrors(self, cs_get_mock):
    cs_get_mock.side_effect = cloud_storage.CloudStorageError
    self.assertRaises(cloud_storage.CloudStorageError,
                      self.cs_info.GetRemotePath)

    cs_get_mock.side_effect = cloud_storage.ServerError
    self.assertRaises(cloud_storage.ServerError,
                      self.cs_info.GetRemotePath)

    cs_get_mock.side_effect = cloud_storage.NotFoundError
    self.assertRaises(cloud_storage.NotFoundError,
                      self.cs_info.GetRemotePath)

    cs_get_mock.side_effect = cloud_storage.PermissionError
    self.assertRaises(cloud_storage.PermissionError,
                      self.cs_info.GetRemotePath)

    cs_get_mock.side_effect = cloud_storage.CredentialsError
    self.assertRaises(cloud_storage.CredentialsError,
                      self.cs_info.GetRemotePath)
