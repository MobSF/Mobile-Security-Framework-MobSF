# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from pyfakefs import fake_filesystem_unittest

from dependency_manager import uploader


class CloudStorageUploaderTest(fake_filesystem_unittest.TestCase):
  def setUp(self):
    self.setUpPyfakefs()
    self.bucket = 'cloud_storage_bucket'
    self.local_path = os.path.abspath(os.path.join('path', 'to', 'dependency'))
    self.fs.CreateFile(self.local_path)
    self.remote_path = 'config_folder/remote_path'

  def testCloudStorageUploaderMissingData(self):
    self.assertRaises(ValueError, uploader.CloudStorageUploader,
                      None, self.remote_path, self.local_path)
    self.assertRaises(ValueError, uploader.CloudStorageUploader,
                      self.bucket, None, self.local_path)
    self.assertRaises(ValueError, uploader.CloudStorageUploader,
                      self.bucket, self.remote_path, None)

  def testCloudStorageUploaderLocalFileMissing(self):
    self.fs.RemoveObject(self.local_path)
    self.assertRaises(ValueError, uploader.CloudStorageUploader,
                      self.bucket, self.remote_path, self.local_path)

  def testCloudStorageUploaderCreation(self):
    upload_data = uploader.CloudStorageUploader(
        self.bucket, self.remote_path, self.local_path)
    expected_bucket = self.bucket
    expected_remote_path = self.remote_path
    expected_cs_backup_path = '%s.old' % expected_remote_path
    expected_local_path = self.local_path
    self.assertEqual(expected_bucket, upload_data._cs_bucket)
    self.assertEqual(expected_remote_path, upload_data._cs_remote_path)
    self.assertEqual(expected_local_path, upload_data._local_path)
    self.assertEqual(expected_cs_backup_path, upload_data._cs_backup_path)

  def testCloudStorageUploaderEquality(self):
    upload_data = uploader.CloudStorageUploader(
        self.bucket, self.remote_path, self.local_path)
    upload_data_exact = uploader.CloudStorageUploader(
        self.bucket, self.remote_path, self.local_path)
    upload_data_equal = uploader.CloudStorageUploader(
        'cloud_storage_bucket',
        'config_folder/remote_path',
        os.path.abspath(os.path.join('path', 'to', 'dependency')))
    self.assertEqual(upload_data, upload_data)
    self.assertEqual(upload_data, upload_data_exact)
    self.assertEqual(upload_data_exact, upload_data)
    self.assertEqual(upload_data, upload_data_equal)
    self.assertEqual(upload_data_equal, upload_data)


  def testCloudStorageUploaderInequality(self):
    new_local_path = os.path.abspath(os.path.join('new', 'local', 'path'))
    self.fs.CreateFile(new_local_path)
    new_bucket = 'new_bucket'
    new_remote_path = 'new_remote/path'

    upload_data = uploader.CloudStorageUploader(
        self.bucket, self.remote_path, self.local_path)
    upload_data_all_different = uploader.CloudStorageUploader(
        new_bucket, new_remote_path, new_local_path)
    upload_data_different_bucket = uploader.CloudStorageUploader(
        new_bucket, self.remote_path, self.local_path)
    upload_data_different_remote_path = uploader.CloudStorageUploader(
        self.bucket, new_remote_path, self.local_path)
    upload_data_different_local_path = uploader.CloudStorageUploader(
        self.bucket, self.remote_path, new_local_path)

    self.assertNotEqual(upload_data, 'a string!')
    self.assertNotEqual(upload_data, 0)
    self.assertNotEqual(upload_data, 2354)
    self.assertNotEqual(upload_data, None)
    self.assertNotEqual(upload_data, upload_data_all_different)
    self.assertNotEqual(upload_data_all_different, upload_data)
    self.assertNotEqual(upload_data, upload_data_different_bucket)
    self.assertNotEqual(upload_data_different_bucket, upload_data)
    self.assertNotEqual(upload_data, upload_data_different_remote_path)
    self.assertNotEqual(upload_data_different_remote_path, upload_data)
    self.assertNotEqual(upload_data, upload_data_different_local_path)
    self.assertNotEqual(upload_data_different_local_path, upload_data)

  #TODO: write unittests for upload and rollback
