# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

PERF_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from telemetry.testing import system_stub
from telemetry.internal.testing import system_stub_test_module

class CloudStorageTest(unittest.TestCase):
  SUCCESS_FILE_HASH = 'success'.zfill(40)
  PUBLIC_FILE_HASH = 'public'.zfill(40)
  PARTNER_FILE_HASH = 'partner'.zfill(40)
  INTERNAL_FILE_HASH = 'internal'.zfill(40)
  UPDATED_HASH = 'updated'.zfill(40)

  def setUp(self):
    self.cloud_storage = system_stub.CloudStorageModuleStub()

    # Files in Cloud Storage.
    self.remote_files = ['preset_public_file.wpr',
                         'preset_partner_file.wpr',
                         'preset_internal_file.wpr']
    self.remote_paths = {
      self.cloud_storage.PUBLIC_BUCKET:
        {'preset_public_file.wpr':CloudStorageTest.PUBLIC_FILE_HASH},
      self.cloud_storage.PARTNER_BUCKET:
        {'preset_partner_file.wpr':CloudStorageTest.PARTNER_FILE_HASH},
      self.cloud_storage.INTERNAL_BUCKET:
        {'preset_internal_file.wpr':CloudStorageTest.INTERNAL_FILE_HASH}}

    # Local data files and hashes.
    self.data_files = [
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'),
        os.path.join(os.path.sep, 'path', 'to', 'wrong_hash.wpr'),
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr'),
        os.path.join(os.path.sep, 'path', 'to', 'preset_partner_file.wpr'),
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr')]
    self.local_file_hashes = {
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'):
            CloudStorageTest.SUCCESS_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'wrong_hash.wpr'):
            CloudStorageTest.SUCCESS_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr'):
            CloudStorageTest.PUBLIC_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'preset_partner_file.wpr'):
            CloudStorageTest.PARTNER_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr'):
            CloudStorageTest.INTERNAL_FILE_HASH,
    }
    self.cloud_storage.SetCalculatedHashesForTesting(self.local_file_hashes)
    # Local hash files and their contents.
    local_hash_files = {
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr.sha1'):
            CloudStorageTest.SUCCESS_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'wrong_hash.wpr.sha1'):
            'wronghash'.zfill(40),
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr.sha1'):
            CloudStorageTest.PUBLIC_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to', 'preset_partner_file.wpr.sha1'):
            CloudStorageTest.PARTNER_FILE_HASH,
        os.path.join(os.path.sep, 'path', 'to',
                     'preset_internal_file.wpr.sha1'):
            CloudStorageTest.INTERNAL_FILE_HASH,
    }
    self.cloud_storage.SetHashFileContentsForTesting(local_hash_files)

  def testSetup(self):
    self.assertEqual(self.local_file_hashes,
                     self.cloud_storage.local_file_hashes)
    self.assertEqual(set(self.data_files),
                     set(self.cloud_storage.GetLocalDataFiles()))
    self.assertEqual(self.cloud_storage.default_remote_paths,
                     self.cloud_storage.GetRemotePathsForTesting())
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertEqual(self.remote_paths,
                     self.cloud_storage.GetRemotePathsForTesting())

  def testExistsEmptyCloudStorage(self):
    # Test empty remote files dictionary.
    self.assertFalse(self.cloud_storage.Exists(self.cloud_storage.PUBLIC_BUCKET,
                                               'preset_public_file.wpr'))
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.PARTNER_BUCKET, 'preset_partner_file.wpr'))
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr'))

  def testExistsNonEmptyCloudStorage(self):
    # Test non-empty remote files dictionary.
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'preset_public_file.wpr'))
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.PARTNER_BUCKET, 'preset_partner_file.wpr'))
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr'))
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'fake_file'))
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.PARTNER_BUCKET, 'fake_file'))
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.INTERNAL_BUCKET, 'fake_file'))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testNonEmptyInsertAndExistsPublic(self):
    # Test non-empty remote files dictionary.
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertFalse(self.cloud_storage.Exists(self.cloud_storage.PUBLIC_BUCKET,
                                               'success.wpr'))
    self.cloud_storage.Insert(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr'))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testEmptyInsertAndExistsPublic(self):
    # Test empty remote files dictionary.
    self.assertFalse(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr'))
    self.cloud_storage.Insert(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr'))

  def testEmptyInsertAndGet(self):
    self.assertRaises(self.cloud_storage.NotFoundError, self.cloud_storage.Get,
                      self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
                      os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    self.cloud_storage.Insert(self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
                              os.path.join(os.path.sep, 'path', 'to',
                                           'success.wpr'))
    self.assertTrue(self.cloud_storage.Exists(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr'))
    self.assertEqual(CloudStorageTest.SUCCESS_FILE_HASH, self.cloud_storage.Get(
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr')))

  def testNonEmptyInsertAndGet(self):
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertRaises(self.cloud_storage.NotFoundError, self.cloud_storage.Get,
                      self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
                      os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    self.cloud_storage.Insert(self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
                              os.path.join(os.path.sep, 'path', 'to',
                                           'success.wpr'))
    self.assertTrue(self.cloud_storage.Exists(self.cloud_storage.PUBLIC_BUCKET,
                                              'success.wpr'))
    self.assertEqual(
        CloudStorageTest.SUCCESS_FILE_HASH, self.cloud_storage.Get(
            self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
            os.path.join(os.path.sep, 'path', 'to', 'success.wpr')))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testGetIfChanged(self):
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertRaises(
        self.cloud_storage.NotFoundError, self.cloud_storage.Get,
        self.cloud_storage.PUBLIC_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    self.assertFalse(self.cloud_storage.GetIfChanged(
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr'),
        self.cloud_storage.PUBLIC_BUCKET))
    self.cloud_storage.ChangeRemoteHashForTesting(
        self.cloud_storage.PUBLIC_BUCKET, 'preset_public_file.wpr',
        CloudStorageTest.UPDATED_HASH)
    self.assertTrue(self.cloud_storage.GetIfChanged(
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr'),
        self.cloud_storage.PUBLIC_BUCKET))
    self.assertFalse(self.cloud_storage.GetIfChanged(
        os.path.join(os.path.sep, 'path', 'to', 'preset_public_file.wpr'),
        self.cloud_storage.PUBLIC_BUCKET))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testList(self):
    self.assertEqual([],
                     self.cloud_storage.List(self.cloud_storage.PUBLIC_BUCKET))
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.assertEqual(['preset_public_file.wpr'],
                     self.cloud_storage.List(self.cloud_storage.PUBLIC_BUCKET))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testPermissionError(self):
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.cloud_storage.SetPermissionLevelForTesting(
        self.cloud_storage.PUBLIC_PERMISSION)
    self.assertRaises(
        self.cloud_storage.PermissionError, self.cloud_storage.Get,
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr'))
    self.assertRaises(
        self.cloud_storage.PermissionError, self.cloud_storage.GetIfChanged,
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr'),
        self.cloud_storage.INTERNAL_BUCKET)
    self.assertRaises(
        self.cloud_storage.PermissionError, self.cloud_storage.List,
        self.cloud_storage.INTERNAL_BUCKET)
    self.assertRaises(
        self.cloud_storage.PermissionError, self.cloud_storage.Exists,
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr')
    self.assertRaises(
        self.cloud_storage.PermissionError, self.cloud_storage.Insert,
        self.cloud_storage.INTERNAL_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testCredentialsError(self):
    self.cloud_storage.SetRemotePathsForTesting(self.remote_paths)
    self.cloud_storage.SetPermissionLevelForTesting(
        self.cloud_storage.CREDENTIALS_ERROR_PERMISSION)
    self.assertRaises(
        self.cloud_storage.CredentialsError, self.cloud_storage.Get,
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr'))
    self.assertRaises(
        self.cloud_storage.CredentialsError, self.cloud_storage.GetIfChanged,
        self.cloud_storage.INTERNAL_BUCKET,
        os.path.join(os.path.sep, 'path', 'to', 'preset_internal_file.wpr'))
    self.assertRaises(
        self.cloud_storage.CredentialsError, self.cloud_storage.List,
        self.cloud_storage.INTERNAL_BUCKET)
    self.assertRaises(
        self.cloud_storage.CredentialsError, self.cloud_storage.Exists,
        self.cloud_storage.INTERNAL_BUCKET, 'preset_internal_file.wpr')
    self.assertRaises(
        self.cloud_storage.CredentialsError, self.cloud_storage.Insert,
        self.cloud_storage.INTERNAL_BUCKET, 'success.wpr',
        os.path.join(os.path.sep, 'path', 'to', 'success.wpr'))
    # Reset state.
    self.cloud_storage.SetRemotePathsForTesting()

  def testOpenRestoresCorrectly(self):
    file_path = os.path.realpath(__file__)
    stubs = system_stub.Override(system_stub_test_module, ['open'])
    stubs.open.files = {file_path:'contents'}
    f = system_stub_test_module.SystemStubTest.TestOpen(file_path)
    self.assertEqual(type(f), system_stub.OpenFunctionStub.FileStub)
    stubs.open.files = {}
    stubs.Restore()
    # This will throw an error if the open stub wasn't restored correctly.
    f = system_stub_test_module.SystemStubTest.TestOpen(file_path)
    self.assertEqual(type(f), file)
