# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import sys
import tempfile
import unittest

import mock
from pyfakefs import fake_filesystem_unittest

import py_utils
from py_utils import cloud_storage
from py_utils import lock

_CLOUD_STORAGE_GLOBAL_LOCK_PATH = os.path.join(
    os.path.dirname(__file__), 'cloud_storage_global_lock.py')

def _FakeReadHash(_):
  return 'hashthis!'


def _FakeCalulateHashMatchesRead(_):
  return 'hashthis!'


def _FakeCalulateHashNewHash(_):
  return 'omgnewhash'


class CloudStorageFakeFsUnitTest(fake_filesystem_unittest.TestCase):

  def setUp(self):
    self.original_environ = os.environ.copy()
    os.environ['DISABLE_CLOUD_STORAGE_IO'] = ''
    self.setUpPyfakefs()
    self.fs.CreateFile(
        os.path.join(py_utils.GetCatapultDir(),
                     'third_party', 'gsutil', 'gsutil'))

  def CreateFiles(self, file_paths):
    for f in file_paths:
      self.fs.CreateFile(f)

  def tearDown(self):
    self.tearDownPyfakefs()
    os.environ = self.original_environ

  def _FakeRunCommand(self, cmd):
    pass

  def _FakeGet(self, bucket, remote_path, local_path):
    pass

  def _AssertRunCommandRaisesError(self, communicate_strs, error):
    with mock.patch('py_utils.cloud_storage.subprocess.Popen') as popen:
      p_mock = mock.Mock()
      popen.return_value = p_mock
      p_mock.returncode = 1
      for stderr in communicate_strs:
        p_mock.communicate.return_value = ('', stderr)
        self.assertRaises(error, cloud_storage._RunCommand, [])

  def testRunCommandCredentialsError(self):
    strs = ['You are attempting to access protected data with no configured',
            'Failure: No handler was ready to authenticate.']
    self._AssertRunCommandRaisesError(strs, cloud_storage.CredentialsError)

  def testRunCommandPermissionError(self):
    strs = ['status=403', 'status 403', '403 Forbidden']
    self._AssertRunCommandRaisesError(strs, cloud_storage.PermissionError)

  def testRunCommandNotFoundError(self):
    strs = ['InvalidUriError', 'No such object', 'No URLs matched',
            'One or more URLs matched no', 'InvalidUriError']
    self._AssertRunCommandRaisesError(strs, cloud_storage.NotFoundError)

  def testRunCommandServerError(self):
    strs = ['500 Internal Server Error']
    self._AssertRunCommandRaisesError(strs, cloud_storage.ServerError)

  def testRunCommandGenericError(self):
    strs = ['Random string']
    self._AssertRunCommandRaisesError(strs, cloud_storage.CloudStorageError)

  def testInsertCreatesValidCloudUrl(self):
    orig_run_command = cloud_storage._RunCommand
    try:
      cloud_storage._RunCommand = self._FakeRunCommand
      remote_path = 'test-remote-path.html'
      local_path = 'test-local-path.html'
      cloud_url = cloud_storage.Insert(cloud_storage.PUBLIC_BUCKET,
                                       remote_path, local_path)
      self.assertEqual('https://console.developers.google.com/m/cloudstorage'
                       '/b/chromium-telemetry/o/test-remote-path.html',
                       cloud_url)
    finally:
      cloud_storage._RunCommand = orig_run_command

  @mock.patch('py_utils.cloud_storage.subprocess')
  def testExistsReturnsFalse(self, subprocess_mock):
    p_mock = mock.Mock()
    subprocess_mock.Popen.return_value = p_mock
    p_mock.communicate.return_value = (
        '',
        'CommandException: One or more URLs matched no objects.\n')
    p_mock.returncode_result = 1
    self.assertFalse(cloud_storage.Exists('fake bucket',
                                          'fake remote path'))

  @mock.patch('py_utils.cloud_storage.CalculateHash')
  @mock.patch('py_utils.cloud_storage._GetLocked')
  @mock.patch('py_utils.cloud_storage._FileLock')
  @mock.patch('py_utils.cloud_storage.os.path')
  def testGetIfHashChanged(self, path_mock, unused_lock_mock, get_mock,
                           calc_hash_mock):
    path_mock.exists.side_effect = [False, True, True]
    calc_hash_mock.return_value = 'hash'

    # The file at |local_path| doesn't exist. We should download file from cs.
    ret = cloud_storage.GetIfHashChanged(
        'remote_path', 'local_path', 'cs_bucket', 'hash')
    self.assertTrue(ret)
    get_mock.assert_called_once_with('cs_bucket', 'remote_path', 'local_path')
    get_mock.reset_mock()
    self.assertFalse(calc_hash_mock.call_args)
    calc_hash_mock.reset_mock()

    # A local file exists at |local_path| but has the wrong hash.
    # We should download file from cs.
    ret = cloud_storage.GetIfHashChanged(
        'remote_path', 'local_path', 'cs_bucket', 'new_hash')
    self.assertTrue(ret)
    get_mock.assert_called_once_with('cs_bucket', 'remote_path', 'local_path')
    get_mock.reset_mock()
    calc_hash_mock.assert_called_once_with('local_path')
    calc_hash_mock.reset_mock()

    # Downloaded file exists locally and has the right hash. Don't download.
    ret = cloud_storage.GetIfHashChanged(
        'remote_path', 'local_path', 'cs_bucket', 'hash')
    self.assertFalse(get_mock.call_args)
    self.assertFalse(ret)
    calc_hash_mock.reset_mock()
    get_mock.reset_mock()

  @mock.patch('py_utils.cloud_storage._FileLock')
  def testGetIfChanged(self, unused_lock_mock):
    orig_get = cloud_storage._GetLocked
    orig_read_hash = cloud_storage.ReadHash
    orig_calculate_hash = cloud_storage.CalculateHash
    cloud_storage.ReadHash = _FakeReadHash
    cloud_storage.CalculateHash = _FakeCalulateHashMatchesRead
    file_path = 'test-file-path.wpr'
    hash_path = file_path + '.sha1'
    try:
      cloud_storage._GetLocked = self._FakeGet
      # hash_path doesn't exist.
      self.assertFalse(cloud_storage.GetIfChanged(file_path,
                                                  cloud_storage.PUBLIC_BUCKET))
      # hash_path exists, but file_path doesn't.
      self.CreateFiles([hash_path])
      self.assertTrue(cloud_storage.GetIfChanged(file_path,
                                                 cloud_storage.PUBLIC_BUCKET))
      # hash_path and file_path exist, and have same hash.
      self.CreateFiles([file_path])
      self.assertFalse(cloud_storage.GetIfChanged(file_path,
                                                  cloud_storage.PUBLIC_BUCKET))
      # hash_path and file_path exist, and have different hashes.
      cloud_storage.CalculateHash = _FakeCalulateHashNewHash
      self.assertTrue(cloud_storage.GetIfChanged(file_path,
                                                 cloud_storage.PUBLIC_BUCKET))
    finally:
      cloud_storage._GetLocked = orig_get
      cloud_storage.CalculateHash = orig_calculate_hash
      cloud_storage.ReadHash = orig_read_hash

  @unittest.skipIf(sys.platform.startswith('win'),
                   'https://github.com/catapult-project/catapult/issues/1861')
  def testGetFilesInDirectoryIfChanged(self):
    self.CreateFiles([
        'real_dir_path/dir1/1file1.sha1',
        'real_dir_path/dir1/1file2.txt',
        'real_dir_path/dir1/1file3.sha1',
        'real_dir_path/dir2/2file.txt',
        'real_dir_path/dir3/3file1.sha1'])

    def IncrementFilesUpdated(*_):
      IncrementFilesUpdated.files_updated += 1
    IncrementFilesUpdated.files_updated = 0
    orig_get_if_changed = cloud_storage.GetIfChanged
    cloud_storage.GetIfChanged = IncrementFilesUpdated
    try:
      self.assertRaises(ValueError, cloud_storage.GetFilesInDirectoryIfChanged,
                        os.path.abspath(os.sep), cloud_storage.PUBLIC_BUCKET)
      self.assertEqual(0, IncrementFilesUpdated.files_updated)
      self.assertRaises(ValueError, cloud_storage.GetFilesInDirectoryIfChanged,
                        'fake_dir_path', cloud_storage.PUBLIC_BUCKET)
      self.assertEqual(0, IncrementFilesUpdated.files_updated)
      cloud_storage.GetFilesInDirectoryIfChanged('real_dir_path',
                                                 cloud_storage.PUBLIC_BUCKET)
      self.assertEqual(3, IncrementFilesUpdated.files_updated)
    finally:
      cloud_storage.GetIfChanged = orig_get_if_changed

  def testCopy(self):
    orig_run_command = cloud_storage._RunCommand

    def AssertCorrectRunCommandArgs(args):
      self.assertEqual(expected_args, args)
    cloud_storage._RunCommand = AssertCorrectRunCommandArgs
    expected_args = ['cp', 'gs://bucket1/remote_path1',
                     'gs://bucket2/remote_path2']
    try:
      cloud_storage.Copy('bucket1', 'bucket2', 'remote_path1', 'remote_path2')
    finally:
      cloud_storage._RunCommand = orig_run_command


  @mock.patch('py_utils.cloud_storage._FileLock')
  def testDisableCloudStorageIo(self, unused_lock_mock):
    os.environ['DISABLE_CLOUD_STORAGE_IO'] = '1'
    dir_path = 'real_dir_path'
    self.fs.CreateDirectory(dir_path)
    file_path = os.path.join(dir_path, 'file1')
    file_path_sha = file_path + '.sha1'
    self.CreateFiles([file_path, file_path_sha])
    with open(file_path_sha, 'w') as f:
      f.write('hash1234')
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.Copy('bucket1', 'bucket2', 'remote_path1', 'remote_path2')
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.Get('bucket', 'foo', file_path)
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.GetIfChanged(file_path, 'foo')
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.GetIfHashChanged('bar', file_path, 'bucket', 'hash1234')
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.Insert('bucket', 'foo', file_path)
    with self.assertRaises(cloud_storage.CloudStorageIODisabled):
      cloud_storage.GetFilesInDirectoryIfChanged(dir_path, 'bucket')


class CloudStorageRealFsUnitTest(unittest.TestCase):

  def setUp(self):
    self.original_environ = os.environ.copy()
    os.environ['DISABLE_CLOUD_STORAGE_IO'] = ''

  def tearDown(self):
    os.environ = self.original_environ

  @mock.patch('py_utils.cloud_storage.LOCK_ACQUISITION_TIMEOUT', .005)
  def testGetPseudoLockUnavailableCausesTimeout(self):
    with tempfile.NamedTemporaryFile(suffix='.pseudo_lock') as pseudo_lock_fd:
      with lock.FileLock(pseudo_lock_fd, lock.LOCK_EX | lock.LOCK_NB):
        with self.assertRaises(py_utils.TimeoutException):
          file_path = pseudo_lock_fd.name.replace('.pseudo_lock', '')
          cloud_storage.GetIfChanged(file_path, cloud_storage.PUBLIC_BUCKET)

  @mock.patch('py_utils.cloud_storage.LOCK_ACQUISITION_TIMEOUT', .005)
  def testGetGlobalLockUnavailableCausesTimeout(self):
    with open(_CLOUD_STORAGE_GLOBAL_LOCK_PATH) as global_lock_fd:
      with lock.FileLock(global_lock_fd, lock.LOCK_EX | lock.LOCK_NB):
        tmp_dir = tempfile.mkdtemp()
        try:
          file_path = os.path.join(tmp_dir, 'foo')
          with self.assertRaises(py_utils.TimeoutException):
            cloud_storage.GetIfChanged(file_path, cloud_storage.PUBLIC_BUCKET)
        finally:
          shutil.rmtree(tmp_dir)


class CloudStorageErrorHandlingTest(unittest.TestCase):
  def runTest(self):
    self.assertIsInstance(cloud_storage.GetErrorObjectForCloudStorageStderr(
        'ServiceException: 401 Anonymous users does not have '
        'storage.objects.get access to object chrome-partner-telemetry'),
                          cloud_storage.CredentialsError)
    self.assertIsInstance(cloud_storage.GetErrorObjectForCloudStorageStderr(
        '403 Caller does not have storage.objects.list access to bucket '
        'chrome-telemetry'), cloud_storage.PermissionError)
