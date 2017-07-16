# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import stat
import sys
import tempfile
import unittest
import uuid
import zipfile

import mock

from dependency_manager import dependency_manager_util
from dependency_manager import exceptions


class DependencyManagerUtilTest(unittest.TestCase):
  # This class intentionally uses actual file I/O to test real system behavior.

  def setUp(self):
    self.tmp_dir = os.path.abspath(tempfile.mkdtemp(prefix='telemetry'))
    self.sub_dir = os.path.join(self.tmp_dir, 'sub_dir')
    os.mkdir(self.sub_dir)

    self.read_only_path = (os.path.join(self.tmp_dir, 'read_only'))
    with open(self.read_only_path, 'w+') as read_file:
      read_file.write('Read-only file')
    os.chmod(self.read_only_path, stat.S_IRUSR)

    self.writable_path = (os.path.join(self.tmp_dir, 'writable'))
    with open(self.writable_path, 'w+') as writable_file:
      writable_file.write('Writable file')
    os.chmod(self.writable_path, stat.S_IRUSR | stat.S_IWUSR)

    self.executable_path = (os.path.join(self.tmp_dir, 'executable'))
    with open(self.executable_path, 'w+') as executable_file:
      executable_file.write('Executable file')
    os.chmod(self.executable_path, stat.S_IRWXU)

    self.sub_read_only_path = (os.path.join(self.sub_dir, 'read_only'))
    with open(self.sub_read_only_path, 'w+') as read_file:
      read_file.write('Read-only sub file')
    os.chmod(self.sub_read_only_path, stat.S_IRUSR)

    self.sub_writable_path = (os.path.join(self.sub_dir, 'writable'))
    with open(self.sub_writable_path, 'w+') as writable_file:
      writable_file.write('Writable sub file')
    os.chmod(self.sub_writable_path, stat.S_IRUSR | stat.S_IWUSR)

    self.sub_executable_path = (os.path.join(self.sub_dir, 'executable'))
    with open(self.sub_executable_path, 'w+') as executable_file:
      executable_file.write('Executable sub file')
    os.chmod(self.sub_executable_path, stat.S_IRWXU)

    self.AssertExpectedDirFiles(self.tmp_dir)
    self.archive_path = self.CreateZipArchiveFromDir(self.tmp_dir)

  def tearDown(self):
    if os.path.isdir(self.tmp_dir):
      dependency_manager_util.RemoveDir(self.tmp_dir)
    if os.path.isfile(self.archive_path):
      os.remove(self.archive_path)

  def AssertExpectedDirFiles(self, top_dir):
    sub_dir = os.path.join(top_dir, 'sub_dir')
    read_only_path = (os.path.join(top_dir, 'read_only'))
    writable_path = (os.path.join(top_dir, 'writable'))
    executable_path = (os.path.join(top_dir, 'executable'))
    sub_read_only_path = (os.path.join(sub_dir, 'read_only'))
    sub_writable_path = (os.path.join(sub_dir, 'writable'))
    sub_executable_path = (os.path.join(sub_dir, 'executable'))
    # assert contents as expected
    self.assertTrue(os.path.isdir(top_dir))
    self.assertTrue(os.path.isdir(sub_dir))
    self.assertTrue(os.path.isfile(read_only_path))
    self.assertTrue(os.path.isfile(writable_path))
    self.assertTrue(os.path.isfile(executable_path))
    self.assertTrue(os.path.isfile(sub_read_only_path))
    self.assertTrue(os.path.isfile(sub_writable_path))
    self.assertTrue(os.path.isfile(sub_executable_path))

    # assert permissions as expected
    self.assertTrue(
        stat.S_IRUSR & stat.S_IMODE(os.stat(read_only_path).st_mode))
    self.assertTrue(
        stat.S_IRUSR & stat.S_IMODE(os.stat(sub_read_only_path).st_mode))
    self.assertTrue(
        stat.S_IRUSR & stat.S_IMODE(os.stat(writable_path).st_mode))
    self.assertTrue(
        stat.S_IWUSR & stat.S_IMODE(os.stat(writable_path).st_mode))
    self.assertTrue(
        stat.S_IRUSR & stat.S_IMODE(os.stat(sub_writable_path).st_mode))
    self.assertTrue(
        stat.S_IWUSR & stat.S_IMODE(os.stat(sub_writable_path).st_mode))
    if not sys.platform.startswith('win'):
      self.assertEqual(
          stat.S_IRWXU,
          stat.S_IRWXU & stat.S_IMODE(os.stat(executable_path).st_mode))
      self.assertEqual(
          stat.S_IRWXU,
          stat.S_IRWXU & stat.S_IMODE(os.stat(sub_executable_path).st_mode))

  def CreateZipArchiveFromDir(self, dir_path):
    try:
      base_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
      archive_path = shutil.make_archive(base_path, 'zip', dir_path)
      self.assertTrue(os.path.exists(archive_path))
      self.assertTrue(zipfile.is_zipfile(archive_path))
    except:
      if os.path.isfile(archive_path):
        os.remove(archive_path)
      raise
    return archive_path

  def testRemoveDirWithSubDir(self):
    dependency_manager_util.RemoveDir(self.tmp_dir)

    self.assertFalse(os.path.exists(self.tmp_dir))
    self.assertFalse(os.path.exists(self.sub_dir))
    self.assertFalse(os.path.exists(self.read_only_path))
    self.assertFalse(os.path.exists(self.writable_path))
    self.assertFalse(os.path.isfile(self.executable_path))
    self.assertFalse(os.path.exists(self.sub_read_only_path))
    self.assertFalse(os.path.exists(self.sub_writable_path))
    self.assertFalse(os.path.isfile(self.sub_executable_path))

  def testUnzipFile(self):
    self.AssertExpectedDirFiles(self.tmp_dir)
    unzip_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    dependency_manager_util.UnzipArchive(self.archive_path, unzip_path)
    self.AssertExpectedDirFiles(unzip_path)
    self.AssertExpectedDirFiles(self.tmp_dir)
    dependency_manager_util.RemoveDir(unzip_path)

  def testUnzipFileContainingLongPath(self):
    try:
      dir_path = self.tmp_dir
      if sys.platform.startswith('win'):
        dir_path = u'\\\\?\\' + dir_path

      archive_suffix = ''
      # 260 is the Windows API path length limit.
      while len(archive_suffix) < 260:
        archive_suffix = os.path.join(archive_suffix, 'really')
      contents_dir_path = os.path.join(dir_path, archive_suffix)
      os.makedirs(contents_dir_path)
      filename = os.path.join(contents_dir_path, 'longpath.txt')
      open(filename, 'a').close()

      base_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
      archive_path = shutil.make_archive(base_path, 'zip', dir_path)
      self.assertTrue(os.path.exists(archive_path))
      self.assertTrue(zipfile.is_zipfile(archive_path))
    except:
      if os.path.isfile(archive_path):
        os.remove(archive_path)
      raise

    unzip_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    dependency_manager_util.UnzipArchive(archive_path, unzip_path)
    dependency_manager_util.RemoveDir(unzip_path)

  def testUnzipFileFailure(self):
    unzip_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    self.assertFalse(os.path.exists(unzip_path))
    with mock.patch(
        'dependency_manager.dependency_manager_util.zipfile.ZipFile.extractall'  # pylint: disable=line-too-long
        ) as zipfile_mock:
      zipfile_mock.side_effect = IOError
      self.assertRaises(
          IOError, dependency_manager_util.UnzipArchive, self.archive_path,
          unzip_path)
    self.AssertExpectedDirFiles(self.tmp_dir)
    self.assertFalse(os.path.exists(unzip_path))

  def testVerifySafeArchivePasses(self):
    with zipfile.ZipFile(self.archive_path) as archive:
      dependency_manager_util.VerifySafeArchive(archive)

  def testVerifySafeArchiveFailsOnRelativePathWithPardir(self):
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file_name = tmp_file.name
    tmp_file.write('Bad file!')
    tmp_file.close()
    with zipfile.ZipFile(self.archive_path, 'w') as archive:
      archive.write(tmp_file_name, '../../foo')
      self.assertRaises(
          exceptions.ArchiveError, dependency_manager_util.VerifySafeArchive,
          archive)

