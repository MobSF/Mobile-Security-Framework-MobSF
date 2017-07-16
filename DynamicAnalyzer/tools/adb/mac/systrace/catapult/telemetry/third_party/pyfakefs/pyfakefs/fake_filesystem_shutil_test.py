#! /usr/bin/env python
#
# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unittest for fake_filesystem_shutil."""

import stat
import time
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import fake_filesystem
import fake_filesystem_shutil


class FakeShutilModuleTest(unittest.TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.shutil = fake_filesystem_shutil.FakeShutilModule(self.filesystem)

  def testRmtree(self):
    directory = 'xyzzy'
    self.filesystem.CreateDirectory(directory)
    self.filesystem.CreateDirectory('%s/subdir' % directory)
    self.filesystem.CreateFile('%s/subfile' % directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.shutil.rmtree(directory)
    self.assertFalse(self.filesystem.Exists(directory))

  def testCopy(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_obj = self.filesystem.CreateFile(src_file)
    src_obj.st_mode = ((src_obj.st_mode & ~0o7777) | 0o750)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.copy(src_file, dst_file)
    self.assertTrue(self.filesystem.Exists(dst_file))
    dst_obj = self.filesystem.GetObject(dst_file)
    self.assertEqual(src_obj.st_mode, dst_obj.st_mode)

  def testCopyDirectory(self):
    src_file = 'xyzzy'
    parent_directory = 'parent'
    dst_file = '%s/%s' % (parent_directory, src_file)
    src_obj = self.filesystem.CreateFile(src_file)
    self.filesystem.CreateDirectory(parent_directory)
    src_obj.st_mode = ((src_obj.st_mode & ~0o7777) | 0o750)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(parent_directory))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.copy(src_file, parent_directory)
    self.assertTrue(self.filesystem.Exists(dst_file))
    dst_obj = self.filesystem.GetObject(dst_file)
    self.assertEqual(src_obj.st_mode, dst_obj.st_mode)

  def testCopystat(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_obj = self.filesystem.CreateFile(src_file)
    dst_obj = self.filesystem.CreateFile(dst_file)
    src_obj.st_mode = ((src_obj.st_mode & ~0o7777) | 0o750)
    src_obj.st_uid = 123
    src_obj.st_gid = 123
    src_obj.st_atime = time.time()
    src_obj.st_mtime = time.time()
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.shutil.copystat(src_file, dst_file)
    self.assertEqual(src_obj.st_mode, dst_obj.st_mode)
    self.assertEqual(src_obj.st_uid, dst_obj.st_uid)
    self.assertEqual(src_obj.st_gid, dst_obj.st_gid)
    self.assertEqual(src_obj.st_atime, dst_obj.st_atime)
    self.assertEqual(src_obj.st_mtime, dst_obj.st_mtime)

  def testCopy2(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_obj = self.filesystem.CreateFile(src_file)
    src_obj.st_mode = ((src_obj.st_mode & ~0o7777) | 0o750)
    src_obj.st_uid = 123
    src_obj.st_gid = 123
    src_obj.st_atime = time.time()
    src_obj.st_mtime = time.time()
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.copy2(src_file, dst_file)
    self.assertTrue(self.filesystem.Exists(dst_file))
    dst_obj = self.filesystem.GetObject(dst_file)
    self.assertEqual(src_obj.st_mode, dst_obj.st_mode)
    self.assertEqual(src_obj.st_uid, dst_obj.st_uid)
    self.assertEqual(src_obj.st_gid, dst_obj.st_gid)
    self.assertEqual(src_obj.st_atime, dst_obj.st_atime)
    self.assertEqual(src_obj.st_mtime, dst_obj.st_mtime)

  def testCopy2Directory(self):
    src_file = 'xyzzy'
    parent_directory = 'parent'
    dst_file = '%s/%s' % (parent_directory, src_file)
    src_obj = self.filesystem.CreateFile(src_file)
    self.filesystem.CreateDirectory(parent_directory)
    src_obj.st_mode = ((src_obj.st_mode & ~0o7777) | 0o750)
    src_obj.st_uid = 123
    src_obj.st_gid = 123
    src_obj.st_atime = time.time()
    src_obj.st_mtime = time.time()
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(parent_directory))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.copy2(src_file, parent_directory)
    self.assertTrue(self.filesystem.Exists(dst_file))
    dst_obj = self.filesystem.GetObject(dst_file)
    self.assertEqual(src_obj.st_mode, dst_obj.st_mode)
    self.assertEqual(src_obj.st_uid, dst_obj.st_uid)
    self.assertEqual(src_obj.st_gid, dst_obj.st_gid)
    self.assertEqual(src_obj.st_atime, dst_obj.st_atime)
    self.assertEqual(src_obj.st_mtime, dst_obj.st_mtime)

  def testCopytree(self):
    src_directory = 'xyzzy'
    dst_directory = 'xyzzy_copy'
    self.filesystem.CreateDirectory(src_directory)
    self.filesystem.CreateDirectory('%s/subdir' % src_directory)
    self.filesystem.CreateFile('%s/subfile' % src_directory)
    self.assertTrue(self.filesystem.Exists(src_directory))
    self.assertFalse(self.filesystem.Exists(dst_directory))
    self.shutil.copytree(src_directory, dst_directory)
    self.assertTrue(self.filesystem.Exists(dst_directory))
    self.assertTrue(self.filesystem.Exists('%s/subdir' % dst_directory))
    self.assertTrue(self.filesystem.Exists('%s/subfile' % dst_directory))

  def testCopytreeSrcIsFile(self):
    src_file = 'xyzzy'
    dst_directory = 'xyzzy_copy'
    self.filesystem.CreateFile(src_file)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_directory))
    self.assertRaises(OSError,
                      self.shutil.copytree,
                      src_file,
                      dst_directory)

  def testMoveFile(self):
    src_file = 'original_xyzzy'
    dst_file = 'moved_xyzzy'
    self.filesystem.CreateFile(src_file)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.move(src_file, dst_file)
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.assertFalse(self.filesystem.Exists(src_file))

  def testMoveFileIntoDirectory(self):
    src_file = 'xyzzy'
    dst_directory = 'directory'
    dst_file = '%s/%s' % (dst_directory, src_file)
    self.filesystem.CreateFile(src_file)
    self.filesystem.CreateDirectory(dst_directory)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.move(src_file, dst_directory)
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.assertFalse(self.filesystem.Exists(src_file))

  def testMoveDirectory(self):
    src_directory = 'original_xyzzy'
    dst_directory = 'moved_xyzzy'
    self.filesystem.CreateDirectory(src_directory)
    self.filesystem.CreateFile('%s/subfile' % src_directory)
    self.filesystem.CreateDirectory('%s/subdir' % src_directory)
    self.assertTrue(self.filesystem.Exists(src_directory))
    self.assertFalse(self.filesystem.Exists(dst_directory))
    self.shutil.move(src_directory, dst_directory)
    self.assertTrue(self.filesystem.Exists(dst_directory))
    self.assertTrue(self.filesystem.Exists('%s/subfile' % dst_directory))
    self.assertTrue(self.filesystem.Exists('%s/subdir' % dst_directory))
    self.assertFalse(self.filesystem.Exists(src_directory))


class CopyFileTest(unittest.TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.shutil = fake_filesystem_shutil.FakeShutilModule(self.filesystem)

  def testCommonCase(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    contents = 'contents of file'
    self.filesystem.CreateFile(src_file, contents=contents)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertFalse(self.filesystem.Exists(dst_file))
    self.shutil.copyfile(src_file, dst_file)
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.assertEqual(contents, self.filesystem.GetObject(dst_file).contents)

  def testRaisesIfSourceAndDestAreTheSameFile(self):
    src_file = 'xyzzy'
    dst_file = src_file
    contents = 'contents of file'
    self.filesystem.CreateFile(src_file, contents=contents)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertRaises(self.shutil.Error,
                      self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfDestIsASymlinkToSrc(self):
    src_file = '/tmp/foo'
    dst_file = '/tmp/bar'
    contents = 'contents of file'
    self.filesystem.CreateFile(src_file, contents=contents)
    self.filesystem.CreateLink(dst_file, src_file)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertRaises(self.shutil.Error,
                      self.shutil.copyfile, src_file, dst_file)

  def testSucceedsIfDestExistsAndIsWritable(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_contents = 'contents of source file'
    dst_contents = 'contents of dest file'
    self.filesystem.CreateFile(src_file, contents=src_contents)
    self.filesystem.CreateFile(dst_file, contents=dst_contents)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.shutil.copyfile(src_file, dst_file)
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.assertEqual(src_contents,
                     self.filesystem.GetObject(dst_file).contents)

  def testRaisesIfDestExistsAndIsNotWritable(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_contents = 'contents of source file'
    dst_contents = 'contents of dest file'
    self.filesystem.CreateFile(src_file, contents=src_contents)
    self.filesystem.CreateFile(dst_file,
                               st_mode=stat.S_IFREG | 0o400,
                               contents=dst_contents)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(dst_file))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfDestDirIsNotWritable(self):
    src_file = 'xyzzy'
    dst_dir = '/tmp/foo'
    dst_file = '%s/%s' % (dst_dir, src_file)
    src_contents = 'contents of source file'
    self.filesystem.CreateFile(src_file, contents=src_contents)
    self.filesystem.CreateDirectory(dst_dir, perm_bits=0o555)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(dst_dir))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfSrcDoesntExist(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    self.assertFalse(self.filesystem.Exists(src_file))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfSrcNotReadable(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    src_contents = 'contents of source file'
    self.filesystem.CreateFile(src_file,
                               st_mode=stat.S_IFREG | 0o000,
                               contents=src_contents)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfSrcIsADirectory(self):
    src_file = 'xyzzy'
    dst_file = 'xyzzy_copy'
    self.filesystem.CreateDirectory(src_file)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_file)

  def testRaisesIfDestIsADirectory(self):
    src_file = 'xyzzy'
    dst_dir = '/tmp/foo'
    src_contents = 'contents of source file'
    self.filesystem.CreateFile(src_file, contents=src_contents)
    self.filesystem.CreateDirectory(dst_dir)
    self.assertTrue(self.filesystem.Exists(src_file))
    self.assertTrue(self.filesystem.Exists(dst_dir))
    self.assertRaises(IOError, self.shutil.copyfile, src_file, dst_dir)


if __name__ == '__main__':
  unittest.main()
