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

"""Unittest for fake_filesystem module."""

import errno
import os
import re
import stat
import sys
import time
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import fake_filesystem


def _GetDummyTime(start_time, increment):
  def _DummyTime():
    _DummyTime._curr_time += increment
    return _DummyTime._curr_time
  _DummyTime._curr_time = start_time - increment  # pylint: disable-msg=W0612
  return _DummyTime


class TestCase(unittest.TestCase):
  is_windows = sys.platform.startswith('win')
  is_cygwin = sys.platform == 'cygwin'

  def assertModeEqual(self, expected, actual):
    return self.assertEqual(stat.S_IMODE(expected), stat.S_IMODE(actual))


class FakeDirectoryUnitTest(TestCase):
  def setUp(self):
    self.orig_time = time.time
    time.time = _GetDummyTime(10, 1)
    self.fake_file = fake_filesystem.FakeFile('foobar', contents='dummy_file')
    self.fake_dir = fake_filesystem.FakeDirectory('somedir')

  def tearDown(self):
    time.time = self.orig_time

  def testNewFileAndDirectory(self):
    self.assertTrue(stat.S_IFREG & self.fake_file.st_mode)
    self.assertTrue(stat.S_IFDIR & self.fake_dir.st_mode)
    self.assertEqual({}, self.fake_dir.contents)
    self.assertEqual(10, self.fake_file.st_ctime)

  def testAddEntry(self):
    self.fake_dir.AddEntry(self.fake_file)
    self.assertEqual({'foobar': self.fake_file}, self.fake_dir.contents)

  def testGetEntry(self):
    self.fake_dir.AddEntry(self.fake_file)
    self.assertEqual(self.fake_file, self.fake_dir.GetEntry('foobar'))

  def testRemoveEntry(self):
    self.fake_dir.AddEntry(self.fake_file)
    self.assertEqual(self.fake_file, self.fake_dir.GetEntry('foobar'))
    self.fake_dir.RemoveEntry('foobar')
    self.assertRaises(KeyError, self.fake_dir.GetEntry, 'foobar')

  def testShouldThrowIfSetSizeIsNotInteger(self):
    self.assertRaises(IOError, self.fake_file.SetSize, 0.1)

  def testShouldThrowIfSetSizeIsNegative(self):
    self.assertRaises(IOError, self.fake_file.SetSize, -1)

  def testProduceEmptyFileIfSetSizeIsZero(self):
    self.fake_file.SetSize(0)
    self.assertEqual('', self.fake_file.contents)

  def testSetsContentEmptyIfSetSizeIsZero(self):
    self.fake_file.SetSize(0)
    self.assertEqual('', self.fake_file.contents)

  def testTruncateFileIfSizeIsSmallerThanCurrentSize(self):
    self.fake_file.SetSize(6)
    self.assertEqual('dummy_', self.fake_file.contents)

  def testLeaveFileUnchangedIfSizeIsEqualToCurrentSize(self):
    self.fake_file.SetSize(10)
    self.assertEqual('dummy_file', self.fake_file.contents)

  def testPadsFileContentWithNullBytesIfSizeIsGreaterThanCurrentSize(self):
    self.fake_file.SetSize(13)
    self.assertEqual('dummy_file\0\0\0', self.fake_file.contents)

  def testSetMTime(self):
    self.assertEqual(10, self.fake_file.st_mtime)
    self.fake_file.SetMTime(13)
    self.assertEqual(13, self.fake_file.st_mtime)
    self.fake_file.SetMTime(131)
    self.assertEqual(131, self.fake_file.st_mtime)

  def testFileInode(self):
    filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    fake_os = fake_filesystem.FakeOsModule(filesystem)
    file_path = 'some_file1'
    filesystem.CreateFile(file_path, contents='contents here1', inode=42)
    self.assertEqual(42, fake_os.stat(file_path)[stat.ST_INO])

    file_obj = filesystem.GetObject(file_path)
    file_obj.SetIno(43)
    self.assertEqual(43, fake_os.stat(file_path)[stat.ST_INO])

  def testDirectoryInode(self):
    filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    fake_os = fake_filesystem.FakeOsModule(filesystem)
    dirpath = 'testdir'
    filesystem.CreateDirectory(dirpath, inode=42)
    self.assertEqual(42, fake_os.stat(dirpath)[stat.ST_INO])

    dir_obj = filesystem.GetObject(dirpath)
    dir_obj.SetIno(43)
    self.assertEqual(43, fake_os.stat(dirpath)[stat.ST_INO])


class SetLargeFileSizeTest(FakeDirectoryUnitTest):

  def testShouldThrowIfSizeIsNotInteger(self):
    self.assertRaises(IOError, self.fake_file.SetLargeFileSize, 0.1)

  def testShouldThrowIfSizeIsNegative(self):
    self.assertRaises(IOError, self.fake_file.SetLargeFileSize, -1)

  def testSetsContentNoneIfSizeIsNonNegativeInteger(self):
    self.fake_file.SetLargeFileSize(1000000000)
    self.assertEqual(None, self.fake_file.contents)
    self.assertEqual(1000000000, self.fake_file.st_size)


class NormalizePathTest(TestCase):
  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.root_name = '/'

  def testEmptyPathShouldGetNormalizedToRootPath(self):
    self.assertEqual(self.root_name, self.filesystem.NormalizePath(''))

  def testRootPathRemainsUnchanged(self):
    self.assertEqual(self.root_name,
                     self.filesystem.NormalizePath(self.root_name))

  def testRelativePathForcedToCwd(self):
    path = 'bar'
    self.filesystem.cwd = '/foo'
    self.assertEqual('/foo/bar', self.filesystem.NormalizePath(path))

  def testAbsolutePathRemainsUnchanged(self):
    path = '/foo/bar'
    self.assertEqual(path, self.filesystem.NormalizePath(path))

  def testDottedPathIsNormalized(self):
    path = '/foo/..'
    self.assertEqual('/', self.filesystem.NormalizePath(path))
    path = 'foo/../bar'
    self.assertEqual('/bar', self.filesystem.NormalizePath(path))

  def testDotPathIsNormalized(self):
    path = '.'
    self.assertEqual('/', self.filesystem.NormalizePath(path))


class GetPathComponentsTest(TestCase):
  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.root_name = '/'

  def testRootPathShouldReturnEmptyList(self):
    self.assertEqual([], self.filesystem.GetPathComponents(self.root_name))

  def testEmptyPathShouldReturnEmptyList(self):
    self.assertEqual([], self.filesystem.GetPathComponents(''))

  def testRelativePathWithOneComponentShouldReturnComponent(self):
    self.assertEqual(['foo'], self.filesystem.GetPathComponents('foo'))

  def testAbsolutePathWithOneComponentShouldReturnComponent(self):
    self.assertEqual(['foo'], self.filesystem.GetPathComponents('/foo'))

  def testTwoLevelRelativePathShouldReturnComponents(self):
    self.assertEqual(['foo', 'bar'],
                     self.filesystem.GetPathComponents('foo/bar'))

  def testTwoLevelAbsolutePathShouldReturnComponents(self):
    self.assertEqual(['foo', 'bar'],
                     self.filesystem.GetPathComponents('/foo/bar'))


class FakeFilesystemUnitTest(TestCase):
  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.root_name = '/'
    self.fake_file = fake_filesystem.FakeFile('foobar')
    self.fake_child = fake_filesystem.FakeDirectory('foobaz')
    self.fake_grandchild = fake_filesystem.FakeDirectory('quux')

  def testNewFilesystem(self):
    self.assertEqual('/', self.filesystem.path_separator)
    self.assertTrue(stat.S_IFDIR & self.filesystem.root.st_mode)
    self.assertEqual(self.root_name, self.filesystem.root.name)
    self.assertEqual({}, self.filesystem.root.contents)

  def testNoneRaisesTypeError(self):
    self.assertRaises(TypeError, self.filesystem.Exists, None)

  def testEmptyStringDoesNotExist(self):
    self.assertFalse(self.filesystem.Exists(''))

  def testExistsRoot(self):
    self.assertTrue(self.filesystem.Exists(self.root_name))

  def testExistsUnaddedFile(self):
    self.assertFalse(self.filesystem.Exists(self.fake_file.name))

  def testGetRootObject(self):
    self.assertEqual(self.filesystem.root,
                     self.filesystem.GetObject(self.root_name))

  def testAddObjectToRoot(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertEqual({'foobar': self.fake_file}, self.filesystem.root.contents)

  def testExistsAddedFile(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertTrue(self.filesystem.Exists(self.fake_file.name))

  def testExistsRelativePath(self):
    self.filesystem.CreateFile('/a/b/file_one')
    self.filesystem.CreateFile('/a/c/file_two')
    self.assertTrue(self.filesystem.Exists('a/b/../c/file_two'))
    self.assertTrue(self.filesystem.Exists('/a/c/../b/file_one'))
    self.assertTrue(self.filesystem.Exists('/a/c/../../a/b/file_one'))
    self.assertFalse(self.filesystem.Exists('a/b/../z/d'))
    self.assertFalse(self.filesystem.Exists('a/b/../z/../c/file_two'))
    self.filesystem.cwd = '/a/c'
    self.assertTrue(self.filesystem.Exists('../b/file_one'))
    self.assertTrue(self.filesystem.Exists('../../a/b/file_one'))
    self.assertTrue(self.filesystem.Exists('../../a/b/../../a/c/file_two'))
    self.assertFalse(self.filesystem.Exists('../z/file_one'))
    self.assertFalse(self.filesystem.Exists('../z/../c/file_two'))

  def testGetObjectFromRoot(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertEqual(self.fake_file, self.filesystem.GetObject('foobar'))

  def testGetNonexistentObjectFromRootError(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertEqual(self.fake_file, self.filesystem.GetObject('foobar'))
    self.assertRaises(IOError, self.filesystem.GetObject,
                      'some_bogus_filename')

  def testRemoveObjectFromRoot(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.filesystem.RemoveObject(self.fake_file.name)
    self.assertRaises(IOError, self.filesystem.GetObject, self.fake_file.name)

  def testRemoveNonexistenObjectFromRootError(self):
    self.assertRaises(IOError, self.filesystem.RemoveObject,
                      'some_bogus_filename')

  def testExistsRemovedFile(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.filesystem.RemoveObject(self.fake_file.name)
    self.assertFalse(self.filesystem.Exists(self.fake_file.name))

  def testAddObjectToChild(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    self.assertEqual(
        {self.fake_file.name: self.fake_file},
        self.filesystem.root.GetEntry(self.fake_child.name).contents)

  def testAddObjectToRegularFileError(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertRaises(IOError, self.filesystem.AddObject,
                      self.fake_file.name, self.fake_file)

  def testExistsFileAddedToChild(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    path = self.filesystem.JoinPaths(self.fake_child.name,
                                     self.fake_file.name)
    self.assertTrue(self.filesystem.Exists(path))

  def testGetObjectFromChild(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    self.assertEqual(self.fake_file,
                     self.filesystem.GetObject(
                         self.filesystem.JoinPaths(self.fake_child.name,
                                                   self.fake_file.name)))

  def testGetNonexistentObjectFromChildError(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    self.assertRaises(IOError, self.filesystem.GetObject,
                      self.filesystem.JoinPaths(self.fake_child.name,
                                                'some_bogus_filename'))

  def testRemoveObjectFromChild(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    target_path = self.filesystem.JoinPaths(self.fake_child.name,
                                            self.fake_file.name)
    self.filesystem.RemoveObject(target_path)
    self.assertRaises(IOError, self.filesystem.GetObject, target_path)

  def testRemoveObjectFromChildError(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.assertRaises(IOError, self.filesystem.RemoveObject,
                      self.filesystem.JoinPaths(self.fake_child.name,
                                                'some_bogus_filename'))

  def testRemoveObjectFromNonDirectoryError(self):
    self.filesystem.AddObject(self.root_name, self.fake_file)
    self.assertRaises(
        IOError, self.filesystem.RemoveObject,
        self.filesystem.JoinPaths(
            '%s' % self.fake_file.name,
            'file_does_not_matter_since_parent_not_a_directory'))

  def testExistsFileRemovedFromChild(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_file)
    path = self.filesystem.JoinPaths(self.fake_child.name,
                                     self.fake_file.name)
    self.filesystem.RemoveObject(path)
    self.assertFalse(self.filesystem.Exists(path))

  def testOperateOnGrandchildDirectory(self):
    self.filesystem.AddObject(self.root_name, self.fake_child)
    self.filesystem.AddObject(self.fake_child.name, self.fake_grandchild)
    grandchild_directory = self.filesystem.JoinPaths(self.fake_child.name,
                                                     self.fake_grandchild.name)
    grandchild_file = self.filesystem.JoinPaths(grandchild_directory,
                                                self.fake_file.name)
    self.assertRaises(IOError, self.filesystem.GetObject, grandchild_file)
    self.filesystem.AddObject(grandchild_directory, self.fake_file)
    self.assertEqual(self.fake_file,
                     self.filesystem.GetObject(grandchild_file))
    self.assertTrue(self.filesystem.Exists(grandchild_file))
    self.filesystem.RemoveObject(grandchild_file)
    self.assertRaises(IOError, self.filesystem.GetObject, grandchild_file)
    self.assertFalse(self.filesystem.Exists(grandchild_file))

  def testCreateDirectoryInRootDirectory(self):
    path = 'foo'
    self.filesystem.CreateDirectory(path)
    new_dir = self.filesystem.GetObject(path)
    self.assertEqual(os.path.basename(path), new_dir.name)
    self.assertTrue(stat.S_IFDIR & new_dir.st_mode)

  def testCreateDirectoryInRootDirectoryAlreadyExistsError(self):
    path = 'foo'
    self.filesystem.CreateDirectory(path)
    self.assertRaises(OSError, self.filesystem.CreateDirectory, path)

  def testCreateDirectory(self):
    path = 'foo/bar/baz'
    self.filesystem.CreateDirectory(path)
    new_dir = self.filesystem.GetObject(path)
    self.assertEqual(os.path.basename(path), new_dir.name)
    self.assertTrue(stat.S_IFDIR & new_dir.st_mode)

    # Create second directory to make sure first is OK.
    path = '%s/quux' % path
    self.filesystem.CreateDirectory(path)
    new_dir = self.filesystem.GetObject(path)
    self.assertEqual(os.path.basename(path), new_dir.name)
    self.assertTrue(stat.S_IFDIR & new_dir.st_mode)

  def testCreateDirectoryAlreadyExistsError(self):
    path = 'foo/bar/baz'
    self.filesystem.CreateDirectory(path)
    self.assertRaises(OSError, self.filesystem.CreateDirectory, path)

  def testCreateFileInCurrentDirectory(self):
    path = 'foo'
    contents = 'dummy data'
    self.filesystem.CreateFile(path, contents=contents)
    self.assertTrue(self.filesystem.Exists(path))
    self.assertFalse(self.filesystem.Exists(os.path.dirname(path)))
    path = './%s' % path
    self.assertTrue(self.filesystem.Exists(os.path.dirname(path)))

  def testCreateFileInRootDirectory(self):
    path = '/foo'
    contents = 'dummy data'
    self.filesystem.CreateFile(path, contents=contents)
    new_file = self.filesystem.GetObject(path)
    self.assertTrue(self.filesystem.Exists(path))
    self.assertTrue(self.filesystem.Exists(os.path.dirname(path)))
    self.assertEqual(os.path.basename(path), new_file.name)
    self.assertTrue(stat.S_IFREG & new_file.st_mode)
    self.assertEqual(contents, new_file.contents)

  def testCreateFileWithSizeButNoContentCreatesLargeFile(self):
    path = 'large_foo_bar'
    self.filesystem.CreateFile(path, st_size=100000000)
    new_file = self.filesystem.GetObject(path)
    self.assertEqual(None, new_file.contents)
    self.assertEqual(100000000, new_file.st_size)

  def testCreateFileInRootDirectoryAlreadyExistsError(self):
    path = 'foo'
    self.filesystem.CreateFile(path)
    self.assertRaises(IOError, self.filesystem.CreateFile, path)

  def testCreateFile(self):
    path = 'foo/bar/baz'
    retval = self.filesystem.CreateFile(path, contents='dummy_data')
    self.assertTrue(self.filesystem.Exists(path))
    self.assertTrue(self.filesystem.Exists(os.path.dirname(path)))
    new_file = self.filesystem.GetObject(path)
    self.assertEqual(os.path.basename(path), new_file.name)
    self.assertTrue(stat.S_IFREG & new_file.st_mode)
    self.assertEqual(new_file, retval)

  def testCreateFileAlreadyExistsError(self):
    path = 'foo/bar/baz'
    self.filesystem.CreateFile(path, contents='dummy_data')
    self.assertRaises(IOError, self.filesystem.CreateFile, path)

  def testCreateLink(self):
    path = 'foo/bar/baz'
    target_path = 'foo/bar/quux'
    new_file = self.filesystem.CreateLink(path, 'quux')
    # Neither the path not the final target exists before we actually write to
    # one of them, even though the link appears in the file system.
    self.assertFalse(self.filesystem.Exists(path))
    self.assertFalse(self.filesystem.Exists(target_path))
    self.assertTrue(stat.S_IFLNK & new_file.st_mode)

    # but once we write the linked to file, they both will exist.
    self.filesystem.CreateFile(target_path)
    self.assertTrue(self.filesystem.Exists(path))
    self.assertTrue(self.filesystem.Exists(target_path))

  def testResolveObject(self):
    target_path = 'dir/target'
    target_contents = '0123456789ABCDEF'
    link_name = 'x'
    self.filesystem.CreateDirectory('dir')
    self.filesystem.CreateFile('dir/target', contents=target_contents)
    self.filesystem.CreateLink(link_name, target_path)
    obj = self.filesystem.ResolveObject(link_name)
    self.assertEqual('target', obj.name)
    self.assertEqual(target_contents, obj.contents)

  def testLresolveObject(self):
    target_path = 'dir/target'
    target_contents = '0123456789ABCDEF'
    link_name = 'x'
    self.filesystem.CreateDirectory('dir')
    self.filesystem.CreateFile('dir/target', contents=target_contents)
    self.filesystem.CreateLink(link_name, target_path)
    obj = self.filesystem.LResolveObject(link_name)
    self.assertEqual(link_name, obj.name)
    self.assertEqual(target_path, obj.contents)

  def testDirectoryAccessOnFile(self):
    self.filesystem.CreateFile('not_a_dir')
    self.assertRaises(IOError, self.filesystem.ResolveObject, 'not_a_dir/foo')
    self.assertRaises(IOError, self.filesystem.ResolveObject,
                      'not_a_dir/foo/bar')
    self.assertRaises(IOError, self.filesystem.LResolveObject, 'not_a_dir/foo')
    self.assertRaises(IOError, self.filesystem.LResolveObject,
                      'not_a_dir/foo/bar')


class FakeOsModuleTest(TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.rwx = self.os.R_OK | self.os.W_OK | self.os.X_OK
    self.rw = self.os.R_OK | self.os.W_OK
    self.orig_time = time.time
    time.time = _GetDummyTime(200, 20)

  def tearDown(self):
    time.time = self.orig_time

  def assertRaisesWithRegexpMatch(self, expected_exception, expected_regexp,
                                  callable_obj, *args, **kwargs):
    """Asserts that the message in a raised exception matches the given regexp.

    Args:
      expected_exception: Exception class expected to be raised.
      expected_regexp: Regexp (re pattern object or string) expected to be
        found in error message.
      callable_obj: Function to be called.
      *args: Extra args.
      **kwargs: Extra kwargs.
    """
    try:
      callable_obj(*args, **kwargs)
    except expected_exception as err:
      if isinstance(expected_regexp, str):
        expected_regexp = re.compile(expected_regexp)
      self.assertTrue(
          expected_regexp.search(str(err)),
          '"%s" does not match "%s"' % (expected_regexp.pattern, str(err)))
    else:
      self.fail(expected_exception.__name__ + ' not raised')

  def testChdir(self):
    """chdir should work on a directory."""
    directory = '/foo'
    self.filesystem.CreateDirectory(directory)
    self.os.chdir(directory)

  def testChdirFailsNonExist(self):
    """chdir should raise OSError if the target does not exist."""
    directory = '/no/such/directory'
    self.assertRaises(OSError, self.os.chdir, directory)

  def testChdirFailsNonDirectory(self):
    """chdir should raies OSError if the target is not a directory."""
    filename = '/foo/bar'
    self.filesystem.CreateFile(filename)
    self.assertRaises(OSError, self.os.chdir, filename)

  def testConsecutiveChdir(self):
    """Consecutive relative chdir calls should work."""
    dir1 = 'foo'
    dir2 = 'bar'
    full_dirname = self.os.path.join(dir1, dir2)
    self.filesystem.CreateDirectory(full_dirname)
    self.os.chdir(dir1)
    self.os.chdir(dir2)
    self.assertEqual(self.os.getcwd(), self.os.path.sep + full_dirname)

  def testBackwardsChdir(self):
    """chdir into '..' should behave appropriately."""
    rootdir = self.os.getcwd()
    dirname = 'foo'
    abs_dirname = self.os.path.abspath(dirname)
    self.filesystem.CreateDirectory(dirname)
    self.os.chdir(dirname)
    self.assertEqual(abs_dirname, self.os.getcwd())
    self.os.chdir('..')
    self.assertEqual(rootdir, self.os.getcwd())
    self.os.chdir(self.os.path.join(dirname, '..'))
    self.assertEqual(rootdir, self.os.getcwd())

  def testGetCwd(self):
    dirname = '/foo/bar'
    self.filesystem.CreateDirectory(dirname)
    self.assertEqual(self.os.getcwd(), self.os.path.sep)
    self.os.chdir(dirname)
    self.assertEqual(self.os.getcwd(), dirname)

  def testListdir(self):
    directory = 'xyzzy/plugh'
    files = ['foo', 'bar', 'baz']
    for f in files:
      self.filesystem.CreateFile('%s/%s' % (directory, f))
    files.sort()
    self.assertEqual(files, self.os.listdir(directory))

  def testListdirOnSymlink(self):
    directory = 'xyzzy'
    files = ['foo', 'bar', 'baz']
    for f in files:
      self.filesystem.CreateFile('%s/%s' % (directory, f))
    self.filesystem.CreateLink('symlink', 'xyzzy')
    files.sort()
    self.assertEqual(files, self.os.listdir('symlink'))

  def testListdirError(self):
    file_path = 'foo/bar/baz'
    self.filesystem.CreateFile(file_path)
    self.assertRaises(OSError, self.os.listdir, file_path)

  def testExistsCurrentDir(self):
    self.assertTrue(self.filesystem.Exists('.'))

  def testListdirCurrent(self):
    files = ['foo', 'bar', 'baz']
    for f in files:
      self.filesystem.CreateFile('%s' % f)
    files.sort()
    self.assertEqual(files, self.os.listdir('.'))

  def testFdopen(self):
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
    file_path1 = 'some_file1'
    self.filesystem.CreateFile(file_path1, contents='contents here1')
    fake_file1 = fake_open(file_path1, 'r')
    self.assertEqual(0, fake_file1.fileno())

    self.assertFalse(self.os.fdopen(0) is fake_file1)

    self.assertRaises(TypeError, self.os.fdopen, None)
    self.assertRaises(TypeError, self.os.fdopen, 'a string')

  def testOutOfRangeFdopen(self):
    # We haven't created any files, so even 0 is out of range.
    self.assertRaises(OSError, self.os.fdopen, 0)

  def testClosedFileDescriptor(self):
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
    first_path = 'some_file1'
    second_path = 'some_file2'
    third_path = 'some_file3'
    self.filesystem.CreateFile(first_path, contents='contents here1')
    self.filesystem.CreateFile(second_path, contents='contents here2')
    self.filesystem.CreateFile(third_path, contents='contents here3')

    fake_file1 = fake_open(first_path, 'r')
    fake_file2 = fake_open(second_path, 'r')
    fake_file3 = fake_open(third_path, 'r')
    self.assertEqual(0, fake_file1.fileno())
    self.assertEqual(1, fake_file2.fileno())
    self.assertEqual(2, fake_file3.fileno())

    fileno2 = fake_file2.fileno()
    self.os.close(fileno2)
    self.assertRaises(OSError, self.os.close, fileno2)
    self.assertEqual(0, fake_file1.fileno())
    self.assertEqual(2, fake_file3.fileno())

    self.assertFalse(self.os.fdopen(0) is fake_file1)
    self.assertFalse(self.os.fdopen(2) is fake_file3)
    self.assertRaises(OSError, self.os.fdopen, 1)

  def testFdopenMode(self):
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
    file_path1 = 'some_file1'
    self.filesystem.CreateFile(file_path1, contents='contents here1',
                               st_mode=((stat.S_IFREG | 0o666) ^ stat.S_IWRITE))

    fake_file1 = fake_open(file_path1, 'r')
    self.assertEqual(0, fake_file1.fileno())
    self.os.fdopen(0)
    self.os.fdopen(0, mode='r')
    exception = OSError if sys.version_info < (3, 0) else IOError
    self.assertRaises(exception, self.os.fdopen, 0, 'w')

  def testLowLevelOpenCreate(self):
    file_path = 'file1'
    # this is the low-level open, not FakeFileOpen
    fileno = self.os.open(file_path, self.os.O_CREAT)
    self.assertEqual(0, fileno)
    self.assertTrue(self.os.path.exists(file_path))

  def testLowLevelOpenCreateMode(self):
    file_path = 'file1'
    fileno = self.os.open(file_path, self.os.O_CREAT, 0o700)
    self.assertEqual(0, fileno)
    self.assertTrue(self.os.path.exists(file_path))
    self.assertModeEqual(0o700, self.os.stat(file_path).st_mode)

  def testLowLevelOpenCreateModeUnsupported(self):
    file_path = 'file1'
    fake_flag = 0b100000000000000000000000
    self.assertRaises(NotImplementedError, self.os.open, file_path, fake_flag)

  def testLowLevelWriteRead(self):
    file_path = 'file1'
    self.filesystem.CreateFile(file_path, contents='orig contents')
    new_contents = '1234567890abcdef'
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)

    fh = fake_open(file_path, 'w')
    fileno = fh.fileno()

    self.assertEqual(len(new_contents), self.os.write(fileno, new_contents))
    self.assertEqual(new_contents,
                     self.filesystem.GetObject(file_path).contents)
    self.os.close(fileno)

    fh = fake_open(file_path, 'r')
    fileno = fh.fileno()
    self.assertEqual('', self.os.read(fileno, 0))
    self.assertEqual(new_contents[0:2], self.os.read(fileno, 2))
    self.assertEqual(new_contents[2:10], self.os.read(fileno, 8))
    self.assertEqual(new_contents[10:], self.os.read(fileno, 100))
    self.assertEqual('', self.os.read(fileno, 10))
    self.os.close(fileno)

    self.assertRaises(OSError, self.os.write, fileno, new_contents)
    self.assertRaises(OSError, self.os.read, fileno, 10)

  def testFstat(self):
    directory = 'xyzzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path, contents='ABCDE')
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
    file_obj = fake_open(file_path)
    fileno = file_obj.fileno()
    self.assertTrue(stat.S_IFREG & self.os.fstat(fileno)[stat.ST_MODE])
    self.assertTrue(stat.S_IFREG & self.os.fstat(fileno).st_mode)
    self.assertEqual(5, self.os.fstat(fileno)[stat.ST_SIZE])

  def testStat(self):
    directory = 'xyzzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path, contents='ABCDE')
    self.assertTrue(stat.S_IFDIR & self.os.stat(directory)[stat.ST_MODE])
    self.assertTrue(stat.S_IFREG & self.os.stat(file_path)[stat.ST_MODE])
    self.assertTrue(stat.S_IFREG & self.os.stat(file_path).st_mode)
    self.assertEqual(5, self.os.stat(file_path)[stat.ST_SIZE])

  def testLstat(self):
    directory = 'xyzzy'
    base_name = 'plugh'
    file_contents = 'frobozz'
    # Just make sure we didn't accidentally make our test data meaningless.
    self.assertNotEqual(len(base_name), len(file_contents))
    file_path = '%s/%s' % (directory, base_name)
    link_path = '%s/link' % directory
    self.filesystem.CreateFile(file_path, contents=file_contents)
    self.filesystem.CreateLink(link_path, base_name)
    self.assertEqual(len(file_contents), self.os.lstat(file_path)[stat.ST_SIZE])
    self.assertEqual(len(base_name), self.os.lstat(link_path)[stat.ST_SIZE])

  def testStatNonExistentFile(self):
    # set up
    file_path = '/non/existent/file'
    self.assertFalse(self.filesystem.Exists(file_path))
    # actual tests
    try:
      # Use try-catch to check exception attributes.
      self.os.stat(file_path)
      self.fail('Exception is expected.')  # COV_NF_LINE
    except OSError as os_error:
      self.assertEqual(errno.ENOENT, os_error.errno)
      self.assertEqual(file_path, os_error.filename)

  def testReadlink(self):
    link_path = 'foo/bar/baz'
    target = 'tarJAY'
    self.filesystem.CreateLink(link_path, target)
    self.assertEqual(self.os.readlink(link_path), target)

  def testReadlinkRaisesIfPathIsNotALink(self):
    file_path = 'foo/bar/eleventyone'
    self.filesystem.CreateFile(file_path)
    self.assertRaises(OSError, self.os.readlink, file_path)

  def testReadlinkRaisesIfPathDoesNotExist(self):
    self.assertRaises(OSError, self.os.readlink, '/this/path/does/not/exist')

  def testReadlinkRaisesIfPathIsNone(self):
    self.assertRaises(TypeError, self.os.readlink, None)

  def testReadlinkWithLinksInPath(self):
    self.filesystem.CreateLink('/meyer/lemon/pie', 'yum')
    self.filesystem.CreateLink('/geo/metro', '/meyer')
    self.assertEqual('yum', self.os.readlink('/geo/metro/lemon/pie'))

  def testReadlinkWithChainedLinksInPath(self):
    self.filesystem.CreateLink('/eastern/european/wolfhounds/chase', 'cats')
    self.filesystem.CreateLink('/russian', '/eastern/european')
    self.filesystem.CreateLink('/dogs', '/russian/wolfhounds')
    self.assertEqual('cats', self.os.readlink('/dogs/chase'))

  def testRemoveDir(self):
    directory = 'xyzzy'
    dir_path = '/%s/plugh' % directory
    self.filesystem.CreateDirectory(dir_path)
    self.assertTrue(self.filesystem.Exists(dir_path))
    self.assertRaises(OSError, self.os.remove, dir_path)
    self.assertTrue(self.filesystem.Exists(dir_path))
    self.os.chdir(directory)
    self.assertRaises(OSError, self.os.remove, 'plugh')
    self.assertTrue(self.filesystem.Exists(dir_path))
    self.assertRaises(OSError, self.os.remove, '/plugh')

  def testRemoveFile(self):
    directory = 'zzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.os.remove(file_path)
    self.assertFalse(self.filesystem.Exists(file_path))

  def testRemoveFileNoDirectory(self):
    directory = 'zzy'
    file_name = 'plugh'
    file_path = '%s/%s' % (directory, file_name)
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.os.chdir(directory)
    self.os.remove(file_name)
    self.assertFalse(self.filesystem.Exists(file_path))

  def testRemoveFileRelativePath(self):
    original_dir = self.os.getcwd()
    directory = 'zzy'
    subdirectory = self.os.path.join(directory, directory)
    file_name = 'plugh'
    file_path = '%s/%s' % (directory, file_name)
    file_path_relative = self.os.path.join('..', file_name)
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.filesystem.CreateDirectory(subdirectory)
    self.assertTrue(self.filesystem.Exists(subdirectory))
    self.os.chdir(subdirectory)
    self.os.remove(file_path_relative)
    self.assertFalse(self.filesystem.Exists(file_path_relative))
    self.os.chdir(original_dir)
    self.assertFalse(self.filesystem.Exists(file_path))

  def testRemoveDirRaisesError(self):
    directory = 'zzy'
    self.filesystem.CreateDirectory(directory)
    self.assertRaises(OSError,
                      self.os.remove,
                      directory)

  def testRemoveSymlinkToDir(self):
    directory = 'zzy'
    link = 'link_to_dir'
    self.filesystem.CreateDirectory(directory)
    self.os.symlink(directory, link)
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertTrue(self.filesystem.Exists(link))
    self.os.remove(link)
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertFalse(self.filesystem.Exists(link))

  def testUnlink(self):
    self.assertTrue(self.os.unlink == self.os.remove)

  def testUnlinkRaisesIfNotExist(self):
    file_path = '/file/does/not/exist'
    self.assertFalse(self.filesystem.Exists(file_path))
    self.assertRaises(OSError, self.os.unlink, file_path)

  def testRenameToNonexistentFile(self):
    """Can rename a file to an unused name."""
    directory = 'xyzzy'
    old_file_path = '%s/plugh_old' % directory
    new_file_path = '%s/plugh_new' % directory
    self.filesystem.CreateFile(old_file_path, contents='test contents')
    self.assertTrue(self.filesystem.Exists(old_file_path))
    self.assertFalse(self.filesystem.Exists(new_file_path))
    self.os.rename(old_file_path, new_file_path)
    self.assertFalse(self.filesystem.Exists(old_file_path))
    self.assertTrue(self.filesystem.Exists(new_file_path))
    self.assertEqual('test contents',
                     self.filesystem.GetObject(new_file_path).contents)

  def testRenameDirectory(self):
    """Can rename a directory to an unused name."""
    for old_path, new_path in [('wxyyw', 'xyzzy'), ('/abccb', 'cdeed')]:
      self.filesystem.CreateFile('%s/plugh' % old_path, contents='test')
      self.assertTrue(self.filesystem.Exists(old_path))
      self.assertFalse(self.filesystem.Exists(new_path))
      self.os.rename(old_path, new_path)
      self.assertFalse(self.filesystem.Exists(old_path))
      self.assertTrue(self.filesystem.Exists(new_path))
      self.assertEqual(
          'test', self.filesystem.GetObject('%s/plugh' % new_path).contents)

  def testRenameToExistentFile(self):
    """Can rename a file to a used name."""
    directory = 'xyzzy'
    old_file_path = '%s/plugh_old' % directory
    new_file_path = '%s/plugh_new' % directory
    self.filesystem.CreateFile(old_file_path, contents='test contents 1')
    self.filesystem.CreateFile(new_file_path, contents='test contents 2')
    self.assertTrue(self.filesystem.Exists(old_file_path))
    self.assertTrue(self.filesystem.Exists(new_file_path))
    self.os.rename(old_file_path, new_file_path)
    self.assertFalse(self.filesystem.Exists(old_file_path))
    self.assertTrue(self.filesystem.Exists(new_file_path))
    self.assertEqual('test contents 1',
                     self.filesystem.GetObject(new_file_path).contents)

  def testRenameToNonexistentDir(self):
    """Can rename a file to a name in a nonexistent dir."""
    directory = 'xyzzy'
    old_file_path = '%s/plugh_old' % directory
    new_file_path = '%s/no_such_path/plugh_new' % directory
    self.filesystem.CreateFile(old_file_path, contents='test contents')
    self.assertTrue(self.filesystem.Exists(old_file_path))
    self.assertFalse(self.filesystem.Exists(new_file_path))
    self.assertRaises(IOError, self.os.rename, old_file_path, new_file_path)
    self.assertTrue(self.filesystem.Exists(old_file_path))
    self.assertFalse(self.filesystem.Exists(new_file_path))
    self.assertEqual('test contents',
                     self.filesystem.GetObject(old_file_path).contents)

  def testRenameNonexistentFileShouldRaiseError(self):
    """Can't rename a file that doesn't exist."""
    self.assertRaises(OSError,
                      self.os.rename,
                      'nonexistent-foo',
                      'doesn\'t-matter-bar')

  def testRenameEmptyDir(self):
    """Test a rename of an empty directory."""
    directory = 'xyzzy'
    before_dir = '%s/empty' % directory
    after_dir = '%s/unused' % directory
    self.filesystem.CreateDirectory(before_dir)
    self.assertTrue(self.filesystem.Exists('%s/.' % before_dir))
    self.assertFalse(self.filesystem.Exists(after_dir))
    self.os.rename(before_dir, after_dir)
    self.assertFalse(self.filesystem.Exists(before_dir))
    self.assertTrue(self.filesystem.Exists('%s/.' % after_dir))

  def testRenameDir(self):
    """Test a rename of a directory."""
    directory = 'xyzzy'
    before_dir = '%s/before' % directory
    before_file = '%s/before/file' % directory
    after_dir = '%s/after' % directory
    after_file = '%s/after/file' % directory
    self.filesystem.CreateDirectory(before_dir)
    self.filesystem.CreateFile(before_file, contents='payload')
    self.assertTrue(self.filesystem.Exists(before_dir))
    self.assertTrue(self.filesystem.Exists(before_file))
    self.assertFalse(self.filesystem.Exists(after_dir))
    self.assertFalse(self.filesystem.Exists(after_file))
    self.os.rename(before_dir, after_dir)
    self.assertFalse(self.filesystem.Exists(before_dir))
    self.assertFalse(self.filesystem.Exists(before_file))
    self.assertTrue(self.filesystem.Exists(after_dir))
    self.assertTrue(self.filesystem.Exists(after_file))
    self.assertEqual('payload',
                     self.filesystem.GetObject(after_file).contents)

  def testRenamePreservesStat(self):
    """Test if rename preserves mtime."""
    directory = 'xyzzy'
    old_file_path = '%s/plugh_old' % directory
    new_file_path = '%s/plugh_new' % directory
    old_file = self.filesystem.CreateFile(old_file_path)
    old_file.SetMTime(old_file.st_mtime - 3600)
    self.os.chown(old_file_path, 200, 200)
    self.os.chmod(old_file_path, 0o222)
    new_file = self.filesystem.CreateFile(new_file_path)
    self.assertNotEqual(new_file.st_mtime, old_file.st_mtime)
    self.os.rename(old_file_path, new_file_path)
    new_file = self.filesystem.GetObject(new_file_path)
    self.assertEqual(new_file.st_mtime, old_file.st_mtime)
    self.assertEqual(new_file.st_mode, old_file.st_mode)
    self.assertEqual(new_file.st_uid, old_file.st_uid)
    self.assertEqual(new_file.st_gid, old_file.st_gid)

  def testRenameSameFilenames(self):
    """Test renaming when old and new names are the same."""
    directory = 'xyzzy'
    file_contents = 'Spam eggs'
    file_path = '%s/eggs' % directory
    self.filesystem.CreateFile(file_path, contents=file_contents)
    self.os.rename(file_path, file_path)
    self.assertEqual(file_contents,
                     self.filesystem.GetObject(file_path).contents)

  def testRmdir(self):
    """Can remove a directory."""
    directory = 'xyzzy'
    sub_dir = '/xyzzy/abccd'
    other_dir = '/xyzzy/cdeed'
    self.filesystem.CreateDirectory(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.os.rmdir(directory)
    self.assertFalse(self.filesystem.Exists(directory))
    self.filesystem.CreateDirectory(sub_dir)
    self.filesystem.CreateDirectory(other_dir)
    self.os.chdir(sub_dir)
    self.os.rmdir('../cdeed')
    self.assertFalse(self.filesystem.Exists(other_dir))
    self.os.chdir('..')
    self.os.rmdir('abccd')
    self.assertFalse(self.filesystem.Exists(sub_dir))

  def testRmdirRaisesIfNotEmpty(self):
    """Raises an exception if the target directory is not empty."""
    directory = 'xyzzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.assertRaises(OSError, self.os.rmdir, directory)

  def testRmdirRaisesIfNotDirectory(self):
    """Raises an exception if the target is not a directory."""
    directory = 'xyzzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.assertRaises(OSError, self.os.rmdir, file_path)
    self.assertRaises(OSError, self.os.rmdir, '.')

  def testRmdirRaisesIfNotExist(self):
    """Raises an exception if the target does not exist."""
    directory = 'xyzzy'
    self.assertFalse(self.filesystem.Exists(directory))
    self.assertRaises(OSError, self.os.rmdir, directory)

  def RemovedirsCheck(self, directory):
    self.assertTrue(self.filesystem.Exists(directory))
    self.os.removedirs(directory)
    return not self.filesystem.Exists(directory)

  def testRemovedirs(self):
    data = ['test1', 'test1/test2', 'test1/extra', 'test1/test2/test3']
    for directory in data:
      self.filesystem.CreateDirectory(directory)
      self.assertTrue(self.filesystem.Exists(directory))
    self.assertRaises(OSError, self.RemovedirsCheck, data[0])
    self.assertRaises(OSError, self.RemovedirsCheck, data[1])

    self.assertTrue(self.RemovedirsCheck(data[3]))
    self.assertTrue(self.filesystem.Exists(data[0]))
    self.assertFalse(self.filesystem.Exists(data[1]))
    self.assertTrue(self.filesystem.Exists(data[2]))

    # Should raise because '/test1/extra' is all that is left, and
    # removedirs('/test1/extra') will eventually try to rmdir('/').
    self.assertRaises(OSError, self.RemovedirsCheck, data[2])

    # However, it will still delete '/test1') in the process.
    self.assertFalse(self.filesystem.Exists(data[0]))

    self.filesystem.CreateDirectory('test1/test2')
    # Add this to the root directory to avoid raising an exception.
    self.filesystem.CreateDirectory('test3')
    self.assertTrue(self.RemovedirsCheck('test1/test2'))
    self.assertFalse(self.filesystem.Exists('test1/test2'))
    self.assertFalse(self.filesystem.Exists('test1'))

  def testRemovedirsRaisesIfRemovingRoot(self):
    """Raises exception if asked to remove '/'."""
    directory = '/'
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertRaises(OSError, self.os.removedirs, directory)

  def testRemovedirsRaisesIfCascadeRemovingRoot(self):
    """Raises exception if asked to remove '/' as part of a larger operation.

    All of other directories should still be removed, though.
    """
    directory = '/foo/bar/'
    self.filesystem.CreateDirectory(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertRaises(OSError, self.os.removedirs, directory)
    head, unused_tail = self.os.path.split(directory)
    while head != '/':
      self.assertFalse(self.filesystem.Exists(directory))
      head, unused_tail = self.os.path.split(head)

  def testRemovedirsWithTrailingSlash(self):
    """removedirs works on directory names with trailing slashes."""
    # separate this case from the removing-root-directory case
    self.filesystem.CreateDirectory('/baz')
    directory = '/foo/bar/'
    self.filesystem.CreateDirectory(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.os.removedirs(directory)
    self.assertFalse(self.filesystem.Exists(directory))

  def testMkdir(self):
    """mkdir can create a relative directory."""
    directory = 'xyzzy'
    self.assertFalse(self.filesystem.Exists(directory))
    self.os.mkdir(directory)
    self.assertTrue(self.filesystem.Exists('/%s' % directory))
    self.os.chdir(directory)
    self.os.mkdir(directory)
    self.assertTrue(self.filesystem.Exists('/%s/%s' % (directory, directory)))
    self.os.chdir(directory)
    self.os.mkdir('../abccb')
    self.assertTrue(self.filesystem.Exists('/%s/abccb' % directory))

  def testMkdirWithTrailingSlash(self):
    """mkdir can create a directory named with a trailing slash."""
    directory = '/foo/'
    self.assertFalse(self.filesystem.Exists(directory))
    self.os.mkdir(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertTrue(self.filesystem.Exists('/foo'))

  def testMkdirRaisesIfEmptyDirectoryName(self):
    """mkdir raises exeption if creating directory named ''."""
    directory = ''
    self.assertRaises(OSError, self.os.mkdir, directory)

  def testMkdirRaisesIfNoParent(self):
    """mkdir raises exception if parent directory does not exist."""
    parent = 'xyzzy'
    directory = '%s/foo' % (parent,)
    self.assertFalse(self.filesystem.Exists(parent))
    self.assertRaises(Exception, self.os.mkdir, directory)

  def testMkdirRaisesIfDirectoryExists(self):
    """mkdir raises exception if directory already exists."""
    directory = 'xyzzy'
    self.filesystem.CreateDirectory(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    self.assertRaises(Exception, self.os.mkdir, directory)

  def testMkdirRaisesIfFileExists(self):
    """mkdir raises exception if name already exists as a file."""
    directory = 'xyzzy'
    file_path = '%s/plugh' % directory
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.assertRaises(Exception, self.os.mkdir, file_path)

  def testMkdirRaisesWithSlashDot(self):
    """mkdir raises exception if mkdir foo/. (trailing /.)."""
    self.assertRaises(Exception, self.os.mkdir, '/.')
    directory = '/xyzzy/.'
    self.assertRaises(Exception, self.os.mkdir, directory)
    self.filesystem.CreateDirectory('/xyzzy')
    self.assertRaises(Exception, self.os.mkdir, directory)

  def testMkdirRaisesWithDoubleDots(self):
    """mkdir raises exception if mkdir foo/foo2/../foo3."""
    self.assertRaises(Exception, self.os.mkdir, '/..')
    directory = '/xyzzy/dir1/dir2/../../dir3'
    self.assertRaises(Exception, self.os.mkdir, directory)
    self.filesystem.CreateDirectory('/xyzzy')
    self.assertRaises(Exception, self.os.mkdir, directory)
    self.filesystem.CreateDirectory('/xyzzy/dir1')
    self.assertRaises(Exception, self.os.mkdir, directory)
    self.filesystem.CreateDirectory('/xyzzy/dir1/dir2')
    self.os.mkdir(directory)
    self.assertTrue(self.filesystem.Exists(directory))
    directory = '/xyzzy/dir1/..'
    self.assertRaises(Exception, self.os.mkdir, directory)

  def testMkdirRaisesIfParentIsReadOnly(self):
    """mkdir raises exception if parent is read only."""
    directory = '/a'
    self.os.mkdir(directory)

    # Change directory permissions to be read only.
    self.os.chmod(directory, 0o400)

    directory = '/a/b'
    self.assertRaises(Exception, self.os.mkdir, directory)

  def testMakedirs(self):
    """makedirs can create a directory even in parent does not exist."""
    parent = 'xyzzy'
    directory = '%s/foo' % (parent,)
    self.assertFalse(self.filesystem.Exists(parent))
    self.os.makedirs(directory)
    self.assertTrue(self.filesystem.Exists(parent))

  def testMakedirsRaisesIfParentIsFile(self):
    """makedirs raises exception if a parent component exists as a file."""
    file_path = 'xyzzy'
    directory = '%s/plugh' % file_path
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    self.assertRaises(Exception, self.os.makedirs, directory)

  def testMakedirsRaisesIfAccessDenied(self):
    """makedirs raises exception if access denied."""
    directory = '/a'
    self.os.mkdir(directory)

    # Change directory permissions to be read only.
    self.os.chmod(directory, 0o400)

    directory = '/a/b'
    self.assertRaises(Exception, self.os.makedirs, directory)

  def _CreateTestFile(self, path):
    self.filesystem.CreateFile(path)
    self.assertTrue(self.filesystem.Exists(path))
    st = self.os.stat(path)
    self.assertEqual(0o666, stat.S_IMODE(st.st_mode))
    self.assertTrue(st.st_mode & stat.S_IFREG)
    self.assertFalse(st.st_mode & stat.S_IFDIR)

  def _CreateTestDirectory(self, path):
    self.filesystem.CreateDirectory(path)
    self.assertTrue(self.filesystem.Exists(path))
    st = self.os.stat(path)
    self.assertEqual(0o777, stat.S_IMODE(st.st_mode))
    self.assertFalse(st.st_mode & stat.S_IFREG)
    self.assertTrue(st.st_mode & stat.S_IFDIR)

  def testAccess700(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    self.os.chmod(path, 0o700)
    self.assertModeEqual(0o700, self.os.stat(path).st_mode)
    # actual tests
    self.assertTrue(self.os.access(path, self.os.F_OK))
    self.assertTrue(self.os.access(path, self.os.R_OK))
    self.assertTrue(self.os.access(path, self.os.W_OK))
    self.assertTrue(self.os.access(path, self.os.X_OK))
    self.assertTrue(self.os.access(path, self.rwx))

  def testAccess600(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    self.os.chmod(path, 0o600)
    self.assertModeEqual(0o600, self.os.stat(path).st_mode)
    # actual tests
    self.assertTrue(self.os.access(path, self.os.F_OK))
    self.assertTrue(self.os.access(path, self.os.R_OK))
    self.assertTrue(self.os.access(path, self.os.W_OK))
    self.assertFalse(self.os.access(path, self.os.X_OK))
    self.assertFalse(self.os.access(path, self.rwx))
    self.assertTrue(self.os.access(path, self.rw))

  def testAccess400(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    self.os.chmod(path, 0o400)
    self.assertModeEqual(0o400, self.os.stat(path).st_mode)
    # actual tests
    self.assertTrue(self.os.access(path, self.os.F_OK))
    self.assertTrue(self.os.access(path, self.os.R_OK))
    self.assertFalse(self.os.access(path, self.os.W_OK))
    self.assertFalse(self.os.access(path, self.os.X_OK))
    self.assertFalse(self.os.access(path, self.rwx))
    self.assertFalse(self.os.access(path, self.rw))

  def testAccessNonExistentFile(self):
    # set up
    path = '/non/existent/file'
    self.assertFalse(self.filesystem.Exists(path))
    # actual tests
    self.assertFalse(self.os.access(path, self.os.F_OK))
    self.assertFalse(self.os.access(path, self.os.R_OK))
    self.assertFalse(self.os.access(path, self.os.W_OK))
    self.assertFalse(self.os.access(path, self.os.X_OK))
    self.assertFalse(self.os.access(path, self.rwx))
    self.assertFalse(self.os.access(path, self.rw))

  def testChmod(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    # actual tests
    self.os.chmod(path, 0o6543)
    st = self.os.stat(path)
    self.assertModeEqual(0o6543, st.st_mode)
    self.assertTrue(st.st_mode & stat.S_IFREG)
    self.assertFalse(st.st_mode & stat.S_IFDIR)

  def testChmodDir(self):
    # set up
    path = '/some_dir'
    self._CreateTestDirectory(path)
    # actual tests
    self.os.chmod(path, 0o1234)
    st = self.os.stat(path)
    self.assertModeEqual(0o1234, st.st_mode)
    self.assertFalse(st.st_mode & stat.S_IFREG)
    self.assertTrue(st.st_mode & stat.S_IFDIR)

  def testChmodNonExistent(self):
    # set up
    path = '/non/existent/file'
    self.assertFalse(self.filesystem.Exists(path))
    # actual tests
    try:
      # Use try-catch to check exception attributes.
      self.os.chmod(path, 0o777)
      self.fail('Exception is expected.')  # COV_NF_LINE
    except OSError as os_error:
      self.assertEqual(errno.ENOENT, os_error.errno)
      self.assertEqual(path, os_error.filename)

  def testChmodStCtime(self):
    # set up
    file_path = 'some_file'
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.filesystem.Exists(file_path))
    st = self.os.stat(file_path)
    self.assertEqual(200, st.st_ctime)
    # tests
    self.os.chmod(file_path, 0o765)
    st = self.os.stat(file_path)
    self.assertEqual(220, st.st_ctime)

  def testUtimeSetsCurrentTimeIfArgsIsNone(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    st = self.os.stat(path)
    # 200 is the current time established in setUp().
    self.assertEqual(200, st.st_atime)
    self.assertEqual(200, st.st_mtime)
    # actual tests
    self.os.utime(path, None)
    st = self.os.stat(path)
    self.assertEqual(220, st.st_atime)
    self.assertEqual(240, st.st_mtime)

  def testUtimeSetsCurrentTimeIfArgsIsNoneWithFloats(self):
    # set up
    # time.time can report back floats, but it should be converted to ints
    # since atime/ctime/mtime are all defined as seconds since epoch.
    time.time = _GetDummyTime(200.0123, 20)
    path = '/some_file'
    self._CreateTestFile(path)
    st = self.os.stat(path)
    # 200 is the current time established above (if converted to int).
    self.assertEqual(200, st.st_atime)
    self.assertEqual(200, st.st_mtime)
    # actual tests
    self.os.utime(path, None)
    st = self.os.stat(path)
    self.assertEqual(220, st.st_atime)
    self.assertEqual(240, st.st_mtime)

  def testUtimeSetsSpecifiedTime(self):
    # set up
    path = '/some_file'
    self._CreateTestFile(path)
    st = self.os.stat(path)
    # actual tests
    self.os.utime(path, (1, 2))
    st = self.os.stat(path)
    self.assertEqual(1, st.st_atime)
    self.assertEqual(2, st.st_mtime)

  def testUtimeDir(self):
    # set up
    path = '/some_dir'
    self._CreateTestDirectory(path)
    # actual tests
    self.os.utime(path, (1.0, 2.0))
    st = self.os.stat(path)
    self.assertEqual(1.0, st.st_atime)
    self.assertEqual(2.0, st.st_mtime)

  def testUtimeNonExistent(self):
    # set up
    path = '/non/existent/file'
    self.assertFalse(self.filesystem.Exists(path))
    # actual tests
    try:
      # Use try-catch to check exception attributes.
      self.os.utime(path, (1, 2))
      self.fail('Exception is expected.')  # COV_NF_LINE
    except OSError as os_error:
      self.assertEqual(errno.ENOENT, os_error.errno)
      self.assertEqual(path, os_error.filename)

  def testUtimeTupleArgIsOfIncorrectLength(self):
    # set up
    path = '/some_dir'
    self._CreateTestDirectory(path)
    # actual tests
    self.assertRaisesWithRegexpMatch(
        TypeError, r'utime\(\) arg 2 must be a tuple \(atime, mtime\)',
        self.os.utime, path, (1, 2, 3))

  def testUtimeTupleArgContainsIncorrectType(self):
    # set up
    path = '/some_dir'
    self._CreateTestDirectory(path)
    # actual tests
    self.assertRaisesWithRegexpMatch(
        TypeError, 'an integer is required',
        self.os.utime, path, (1, 'str'))

  def testChownExistingFile(self):
    # set up
    file_path = 'some_file'
    self.filesystem.CreateFile(file_path)
    # first set it make sure it's set
    self.os.chown(file_path, 100, 100)
    st = self.os.stat(file_path)
    self.assertEqual(st[stat.ST_UID], 100)
    self.assertEqual(st[stat.ST_GID], 100)
    # we can make sure it changed
    self.os.chown(file_path, 200, 200)
    st = self.os.stat(file_path)
    self.assertEqual(st[stat.ST_UID], 200)
    self.assertEqual(st[stat.ST_GID], 200)
    # setting a value to -1 leaves it unchanged
    self.os.chown(file_path, -1, -1)
    st = self.os.stat(file_path)
    self.assertEqual(st[stat.ST_UID], 200)
    self.assertEqual(st[stat.ST_GID], 200)

  def testChownNonexistingFileShouldRaiseOsError(self):
    file_path = 'some_file'
    self.assertFalse(self.filesystem.Exists(file_path))
    self.assertRaises(OSError, self.os.chown, file_path, 100, 100)

  def testClassifyDirectoryContents(self):
    """Directory classification should work correctly."""
    root_directory = '/foo'
    test_directories = ['bar1', 'baz2']
    test_files = ['baz1', 'bar2', 'baz3']
    self.filesystem.CreateDirectory(root_directory)
    for directory in test_directories:
      directory = self.os.path.join(root_directory, directory)
      self.filesystem.CreateDirectory(directory)
    for test_file in test_files:
      test_file = self.os.path.join(root_directory, test_file)
      self.filesystem.CreateFile(test_file)

    test_directories.sort()
    test_files.sort()
    generator = self.os.walk(root_directory)
    root, dirs, files = next(generator)
    dirs.sort()
    files.sort()
    self.assertEqual(root_directory, root)
    self.assertEqual(test_directories, dirs)
    self.assertEqual(test_files, files)

  def testClassifyDoesNotHideExceptions(self):
    """_ClassifyDirectoryContents should not hide exceptions."""
    directory = '/foo'
    self.assertEqual(False, self.filesystem.Exists(directory))
    self.assertRaises(OSError, self.os._ClassifyDirectoryContents, directory)

  def testWalkTopDown(self):
    """Walk down ordering is correct."""
    self.filesystem.CreateFile('foo/1.txt')
    self.filesystem.CreateFile('foo/bar1/2.txt')
    self.filesystem.CreateFile('foo/bar1/baz/3.txt')
    self.filesystem.CreateFile('foo/bar2/4.txt')
    expected = [
        ('foo', ['bar1', 'bar2'], ['1.txt']),
        ('foo/bar1', ['baz'], ['2.txt']),
        ('foo/bar1/baz', [], ['3.txt']),
        ('foo/bar2', [], ['4.txt']),
        ]
    self.assertEqual(expected, [step for step in self.os.walk('foo')])

  def testWalkBottomUp(self):
    """Walk up ordering is correct."""
    self.filesystem.CreateFile('foo/bar1/baz/1.txt')
    self.filesystem.CreateFile('foo/bar1/2.txt')
    self.filesystem.CreateFile('foo/bar2/3.txt')
    self.filesystem.CreateFile('foo/4.txt')

    expected = [
        ('foo/bar1/baz', [], ['1.txt']),
        ('foo/bar1', ['baz'], ['2.txt']),
        ('foo/bar2', [], ['3.txt']),
        ('foo', ['bar1', 'bar2'], ['4.txt']),
        ]
    self.assertEqual(expected,
                     [step for step in self.os.walk('foo', topdown=False)])

  def testWalkRaisesIfNonExistent(self):
    """Raises an exception when attempting to walk non-existent directory."""
    directory = '/foo/bar'
    self.assertEqual(False, self.filesystem.Exists(directory))
    generator = self.os.walk(directory)
    self.assertRaises(StopIteration, next, generator)

  def testWalkRaisesIfNotDirectory(self):
    """Raises an exception when attempting to walk a non-directory."""
    filename = '/foo/bar'
    self.filesystem.CreateFile(filename)
    generator = self.os.walk(filename)
    self.assertRaises(StopIteration, next, generator)

  def testMkNodeCanCreateAFile(self):
    filename = 'foo'
    self.assertFalse(self.filesystem.Exists(filename))
    self.os.mknod(filename)
    self.assertTrue(self.filesystem.Exists(filename))

  def testMkNodeRaisesIfEmptyFileName(self):
    filename = ''
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMkNodeRaisesIfParentDirDoesntExist(self):
    parent = 'xyzzy'
    filename = '%s/foo' % (parent,)
    self.assertFalse(self.filesystem.Exists(parent))
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMkNodeRaisesIfFileExists(self):
    filename = '/tmp/foo'
    self.filesystem.CreateFile(filename)
    self.assertTrue(self.filesystem.Exists(filename))
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMkNodeRaisesIfFilenameIsDot(self):
    filename = '/tmp/.'
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMkNodeRaisesIfFilenameIsDoubleDot(self):
    filename = '/tmp/..'
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMknodEmptyTailForExistingFileRaises(self):
    filename = '/tmp/foo'
    self.filesystem.CreateFile(filename)
    self.assertTrue(self.filesystem.Exists(filename))
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMknodEmptyTailForNonexistentFileRaises(self):
    filename = '/tmp/foo'
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMknodRaisesIfFilenameIsEmptyString(self):
    filename = ''
    self.assertRaises(OSError, self.os.mknod, filename)

  def testMknodeRaisesIfUnsupportedOptions(self):
    filename = 'abcde'
    self.assertRaises(OSError, self.os.mknod, filename,
                      mode=stat.S_IFCHR)

  def testMknodeRaisesIfParentIsNotADirectory(self):
    filename1 = '/tmp/foo'
    self.filesystem.CreateFile(filename1)
    self.assertTrue(self.filesystem.Exists(filename1))
    filename2 = '/tmp/foo/bar'
    self.assertRaises(OSError, self.os.mknod, filename2)

  def ResetErrno(self):
    """Reset the last seen errno."""
    self.last_errno = False

  def StoreErrno(self, os_error):
    """Store the last errno we saw."""
    self.last_errno = os_error.errno

  def GetErrno(self):
    """Return the last errno we saw."""
    return self.last_errno

  def testWalkCallsOnErrorIfNonExistent(self):
    """Calls onerror with correct errno when walking non-existent directory."""
    self.ResetErrno()
    directory = '/foo/bar'
    self.assertEqual(False, self.filesystem.Exists(directory))
    # Calling os.walk on a non-existent directory should trigger a call to the
    # onerror method.  We do not actually care what, if anything, is returned.
    for unused_entry in self.os.walk(directory, onerror=self.StoreErrno):
      pass
    self.assertTrue(self.GetErrno() in (errno.ENOTDIR, errno.ENOENT))

  def testWalkCallsOnErrorIfNotDirectory(self):
    """Calls onerror with correct errno when walking non-directory."""
    self.ResetErrno()
    filename = '/foo/bar'
    self.filesystem.CreateFile(filename)
    self.assertEqual(True, self.filesystem.Exists(filename))
    # Calling os.walk on a file should trigger a call to the onerror method.
    # We do not actually care what, if anything, is returned.
    for unused_entry in self.os.walk(filename, onerror=self.StoreErrno):
      pass
    self.assertTrue(self.GetErrno() in (errno.ENOTDIR, errno.EACCES))

  def testWalkSkipsRemovedDirectories(self):
    """Caller can modify list of directories to visit while walking."""
    root = '/foo'
    visit = 'visit'
    no_visit = 'no_visit'
    self.filesystem.CreateFile('%s/bar' % (root,))
    self.filesystem.CreateFile('%s/%s/1.txt' % (root, visit))
    self.filesystem.CreateFile('%s/%s/2.txt' % (root, visit))
    self.filesystem.CreateFile('%s/%s/3.txt' % (root, no_visit))
    self.filesystem.CreateFile('%s/%s/4.txt' % (root, no_visit))

    generator = self.os.walk('/foo')
    root_contents = next(generator)
    root_contents[1].remove(no_visit)

    visited_visit_directory = False

    for root, unused_dirs, unused_files in iter(generator):
      self.assertEqual(False, root.endswith('/%s' % (no_visit)))
      if root.endswith('/%s' % (visit)):
        visited_visit_directory = True

    self.assertEqual(True, visited_visit_directory)

  def testSymlink(self):
    file_path = 'foo/bar/baz'
    self.os.symlink('bogus', file_path)
    self.assertTrue(self.os.path.lexists(file_path))
    self.assertFalse(self.os.path.exists(file_path))
    self.filesystem.CreateFile('foo/bar/bogus')
    self.assertTrue(self.os.path.lexists(file_path))
    self.assertTrue(self.os.path.exists(file_path))

  def testUMask(self):
    umask = os.umask(0o22)
    os.umask(umask)
    self.assertEqual(umask, self.os.umask(0o22))

  def testMkdirUmaskApplied(self):
    """mkdir creates a directory with umask applied."""
    self.os.umask(0o22)
    self.os.mkdir('dir1')
    self.assertModeEqual(0o755, self.os.stat('dir1').st_mode)
    self.os.umask(0o67)
    self.os.mkdir('dir2')
    self.assertModeEqual(0o710, self.os.stat('dir2').st_mode)

  def testMakedirsUmaskApplied(self):
    """makedirs creates a directories with umask applied."""
    self.os.umask(0o22)
    self.os.makedirs('/p1/dir1')
    self.assertModeEqual(0o755, self.os.stat('/p1').st_mode)
    self.assertModeEqual(0o755, self.os.stat('/p1/dir1').st_mode)
    self.os.umask(0o67)
    self.os.makedirs('/p2/dir2')
    self.assertModeEqual(0o710, self.os.stat('/p2').st_mode)
    self.assertModeEqual(0o710, self.os.stat('/p2/dir2').st_mode)

  def testMknodeUmaskApplied(self):
    """mkdir creates a device with umask applied."""
    self.os.umask(0o22)
    self.os.mknod('nod1')
    self.assertModeEqual(0o644, self.os.stat('nod1').st_mode)
    self.os.umask(0o27)
    self.os.mknod('nod2')
    self.assertModeEqual(0o640, self.os.stat('nod2').st_mode)

  def testOpenUmaskApplied(self):
    """open creates a file with umask applied."""
    fake_open = fake_filesystem.FakeFileOpen(self.filesystem)
    self.os.umask(0o22)
    fake_open('file1', 'w').close()
    self.assertModeEqual(0o644, self.os.stat('file1').st_mode)
    self.os.umask(0o27)
    fake_open('file2', 'w').close()
    self.assertModeEqual(0o640, self.os.stat('file2').st_mode)


class StatPropagationTest(TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.open = fake_filesystem.FakeFileOpen(self.filesystem)

  def testFileSizeUpdatedViaClose(self):
    """test that file size gets updated via close()."""
    file_dir = 'xyzzy'
    file_path = 'xyzzy/close'
    content = 'This is a test.'
    self.os.mkdir(file_dir)
    fh = self.open(file_path, 'w')
    self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual('', self.filesystem.GetObject(file_path).contents)
    fh.write(content)
    self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual('', self.filesystem.GetObject(file_path).contents)
    fh.close()
    self.assertEqual(len(content), self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual(content, self.filesystem.GetObject(file_path).contents)

  def testFileSizeNotResetAfterClose(self):
    file_dir = 'xyzzy'
    file_path = 'xyzzy/close'
    self.os.mkdir(file_dir)
    size = 1234
    # The file has size, but no content. When the file is opened for reading,
    # its size should be preserved.
    self.filesystem.CreateFile(file_path, st_size=size)
    fh = self.open(file_path, 'r')
    fh.close()
    self.assertEqual(size, self.open(file_path, 'r').Size())

  def testFileSizeAfterWrite(self):
    file_path = 'test_file'
    original_content = 'abcdef'
    original_size = len(original_content)
    self.filesystem.CreateFile(file_path, contents=original_content)
    added_content = 'foo bar'
    expected_size = original_size + len(added_content)
    fh = self.open(file_path, 'a')
    fh.write(added_content)
    self.assertEqual(expected_size, fh.Size())
    fh.close()
    self.assertEqual(expected_size, self.open(file_path, 'r').Size())

  def testLargeFileSizeAfterWrite(self):
    file_path = 'test_file'
    original_content = 'abcdef'
    original_size = len(original_content)
    self.filesystem.CreateFile(file_path, st_size=original_size)
    added_content = 'foo bar'
    fh = self.open(file_path, 'a')
    # We can't use assertRaises, because the exception is thrown
    # in __getattr__, so just saying 'fh.write' causes the exception.
    try:
      fh.write(added_content)
    except fake_filesystem.FakeLargeFileIoException:
      return
    self.fail('Writing to a large file should not be allowed')

  def testFileSizeUpdatedViaFlush(self):
    """test that file size gets updated via flush()."""
    file_dir = 'xyzzy'
    file_name = 'flush'
    file_path = self.os.path.join(file_dir, file_name)
    content = 'This might be a test.'
    self.os.mkdir(file_dir)
    fh = self.open(file_path, 'w')
    self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual('', self.filesystem.GetObject(file_path).contents)
    fh.write(content)
    self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual('', self.filesystem.GetObject(file_path).contents)
    fh.flush()
    self.assertEqual(len(content), self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual(content, self.filesystem.GetObject(file_path).contents)
    fh.close()
    self.assertEqual(len(content), self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual(content, self.filesystem.GetObject(file_path).contents)

  def testFileSizeTruncation(self):
    """test that file size gets updated via open()."""
    file_dir = 'xyzzy'
    file_path = 'xyzzy/truncation'
    content = 'AAA content.'

    # pre-create file with content
    self.os.mkdir(file_dir)
    fh = self.open(file_path, 'w')
    fh.write(content)
    fh.close()
    self.assertEqual(len(content), self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual(content, self.filesystem.GetObject(file_path).contents)

    # test file truncation
    fh = self.open(file_path, 'w')
    self.assertEqual(0, self.os.stat(file_path)[stat.ST_SIZE])
    self.assertEqual('', self.filesystem.GetObject(file_path).contents)
    fh.close()


class OsPathInjectionRegressionTest(TestCase):
  """Test faking os.path before calling os.walk.

  Found when investigating a problem with
  gws/tools/labrat/rat_utils_unittest, which was faking out os.path
  before calling os.walk.
  """

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.os_path = os.path
    # The bug was that when os.path gets faked, the FakePathModule doesn't get
    # called in self.os.walk().  FakePathModule now insists that it is created
    # as part of FakeOsModule.
    self.os = fake_filesystem.FakeOsModule(self.filesystem)

  def tearDown(self):
    os.path = self.os_path

  def testCreateTopLevelDirectory(self):
    top_level_dir = '/x'
    self.assertFalse(self.filesystem.Exists(top_level_dir))
    self.filesystem.CreateDirectory(top_level_dir)
    self.assertTrue(self.filesystem.Exists('/'))
    self.assertTrue(self.filesystem.Exists(top_level_dir))
    self.filesystem.CreateDirectory('%s/po' % top_level_dir)
    self.filesystem.CreateFile('%s/po/control' % top_level_dir)
    self.filesystem.CreateFile('%s/po/experiment' % top_level_dir)
    self.filesystem.CreateDirectory('%s/gv' % top_level_dir)
    self.filesystem.CreateFile('%s/gv/control' % top_level_dir)

    expected = [
        ('/', ['x'], []),
        ('/x', ['gv', 'po'], []),
        ('/x/gv', [], ['control']),
        ('/x/po', [], ['control', 'experiment']),
        ]
    self.assertEqual(expected, [step for step in self.os.walk('/')])


class FakePathModuleTest(TestCase):
  def setUp(self):
    self.orig_time = time.time
    time.time = _GetDummyTime(10, 1)
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.path = self.os.path

  def tearDown(self):
    time.time = self.orig_time

  def testAbspath(self):
    """abspath should return a consistent representation of a file."""
    filename = 'foo'
    abspath = '/%s' % filename
    self.filesystem.CreateFile(abspath)
    self.assertEqual(abspath, self.path.abspath(abspath))
    self.assertEqual(abspath, self.path.abspath(filename))
    self.assertEqual(abspath, self.path.abspath('../%s' % filename))

  def testAbspathDealsWithRelativeNonRootPath(self):
    """abspath should correctly handle relative paths from a non-/ directory.

    This test is distinct from the basic functionality test because
    fake_filesystem has historically been based in /.
    """
    filename = '/foo/bar/baz'
    file_components = filename.split(self.path.sep)
    basedir = '/%s' % (file_components[0],)
    self.filesystem.CreateFile(filename)
    self.os.chdir(basedir)
    self.assertEqual(basedir, self.path.abspath(self.path.curdir))
    self.assertEqual('/', self.path.abspath('..'))
    self.assertEqual(self.path.join(basedir, file_components[1]),
                     self.path.abspath(file_components[1]))

  def testRelpath(self):
    path_foo = '/path/to/foo'
    path_bar = '/path/to/bar'
    path_other = '/some/where/else'
    self.assertRaises(ValueError, self.path.relpath, None)
    self.assertRaises(ValueError, self.path.relpath, '')
    self.assertEqual(path_foo[1:],
                     self.path.relpath(path_foo))
    self.assertEqual('../foo',
                     self.path.relpath(path_foo, path_bar))
    self.assertEqual('../../..%s' % path_other,
                     self.path.relpath(path_other, path_bar))
    self.assertEqual('.',
                     self.path.relpath(path_bar, path_bar))

  @unittest.skipIf(TestCase.is_windows, 'realpath does not follow symlinks in win32')
  def testRealpathVsAbspath(self):
    self.filesystem.CreateFile('/george/washington/bridge')
    self.filesystem.CreateLink('/first/president', '/george/washington')
    self.assertEqual('/first/president/bridge',
                     self.os.path.abspath('/first/president/bridge'))
    self.assertEqual('/george/washington/bridge',
                     self.os.path.realpath('/first/president/bridge'))
    self.os.chdir('/first/president')
    self.assertEqual('/george/washington/bridge',
                     self.os.path.realpath('bridge'))

  def testExists(self):
    file_path = 'foo/bar/baz'
    self.filesystem.CreateFile(file_path)
    self.assertTrue(self.path.exists(file_path))
    self.assertFalse(self.path.exists('/some/other/bogus/path'))

  def testLexists(self):
    file_path = 'foo/bar/baz'
    self.filesystem.CreateDirectory('foo/bar')
    self.filesystem.CreateLink(file_path, 'bogus')
    self.assertTrue(self.path.lexists(file_path))
    self.assertFalse(self.path.exists(file_path))
    self.filesystem.CreateFile('foo/bar/bogus')
    self.assertTrue(self.path.exists(file_path))

  def testDirname(self):
    dirname = 'foo/bar'
    self.assertEqual(dirname, self.path.dirname('%s/baz' % dirname))

  def testJoin(self):
    components = ['foo', 'bar', 'baz']
    self.assertEqual('foo/bar/baz', self.path.join(*components))

  def testExpandUser(self):
    if self.is_windows:
      self.assertEqual(self.path.expanduser('~'),
                       self.os.environ['USERPROFILE'].replace('\\', '/'))
    else:
      self.assertEqual(self.path.expanduser('~'),
                       self.os.environ['HOME'])

  @unittest.skipIf(TestCase.is_windows or TestCase.is_cygwin,
                   'only tested on unix systems')
  def testExpandRoot(self):
      self.assertEqual('/root', self.path.expanduser('~root'))

  def testGetsizePathNonexistent(self):
    file_path = 'foo/bar/baz'
    self.assertRaises(IOError, self.path.getsize, file_path)

  def testGetsizeFileEmpty(self):
    file_path = 'foo/bar/baz'
    self.filesystem.CreateFile(file_path)
    self.assertEqual(0, self.path.getsize(file_path))

  def testGetsizeFileNonZeroSize(self):
    file_path = 'foo/bar/baz'
    self.filesystem.CreateFile(file_path, contents='1234567')
    self.assertEqual(7, self.path.getsize(file_path))

  def testGetsizeDirEmpty(self):
    # For directories, only require that the size is non-negative.
    dir_path = 'foo/bar'
    self.filesystem.CreateDirectory(dir_path)
    size = self.path.getsize(dir_path)
    self.assertFalse(int(size) < 0,
                     'expected non-negative size; actual: %s' % size)

  def testGetsizeDirNonZeroSize(self):
    # For directories, only require that the size is non-negative.
    dir_path = 'foo/bar'
    self.filesystem.CreateFile(self.filesystem.JoinPaths(dir_path, 'baz'))
    size = self.path.getsize(dir_path)
    self.assertFalse(int(size) < 0,
                     'expected non-negative size; actual: %s' % size)

  def testIsdir(self):
    self.filesystem.CreateFile('foo/bar')
    self.assertTrue(self.path.isdir('foo'))
    self.assertFalse(self.path.isdir('foo/bar'))
    self.assertFalse(self.path.isdir('it_dont_exist'))

  def testIsdirWithCwdChange(self):
    self.filesystem.CreateFile('/foo/bar/baz')
    self.assertTrue(self.path.isdir('/foo'))
    self.assertTrue(self.path.isdir('/foo/bar'))
    self.assertTrue(self.path.isdir('foo'))
    self.assertTrue(self.path.isdir('foo/bar'))
    self.filesystem.cwd = '/foo'
    self.assertTrue(self.path.isdir('/foo'))
    self.assertTrue(self.path.isdir('/foo/bar'))
    self.assertTrue(self.path.isdir('bar'))

  def testIsfile(self):
    self.filesystem.CreateFile('foo/bar')
    self.assertFalse(self.path.isfile('foo'))
    self.assertTrue(self.path.isfile('foo/bar'))
    self.assertFalse(self.path.isfile('it_dont_exist'))

  def testGetMtime(self):
    test_file = self.filesystem.CreateFile('foo/bar1.txt')
    # The root directory ('', effectively '/') is created at time 10,
    # the parent directory ('foo') at time 11, and the file at time 12.
    self.assertEqual(12, test_file.st_mtime)
    test_file.SetMTime(24)
    self.assertEqual(24, self.path.getmtime('foo/bar1.txt'))

  def testGetMtimeRaisesOSError(self):
    self.assertFalse(self.path.exists('it_dont_exist'))
    self.assertRaises(OSError, self.path.getmtime, 'it_dont_exist')

  def testIslink(self):
    self.filesystem.CreateDirectory('foo')
    self.filesystem.CreateFile('foo/regular_file')
    self.filesystem.CreateLink('foo/link_to_file', 'regular_file')
    self.assertFalse(self.path.islink('foo'))

    # An object can be both a link and a file or file, according to the
    # comments in Python/Lib/posixpath.py.
    self.assertTrue(self.path.islink('foo/link_to_file'))
    self.assertTrue(self.path.isfile('foo/link_to_file'))

    self.assertTrue(self.path.isfile('foo/regular_file'))
    self.assertFalse(self.path.islink('foo/regular_file'))

    self.assertFalse(self.path.islink('it_dont_exist'))

  @unittest.skipIf(sys.version_info >= (3, 0) or TestCase.is_windows,
                   'os.path.walk deprecrated in Python 3, cannot be properly '
                   'tested in win32')
  def testWalk(self):
    self.filesystem.CreateFile('/foo/bar/baz')
    self.filesystem.CreateFile('/foo/bar/xyzzy/plugh')
    visited_nodes = []

    def RecordVisitedNodes(visited, dirname, fnames):
      visited.extend(((dirname, fname) for fname in fnames))

    self.path.walk('/foo', RecordVisitedNodes, visited_nodes)
    expected = [('/foo', 'bar'),
                ('/foo/bar', 'baz'),
                ('/foo/bar', 'xyzzy'),
                ('/foo/bar/xyzzy', 'plugh')]
    self.assertEqual(expected, visited_nodes)

  @unittest.skipIf(sys.version_info >= (3, 0) or TestCase.is_windows,
                   'os.path.walk deprecrated in Python 3, cannot be properly '
                   'tested in win32')
  def testWalkFromNonexistentTopDoesNotThrow(self):
    visited_nodes = []

    def RecordVisitedNodes(visited, dirname, fnames):
      visited.extend(((dirname, fname) for fname in fnames))

    self.path.walk('/foo', RecordVisitedNodes, visited_nodes)
    self.assertEqual([], visited_nodes)


class FakeFileOpenTestBase(TestCase):
  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.file = fake_filesystem.FakeFileOpen(self.filesystem)
    self.open = self.file
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.orig_time = time.time
    time.time = _GetDummyTime(100, 10)

  def tearDown(self):
    time.time = self.orig_time


class FakeFileOpenTest(FakeFileOpenTestBase):
  def testOpenNoParentDir(self):
    """Expect raise when open'ing a file in a missing directory."""
    file_path = 'foo/bar.txt'
    self.assertRaises(IOError, self.file, file_path, 'w')

  def testDeleteOnClose(self):
    file_dir = 'boo'
    file_path = 'boo/far'
    self.os.mkdir(file_dir)
    self.file = fake_filesystem.FakeFileOpen(self.filesystem,
                                             delete_on_close=True)
    fh = self.file(file_path, 'w')
    self.assertTrue(self.filesystem.Exists(file_path))
    fh.close()
    self.assertFalse(self.filesystem.Exists(file_path))

  def testNoDeleteOnCloseByDefault(self):
    file_dir = 'boo'
    file_path = 'boo/czar'
    self.file = fake_filesystem.FakeFileOpen(self.filesystem)
    self.os.mkdir(file_dir)
    fh = self.file(file_path, 'w')
    self.assertTrue(self.filesystem.Exists(file_path))
    fh.close()
    self.assertTrue(self.filesystem.Exists(file_path))

  def testCompatibilityOfWithStatement(self):
    self.file = fake_filesystem.FakeFileOpen(self.filesystem,
                                             delete_on_close=True)
    file_path = 'foo'
    self.assertFalse(self.filesystem.Exists(file_path))
    with self.file(file_path, 'w') as _:
      self.assertTrue(self.filesystem.Exists(file_path))
    # After the 'with' statement, the close() method should have been called.
    self.assertFalse(self.filesystem.Exists(file_path))

  def testOpenValidFile(self):
    contents = [
        'I am he as\n',
        'you are he as\n',
        'you are me and\n',
        'we are all together\n'
        ]
    file_path = 'foo/bar.txt'
    self.filesystem.CreateFile(file_path, contents=''.join(contents))
    self.assertEqual(contents, self.file(file_path).readlines())

  def testOpenValidArgs(self):
    contents = [
        "Bang bang Maxwell's silver hammer\n",
        'Came down on her head',
        ]
    file_path = 'abbey_road/maxwell'
    self.filesystem.CreateFile(file_path, contents=''.join(contents))
    self.assertEqual(
        contents, self.open(file_path, mode='r', buffering=1).readlines())
    if sys.version_info >= (3, 0):
      self.assertEqual(
          contents, self.open(file_path, mode='r', buffering=1,
                              encoding='utf-8', errors='strict', newline='\n',
                              closefd=False, opener=False).readlines())

  @unittest.skipIf(sys.version_info < (3, 0), 'only tested on 3.0 or greater')
  def testOpenNewlineArg(self):
    file_path = 'some_file'
    file_contents = 'two\r\nlines'
    self.filesystem.CreateFile(file_path, contents=file_contents)
    fake_file = self.open(file_path, mode='r', newline=None)
    self.assertEqual(['two\n', 'lines'], fake_file.readlines())
    fake_file = self.open(file_path, mode='r', newline='')
    self.assertEqual(['two\r\n', 'lines'], fake_file.readlines())
    fake_file = self.open(file_path, mode='r', newline='\r')
    self.assertEqual(['two\r', '\r', 'lines'], fake_file.readlines())
    fake_file = self.open(file_path, mode='r', newline='\n')
    self.assertEqual(['two\r\n', 'lines'], fake_file.readlines())
    fake_file = self.open(file_path, mode='r', newline='\r\n')
    self.assertEqual(['two\r\r\n', 'lines'], fake_file.readlines())

  def testOpenValidFileWithCwd(self):
    contents = [
        'I am he as\n',
        'you are he as\n',
        'you are me and\n',
        'we are all together\n'
        ]
    file_path = '/foo/bar.txt'
    self.filesystem.CreateFile(file_path, contents=''.join(contents))
    self.filesystem.cwd = '/foo'
    self.assertEqual(contents, self.file(file_path).readlines())

  def testIterateOverFile(self):
    contents = [
        "Bang bang Maxwell's silver hammer",
        'Came down on her head',
        ]
    file_path = 'abbey_road/maxwell'
    self.filesystem.CreateFile(file_path, contents='\n'.join(contents))
    result = [line.rstrip() for line in self.file(file_path)]
    self.assertEqual(contents, result)

  def testOpenDirectoryError(self):
    directory_path = 'foo/bar'
    self.filesystem.CreateDirectory(directory_path)
    self.assertRaises(IOError, self.file.__call__, directory_path)

  def testCreateFileWithWrite(self):
    contents = [
        "Here comes the sun, little darlin'",
        'Here comes the sun, and I say,',
        "It's alright",
        ]
    file_dir = 'abbey_road'
    file_path = 'abbey_road/here_comes_the_sun'
    self.os.mkdir(file_dir)
    fake_file = self.file(file_path, 'w')
    for line in contents:
      fake_file.write(line + '\n')
    fake_file.close()
    result = [line.rstrip() for line in self.file(file_path)]
    self.assertEqual(contents, result)

  def testCreateFileWithAppend(self):
    contents = [
        "Here comes the sun, little darlin'",
        'Here comes the sun, and I say,',
        "It's alright",
        ]
    file_dir = 'abbey_road'
    file_path = 'abbey_road/here_comes_the_sun'
    self.os.mkdir(file_dir)
    fake_file = self.file(file_path, 'a')
    for line in contents:
      fake_file.write(line + '\n')
    fake_file.close()
    result = [line.rstrip() for line in self.file(file_path)]
    self.assertEqual(contents, result)

  def testOverwriteExistingFile(self):
    file_path = 'overwrite/this/file'
    self.filesystem.CreateFile(file_path, contents='To disappear')
    new_contents = [
        'Only these lines',
        'should be in the file.',
        ]
    fake_file = self.file(file_path, 'w')
    for line in new_contents:
      fake_file.write(line + '\n')
    fake_file.close()
    result = [line.rstrip() for line in self.file(file_path)]
    self.assertEqual(new_contents, result)

  def testAppendExistingFile(self):
    file_path = 'append/this/file'
    contents = [
        'Contents of original file'
        'Appended contents',
        ]
    self.filesystem.CreateFile(file_path, contents=contents[0])
    fake_file = self.file(file_path, 'a')
    for line in contents[1:]:
      fake_file.write(line + '\n')
    fake_file.close()
    result = [line.rstrip() for line in self.file(file_path)]
    self.assertEqual(contents, result)

  def testOpenWithWplus(self):
    # set up
    file_path = 'wplus_file'
    self.filesystem.CreateFile(file_path, contents='old contents')
    self.assertTrue(self.filesystem.Exists(file_path))
    fake_file = self.file(file_path, 'r')
    self.assertEqual('old contents', fake_file.read())
    fake_file.close()
    # actual tests
    fake_file = self.file(file_path, 'w+')
    fake_file.write('new contents')
    fake_file.seek(0)
    self.assertTrue('new contents', fake_file.read())
    fake_file.close()

  def testOpenWithWplusTruncation(self):
    # set up
    file_path = 'wplus_file'
    self.filesystem.CreateFile(file_path, contents='old contents')
    self.assertTrue(self.filesystem.Exists(file_path))
    fake_file = self.file(file_path, 'r')
    self.assertEqual('old contents', fake_file.read())
    fake_file.close()
    # actual tests
    fake_file = self.file(file_path, 'w+')
    fake_file.seek(0)
    self.assertEqual('', fake_file.read())
    fake_file.close()

  def testOpenWithAppendFlag(self):
    contents = [
        'I am he as\n',
        'you are he as\n',
        'you are me and\n',
        'we are all together\n'
        ]
    additional_contents = [
        'These new lines\n',
        'like you a lot.\n'
        ]
    file_path = 'append/this/file'
    self.filesystem.CreateFile(file_path, contents=''.join(contents))
    fake_file = self.file(file_path, 'a')
    self.assertRaises(IOError, fake_file.read)
    self.assertEqual('', fake_file.read(0))
    self.assertEqual('', fake_file.readline(0))
    self.assertEqual(len(''.join(contents)), fake_file.tell())
    fake_file.seek(0)
    self.assertEqual(0, fake_file.tell())
    fake_file.writelines(additional_contents)
    fake_file.close()
    result = self.file(file_path).readlines()
    self.assertEqual(contents + additional_contents, result)

  def testAppendWithAplus(self):
    # set up
    file_path = 'aplus_file'
    self.filesystem.CreateFile(file_path, contents='old contents')
    self.assertTrue(self.filesystem.Exists(file_path))
    fake_file = self.file(file_path, 'r')
    self.assertEqual('old contents', fake_file.read())
    fake_file.close()
    # actual tests
    fake_file = self.file(file_path, 'a+')
    self.assertEqual(0, fake_file.tell())
    fake_file.seek(6, 1)
    fake_file.write('new contents')
    self.assertEqual(24, fake_file.tell())
    fake_file.seek(0)
    self.assertEqual('old contentsnew contents', fake_file.read())
    fake_file.close()

  def testAppendWithAplusReadWithLoop(self):
    # set up
    file_path = 'aplus_file'
    self.filesystem.CreateFile(file_path, contents='old contents')
    self.assertTrue(self.filesystem.Exists(file_path))
    fake_file = self.file(file_path, 'r')
    self.assertEqual('old contents', fake_file.read())
    fake_file.close()
    # actual tests
    fake_file = self.file(file_path, 'a+')
    fake_file.seek(0)
    fake_file.write('new contents')
    fake_file.seek(0)
    for line in fake_file:
      self.assertEqual('old contentsnew contents', line)
    fake_file.close()

  def testReadEmptyFileWithAplus(self):
    file_path = 'aplus_file'
    fake_file = self.file(file_path, 'a+')
    self.assertEqual('', fake_file.read())
    fake_file.close()

  def testReadWithRplus(self):
    # set up
    file_path = 'rplus_file'
    self.filesystem.CreateFile(file_path, contents='old contents here')
    self.assertTrue(self.filesystem.Exists(file_path))
    fake_file = self.file(file_path, 'r')
    self.assertEqual('old contents here', fake_file.read())
    fake_file.close()
    # actual tests
    fake_file = self.file(file_path, 'r+')
    self.assertEqual('old contents here', fake_file.read())
    fake_file.seek(0)
    fake_file.write('new contents')
    fake_file.seek(0)
    self.assertEqual('new contents here', fake_file.read())
    fake_file.close()

  def testOpenStCtime(self):
    # set up
    file_path = 'some_file'
    self.assertFalse(self.filesystem.Exists(file_path))
    # tests
    fake_file = self.file(file_path, 'w')
    fake_file.close()
    st = self.os.stat(file_path)
    self.assertEqual(100, st.st_ctime)

    fake_file = self.file(file_path, 'w')
    fake_file.close()
    st = self.os.stat(file_path)
    self.assertEqual(110, st.st_ctime)

    fake_file = self.file(file_path, 'w+')
    fake_file.close()
    st = self.os.stat(file_path)
    self.assertEqual(120, st.st_ctime)

    fake_file = self.file(file_path, 'r')
    fake_file.close()
    st = self.os.stat(file_path)
    self.assertEqual(120, st.st_ctime)

  def _CreateWithPermission(self, file_path, perm_bits):
    self.filesystem.CreateFile(file_path)
    self.os.chmod(file_path, perm_bits)
    st = self.os.stat(file_path)
    self.assertModeEqual(perm_bits, st.st_mode)
    self.assertTrue(st.st_mode & stat.S_IFREG)
    self.assertFalse(st.st_mode & stat.S_IFDIR)

  def testOpenFlags700(self):
    # set up
    file_path = 'target_file'
    self._CreateWithPermission(file_path, 0o700)
    # actual tests
    self.file(file_path, 'r').close()
    self.file(file_path, 'w').close()
    self.file(file_path, 'w+').close()
    self.assertRaises(IOError, self.file, file_path, 'INV')

  def testOpenFlags400(self):
    # set up
    file_path = 'target_file'
    self._CreateWithPermission(file_path, 0o400)
    # actual tests
    self.file(file_path, 'r').close()
    self.assertRaises(IOError, self.file, file_path, 'w')
    self.assertRaises(IOError, self.file, file_path, 'w+')

  def testOpenFlags200(self):
    # set up
    file_path = 'target_file'
    self._CreateWithPermission(file_path, 0o200)
    # actual tests
    self.assertRaises(IOError, self.file, file_path, 'r')
    self.file(file_path, 'w').close()
    self.assertRaises(IOError, self.file, file_path, 'w+')

  def testOpenFlags100(self):
    # set up
    file_path = 'target_file'
    self._CreateWithPermission(file_path, 0o100)
    # actual tests 4
    self.assertRaises(IOError, self.file, file_path, 'r')
    self.assertRaises(IOError, self.file, file_path, 'w')
    self.assertRaises(IOError, self.file, file_path, 'w+')

  def testFollowLinkRead(self):
    link_path = '/foo/bar/baz'
    target = '/tarJAY'
    target_contents = 'real baz contents'
    self.filesystem.CreateFile(target, contents=target_contents)
    self.filesystem.CreateLink(link_path, target)
    self.assertEqual(target, self.os.readlink(link_path))
    fh = self.open(link_path, 'r')
    got_contents = fh.read()
    fh.close()
    self.assertEqual(target_contents, got_contents)

  def testFollowLinkWrite(self):
    link_path = '/foo/bar/TBD'
    target = '/tarJAY'
    target_contents = 'real baz contents'
    self.filesystem.CreateLink(link_path, target)
    self.assertFalse(self.filesystem.Exists(target))

    fh = self.open(link_path, 'w')
    fh.write(target_contents)
    fh.close()
    fh = self.open(target, 'r')
    got_contents = fh.read()
    fh.close()
    self.assertEqual(target_contents, got_contents)

  def testFollowIntraPathLinkWrite(self):
    # Test a link in the middle of of a file path.
    link_path = '/foo/build/local_machine/output/1'
    target = '/tmp/output/1'
    self.filesystem.CreateDirectory('/tmp/output')
    self.filesystem.CreateLink('/foo/build/local_machine', '/tmp')
    self.assertFalse(self.filesystem.Exists(link_path))
    self.assertFalse(self.filesystem.Exists(target))

    target_contents = 'real baz contents'
    fh = self.open(link_path, 'w')
    fh.write(target_contents)
    fh.close()
    fh = self.open(target, 'r')
    got_contents = fh.read()
    fh.close()
    self.assertEqual(target_contents, got_contents)

  def testFileDescriptorsForDifferentFiles(self):
    first_path = 'some_file1'
    second_path = 'some_file2'
    third_path = 'some_file3'
    self.filesystem.CreateFile(first_path, contents='contents here1')
    self.filesystem.CreateFile(second_path, contents='contents here2')
    self.filesystem.CreateFile(third_path, contents='contents here3')

    fake_file1 = self.open(first_path, 'r')
    fake_file2 = self.open(second_path, 'r')
    fake_file3 = self.open(third_path, 'r')
    self.assertEqual(0, fake_file1.fileno())
    self.assertEqual(1, fake_file2.fileno())
    self.assertEqual(2, fake_file3.fileno())

  def testFileDescriptorsForTheSameFileAreDifferent(self):
    first_path = 'some_file1'
    second_path = 'some_file2'
    self.filesystem.CreateFile(first_path, contents='contents here1')
    self.filesystem.CreateFile(second_path, contents='contents here2')

    fake_file1 = self.open(first_path, 'r')
    fake_file2 = self.open(second_path, 'r')
    fake_file1a = self.open(first_path, 'r')
    self.assertEqual(0, fake_file1.fileno())
    self.assertEqual(1, fake_file2.fileno())
    self.assertEqual(2, fake_file1a.fileno())

  def testReusedFileDescriptorsDoNotAffectOthers(self):
    first_path = 'some_file1'
    second_path = 'some_file2'
    third_path = 'some_file3'
    self.filesystem.CreateFile(first_path, contents='contents here1')
    self.filesystem.CreateFile(second_path, contents='contents here2')
    self.filesystem.CreateFile(third_path, contents='contents here3')

    fake_file1 = self.open(first_path, 'r')
    fake_file2 = self.open(second_path, 'r')
    fake_file3 = self.open(third_path, 'r')
    fake_file1a = self.open(first_path, 'r')
    self.assertEqual(0, fake_file1.fileno())
    self.assertEqual(1, fake_file2.fileno())
    self.assertEqual(2, fake_file3.fileno())
    self.assertEqual(3, fake_file1a.fileno())

    fake_file1.close()
    fake_file2.close()
    fake_file2 = self.open(second_path, 'r')
    fake_file1b = self.open(first_path, 'r')
    self.assertEqual(0, fake_file2.fileno())
    self.assertEqual(1, fake_file1b.fileno())
    self.assertEqual(2, fake_file3.fileno())
    self.assertEqual(3, fake_file1a.fileno())

  def testIntertwinedReadWrite(self):
    file_path = 'some_file'
    self.filesystem.CreateFile(file_path)
    with self.open(file_path, 'a') as writer:
      with self.open(file_path, 'r') as reader:
        writes = ['hello', 'world\n', 'somewhere\nover', 'the\n', 'rainbow']
        reads = []
        # when writes are flushes, they are piped to the reader
        for write in writes:
          writer.write(write)
          writer.flush()
          reads.append(reader.read())
          reader.flush()
        self.assertEqual(writes, reads)
        writes = ['nothing', 'to\nsee', 'here']
        reads = []
        # when writes are not flushed, the reader doesn't read anything new
        for write in writes:
          writer.write(write)
          reads.append(reader.read())
        self.assertEqual(['' for _ in writes], reads)

  def testOpenIoErrors(self):
    file_path = 'some_file'
    self.filesystem.CreateFile(file_path)

    with self.open(file_path, 'a') as fh:
      self.assertRaises(IOError, fh.read)
      self.assertRaises(IOError, fh.readlines)
    with self.open(file_path, 'w') as fh:
      self.assertRaises(IOError, fh.read)
      self.assertRaises(IOError, fh.readlines)
    with self.open(file_path, 'r') as fh:
      self.assertRaises(IOError, fh.truncate)
      self.assertRaises(IOError, fh.write, 'contents')
      self.assertRaises(IOError, fh.writelines, ['con', 'tents'])

    def _IteratorOpen(file_path, mode):
      for _ in self.open(file_path, mode):
        pass
    self.assertRaises(IOError, _IteratorOpen, file_path, 'w')
    self.assertRaises(IOError, _IteratorOpen, file_path, 'a')


class OpenWithFileDescriptorTest(FakeFileOpenTestBase):

  @unittest.skipIf(sys.version_info < (3, 0), 'only tested on 3.0 or greater')
  def testOpenWithFileDescriptor(self):
    file_path = 'this/file'
    self.filesystem.CreateFile(file_path)
    fd = self.os.open(file_path, os.O_CREAT)
    self.assertEqual(fd, self.open(fd, 'r').fileno())

  @unittest.skipIf(sys.version_info < (3, 0), 'only tested on 3.0 or greater')
  def testClosefdWithFileDescriptor(self):
    file_path = 'this/file'
    self.filesystem.CreateFile(file_path)
    fd = self.os.open(file_path, os.O_CREAT)
    fh = self.open(fd, 'r', closefd=False)
    fh.close()
    self.assertIsNotNone(self.filesystem.open_files[fd])
    fh = self.open(fd, 'r', closefd=True)
    fh.close()
    self.assertIsNone(self.filesystem.open_files[fd])


class OpenWithBinaryFlagsTest(TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.file = fake_filesystem.FakeFileOpen(self.filesystem)
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.file_path = 'some_file'
    self.file_contents = b'binary contents'
    self.filesystem.CreateFile(self.file_path, contents=self.file_contents)

  def OpenFakeFile(self, mode):
    return self.file(self.file_path, mode=mode)

  def OpenFileAndSeek(self, mode):
    fake_file = self.file(self.file_path, mode=mode)
    fake_file.seek(0, 2)
    return fake_file

  def WriteAndReopenFile(self, fake_file, mode='rb'):
    fake_file.write(self.file_contents)
    fake_file.close()
    return self.file(self.file_path, mode=mode)

  def testReadBinary(self):
    fake_file = self.OpenFakeFile('rb')
    self.assertEqual(self.file_contents, fake_file.read())

  def testWriteBinary(self):
    fake_file = self.OpenFileAndSeek('wb')
    self.assertEqual(0, fake_file.tell())
    fake_file = self.WriteAndReopenFile(fake_file, mode='rb')
    self.assertEqual(self.file_contents, fake_file.read())
    # reopen the file in text mode
    fake_file = self.OpenFakeFile('wb')
    fake_file = self.WriteAndReopenFile(fake_file, mode='r')
    self.assertEqual(self.file_contents.decode('ascii'), fake_file.read())

  def testWriteAndReadBinary(self):
    fake_file = self.OpenFileAndSeek('w+b')
    self.assertEqual(0, fake_file.tell())
    fake_file = self.WriteAndReopenFile(fake_file, mode='rb')
    self.assertEqual(self.file_contents, fake_file.read())


class OpenWithIgnoredFlagsTest(TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.file = fake_filesystem.FakeFileOpen(self.filesystem)
    self.os = fake_filesystem.FakeOsModule(self.filesystem)
    self.file_path = 'some_file'
    self.read_contents = self.file_contents = 'two\r\nlines'
    # For python 3.x, text file newlines are converted to \n
    if sys.version_info >= (3, 0):
      self.read_contents = 'two\nlines'
    self.filesystem.CreateFile(self.file_path, contents=self.file_contents)
    # It's resonable to assume the file exists at this point

  def OpenFakeFile(self, mode):
    return self.file(self.file_path, mode=mode)

  def OpenFileAndSeek(self, mode):
    fake_file = self.file(self.file_path, mode=mode)
    fake_file.seek(0, 2)
    return fake_file

  def WriteAndReopenFile(self, fake_file, mode='r'):
    fake_file.write(self.file_contents)
    fake_file.close()
    return self.file(self.file_path, mode=mode)

  def testReadText(self):
    fake_file = self.OpenFakeFile('rt')
    self.assertEqual(self.read_contents, fake_file.read())

  def testReadUniversalNewlines(self):
    fake_file = self.OpenFakeFile('rU')
    self.assertEqual(self.read_contents, fake_file.read())

  def testUniversalNewlines(self):
    fake_file = self.OpenFakeFile('U')
    self.assertEqual(self.read_contents, fake_file.read())

  def testWriteText(self):
    fake_file = self.OpenFileAndSeek('wt')
    self.assertEqual(0, fake_file.tell())
    fake_file = self.WriteAndReopenFile(fake_file)
    self.assertEqual(self.read_contents, fake_file.read())

  def testWriteAndReadTextBinary(self):
    fake_file = self.OpenFileAndSeek('w+bt')
    self.assertEqual(0, fake_file.tell())
    if sys.version_info >= (3, 0):
      self.assertRaises(TypeError, fake_file.write, self.file_contents)
    else:
      fake_file = self.WriteAndReopenFile(fake_file, mode='rb')
      self.assertEqual(self.file_contents, fake_file.read())


class OpenWithInvalidFlagsTest(FakeFileOpenTestBase):

  def testCapitalR(self):
    self.assertRaises(IOError, self.file, 'some_file', 'R')

  def testCapitalW(self):
    self.assertRaises(IOError, self.file, 'some_file', 'W')

  def testCapitalA(self):
    self.assertRaises(IOError, self.file, 'some_file', 'A')

  def testLowerU(self):
    self.assertRaises(IOError, self.file, 'some_file', 'u')

  def testLowerRw(self):
    self.assertRaises(IOError, self.file, 'some_file', 'rw')


class ResolvePathTest(FakeFileOpenTestBase):

  def __WriteToFile(self, file_name):
    fh = self.open(file_name, 'w')
    fh.write('x')
    fh.close()

  def testNoneFilepathRaisesTypeError(self):
    self.assertRaises(TypeError, self.open, None, 'w')

  def testEmptyFilepathRaisesIOError(self):
    self.assertRaises(IOError, self.open, '', 'w')

  def testNormalPath(self):
    self.__WriteToFile('foo')
    self.assertTrue(self.filesystem.Exists('foo'))

  def testLinkWithinSameDirectory(self):
    final_target = '/foo/baz'
    self.filesystem.CreateLink('/foo/bar', 'baz')
    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))
    self.assertEqual(1, self.os.stat(final_target)[stat.ST_SIZE])

  def testLinkToSubDirectory(self):
    final_target = '/foo/baz/bip'
    self.filesystem.CreateDirectory('/foo/baz')
    self.filesystem.CreateLink('/foo/bar', 'baz/bip')
    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))
    self.assertEqual(1, self.os.stat(final_target)[stat.ST_SIZE])
    self.assertTrue(self.filesystem.Exists('/foo/baz'))
    # Make sure that intermediate directory got created.
    new_dir = self.filesystem.GetObject('/foo/baz')
    self.assertTrue(stat.S_IFDIR & new_dir.st_mode)

  def testLinkToParentDirectory(self):
    final_target = '/baz/bip'
    self.filesystem.CreateDirectory('/foo')
    self.filesystem.CreateDirectory('/baz')
    self.filesystem.CreateLink('/foo/bar', '../baz')
    self.__WriteToFile('/foo/bar/bip')
    self.assertTrue(self.filesystem.Exists(final_target))
    self.assertEqual(1, self.os.stat(final_target)[stat.ST_SIZE])
    self.assertTrue(self.filesystem.Exists('/foo/bar'))

  def testLinkToAbsolutePath(self):
    final_target = '/foo/baz/bip'
    self.filesystem.CreateDirectory('/foo/baz')
    self.filesystem.CreateLink('/foo/bar', final_target)
    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))

  def testRelativeLinksWorkAfterChdir(self):
    final_target = '/foo/baz/bip'
    self.filesystem.CreateDirectory('/foo/baz')
    self.filesystem.CreateLink('/foo/bar', './baz/bip')
    self.assertEqual(final_target,
                     self.filesystem.ResolvePath('/foo/bar'))

    os_module = fake_filesystem.FakeOsModule(self.filesystem)
    self.assertTrue(os_module.path.islink('/foo/bar'))
    os_module.chdir('/foo')
    self.assertEqual('/foo', os_module.getcwd())
    self.assertTrue(os_module.path.islink('bar'))

    self.assertEqual('/foo/baz/bip',
                     self.filesystem.ResolvePath('bar'))

    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))

  def testAbsoluteLinksWorkAfterChdir(self):
    final_target = '/foo/baz/bip'
    self.filesystem.CreateDirectory('/foo/baz')
    self.filesystem.CreateLink('/foo/bar', final_target)
    self.assertEqual(final_target,
                     self.filesystem.ResolvePath('/foo/bar'))

    os_module = fake_filesystem.FakeOsModule(self.filesystem)
    self.assertTrue(os_module.path.islink('/foo/bar'))
    os_module.chdir('/foo')
    self.assertEqual('/foo', os_module.getcwd())
    self.assertTrue(os_module.path.islink('bar'))

    self.assertEqual('/foo/baz/bip',
                     self.filesystem.ResolvePath('bar'))

    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))

  def testChdirThroughRelativeLink(self):
    self.filesystem.CreateDirectory('/x/foo')
    self.filesystem.CreateDirectory('/x/bar')
    self.filesystem.CreateLink('/x/foo/bar', '../bar')
    self.assertEqual('/x/bar', self.filesystem.ResolvePath('/x/foo/bar'))

    os_module = fake_filesystem.FakeOsModule(self.filesystem)
    os_module.chdir('/x/foo')
    self.assertEqual('/x/foo', os_module.getcwd())
    self.assertEqual('/x/bar', self.filesystem.ResolvePath('bar'))

    os_module.chdir('bar')
    self.assertEqual('/x/bar', os_module.getcwd())

  def testReadLinkToLink(self):
    # Write into the final link target and read back from a file which will
    # point to that.
    self.filesystem.CreateLink('/foo/bar', 'link')
    self.filesystem.CreateLink('/foo/link', 'baz')
    self.__WriteToFile('/foo/baz')
    fh = self.open('/foo/bar', 'r')
    self.assertEqual('x', fh.read())

  def testWriteLinkToLink(self):
    final_target = '/foo/baz'
    self.filesystem.CreateLink('/foo/bar', 'link')
    self.filesystem.CreateLink('/foo/link', 'baz')
    self.__WriteToFile('/foo/bar')
    self.assertTrue(self.filesystem.Exists(final_target))

  def testMultipleLinks(self):
    final_target = '/a/link1/c/link2/e'
    self.os.makedirs('/a/link1/c/link2')

    self.filesystem.CreateLink('/a/b', 'link1')
    self.assertEqual('/a/link1', self.filesystem.ResolvePath('/a/b'))
    self.assertEqual('/a/link1/c', self.filesystem.ResolvePath('/a/b/c'))

    self.filesystem.CreateLink('/a/link1/c/d', 'link2')
    self.assertTrue(self.filesystem.Exists('/a/link1/c/d'))
    self.assertTrue(self.filesystem.Exists('/a/b/c/d'))

    final_target = '/a/link1/c/link2/e'
    self.assertFalse(self.filesystem.Exists(final_target))
    self.__WriteToFile('/a/b/c/d/e')
    self.assertTrue(self.filesystem.Exists(final_target))

  def testTooManyLinks(self):
    self.filesystem.CreateLink('/a/loop', 'loop')
    self.assertFalse(self.filesystem.Exists('/a/loop'))


class PathManipulationTests(TestCase):
  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='|')


class CollapsePathPipeSeparatorTest(PathManipulationTests):
  """Tests CollapsePath (mimics os.path.normpath) using | as path separator."""

  def testEmptyPathBecomesDotPath(self):
    self.assertEqual('.', self.filesystem.CollapsePath(''))

  def testDotPathUnchanged(self):
    self.assertEqual('.', self.filesystem.CollapsePath('.'))

  def testSlashesAreNotCollapsed(self):
    """Tests that '/' is not treated specially if the path separator is '|'.

    In particular, multiple slashes should not be collapsed.
    """
    self.assertEqual('/', self.filesystem.CollapsePath('/'))
    self.assertEqual('/////', self.filesystem.CollapsePath('/////'))

  def testRootPath(self):
    self.assertEqual('|', self.filesystem.CollapsePath('|'))

  def testMultipleSeparatorsCollapsedIntoRootPath(self):
    self.assertEqual('|', self.filesystem.CollapsePath('|||||'))

  def testAllDotPathsRemovedButOne(self):
    self.assertEqual('.', self.filesystem.CollapsePath('.|.|.|.'))

  def testAllDotPathsRemovedIfAnotherPathComponentExists(self):
    self.assertEqual('|', self.filesystem.CollapsePath('|.|.|.|'))
    self.assertEqual('foo|bar', self.filesystem.CollapsePath('foo|.|.|.|bar'))

  def testIgnoresUpLevelReferencesStartingFromRoot(self):
    self.assertEqual('|', self.filesystem.CollapsePath('|..|..|..|'))
    self.assertEqual('|', self.filesystem.CollapsePath('||..|.|..||'))
    self.assertEqual(
        '|', self.filesystem.CollapsePath('|..|..|foo|bar|..|..|'))

  def testConservesUpLevelReferencesStartingFromCurrentDirectory(self):
    self.assertEqual(
        '..|..', self.filesystem.CollapsePath('..|foo|bar|..|..|..'))

  def testCombineDotAndUpLevelReferencesInAbsolutePath(self):
    self.assertEqual(
        '|yes', self.filesystem.CollapsePath('|||||.|..|||yes|no|..|.|||'))

  def testDotsInPathCollapsesToLastPath(self):
    self.assertEqual(
        'bar', self.filesystem.CollapsePath('foo|..|bar'))
    self.assertEqual(
        'bar', self.filesystem.CollapsePath('foo|..|yes|..|no|..|bar'))


class SplitPathTest(PathManipulationTests):
  """Tests SplitPath (which mimics os.path.split) using | as path separator."""

  def testEmptyPath(self):
    self.assertEqual(('', ''), self.filesystem.SplitPath(''))

  def testNoSeparators(self):
    self.assertEqual(('', 'ab'), self.filesystem.SplitPath('ab'))

  def testSlashesDoNotSplit(self):
    """Tests that '/' is not treated specially if the path separator is '|'."""
    self.assertEqual(('', 'a/b'), self.filesystem.SplitPath('a/b'))

  def testEliminateTrailingSeparatorsFromHead(self):
    self.assertEqual(('a', 'b'), self.filesystem.SplitPath('a|b'))
    self.assertEqual(('a', 'b'), self.filesystem.SplitPath('a|||b'))
    self.assertEqual(('|a', 'b'), self.filesystem.SplitPath('|a||b'))
    self.assertEqual(('a|b', 'c'), self.filesystem.SplitPath('a|b|c'))
    self.assertEqual(('|a|b', 'c'), self.filesystem.SplitPath('|a|b|c'))

  def testRootSeparatorIsNotStripped(self):
    self.assertEqual(('|', ''), self.filesystem.SplitPath('|||'))
    self.assertEqual(('|', 'a'), self.filesystem.SplitPath('|a'))
    self.assertEqual(('|', 'a'), self.filesystem.SplitPath('|||a'))

  def testEmptyTailIfPathEndsInSeparator(self):
    self.assertEqual(('a|b', ''), self.filesystem.SplitPath('a|b|'))

  def testEmptyPathComponentsArePreservedInHead(self):
    self.assertEqual(('|a||b', 'c'), self.filesystem.SplitPath('|a||b||c'))


class JoinPathTest(PathManipulationTests):
  """Tests JoinPath (which mimics os.path.join) using | as path separator."""

  def testOneEmptyComponent(self):
    self.assertEqual('', self.filesystem.JoinPaths(''))

  def testMultipleEmptyComponents(self):
    self.assertEqual('', self.filesystem.JoinPaths('', '', ''))

  def testSeparatorsNotStrippedFromSingleComponent(self):
    self.assertEqual('||a||', self.filesystem.JoinPaths('||a||'))

  def testOneSeparatorAddedBetweenComponents(self):
    self.assertEqual('a|b|c|d', self.filesystem.JoinPaths('a', 'b', 'c', 'd'))

  def testNoSeparatorAddedForComponentsEndingInSeparator(self):
    self.assertEqual('a|b|c', self.filesystem.JoinPaths('a|', 'b|', 'c'))
    self.assertEqual('a|||b|||c',
                     self.filesystem.JoinPaths('a|||', 'b|||', 'c'))

  def testComponentsPrecedingAbsoluteComponentAreIgnored(self):
    self.assertEqual('|c|d', self.filesystem.JoinPaths('a', '|b', '|c', 'd'))

  def testOneSeparatorAddedForTrailingEmptyComponents(self):
    self.assertEqual('a|', self.filesystem.JoinPaths('a', ''))
    self.assertEqual('a|', self.filesystem.JoinPaths('a', '', ''))

  def testNoSeparatorAddedForLeadingEmptyComponents(self):
    self.assertEqual('a', self.filesystem.JoinPaths('', 'a'))

  def testInternalEmptyComponentsIgnored(self):
    self.assertEqual('a|b', self.filesystem.JoinPaths('a', '', 'b'))
    self.assertEqual('a|b|', self.filesystem.JoinPaths('a|', '', 'b|'))


class PathSeparatorTest(TestCase):
  def testOsPathSepMatchesFakeFilesystemSeparator(self):
    filesystem = fake_filesystem.FakeFilesystem(path_separator='!')
    fake_os = fake_filesystem.FakeOsModule(filesystem)
    self.assertEqual('!', fake_os.sep)
    self.assertEqual('!', fake_os.path.sep)


if __name__ == '__main__':
  main()
