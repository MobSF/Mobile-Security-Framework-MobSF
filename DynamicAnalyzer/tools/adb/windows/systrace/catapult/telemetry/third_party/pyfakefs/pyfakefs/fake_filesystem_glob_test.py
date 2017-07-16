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

"""Test for fake_filesystem_glob."""

import doctest
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import fake_filesystem
import fake_filesystem_glob


class FakeGlobUnitTest(unittest.TestCase):

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.glob = fake_filesystem_glob.FakeGlobModule(self.filesystem)
    directory = './xyzzy'
    self.filesystem.CreateDirectory(directory)
    self.filesystem.CreateDirectory('%s/subdir' % directory)
    self.filesystem.CreateDirectory('%s/subdir2' % directory)
    self.filesystem.CreateFile('%s/subfile' % directory)
    self.filesystem.CreateFile('[Temp]')

  def testGlobEmpty(self):
    self.assertEqual(self.glob.glob(''), [])

  def testGlobStar(self):
    self.assertEqual(['/xyzzy/subdir', '/xyzzy/subdir2', '/xyzzy/subfile'],
                     self.glob.glob('/xyzzy/*'))

  def testGlobExact(self):
    self.assertEqual(['/xyzzy'], self.glob.glob('/xyzzy'))
    self.assertEqual(['/xyzzy/subfile'], self.glob.glob('/xyzzy/subfile'))

  def testGlobQuestion(self):
    self.assertEqual(['/xyzzy/subdir', '/xyzzy/subdir2', '/xyzzy/subfile'],
                     self.glob.glob('/x?zz?/*'))

  def testGlobNoMagic(self):
    self.assertEqual(['/xyzzy'], self.glob.glob('/xyzzy'))
    self.assertEqual(['/xyzzy/subdir'], self.glob.glob('/xyzzy/subdir'))

  def testNonExistentPath(self):
    self.assertEqual([], self.glob.glob('nonexistent'))

  def testDocTest(self):
    self.assertFalse(doctest.testmod(fake_filesystem_glob)[0])

  def testMagicDir(self):
    self.assertEqual(['/[Temp]'], self.glob.glob('/*emp*'))

  def testRootGlob(self):
    self.assertEqual(['[Temp]', 'xyzzy'], self.glob.glob('*'))

  def testGlob1(self):
    self.assertEqual(['[Temp]'], self.glob.glob1('/', '*Tem*'))

  def testHasMagic(self):
    self.assertTrue(self.glob.has_magic('['))
    self.assertFalse(self.glob.has_magic('a'))


if __name__ == '__main__':
  unittest.main()
