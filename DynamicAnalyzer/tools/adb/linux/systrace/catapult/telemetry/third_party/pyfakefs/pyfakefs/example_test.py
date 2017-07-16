#! /usr/bin/env python
#
# Copyright 2014 Altera Corporation. All Rights Reserved.
# Author: John McGehee
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

"""
Test the :py:class`pyfakefs.example` module to demonstrate the usage of the
:py:class`pyfakefs.fake_filesystem_unittest.TestCase` base class.
"""

import os
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import fake_filesystem_unittest
# The module under test is pyfakefs.example
import example


def load_tests(loader, tests, ignore):
    '''Load the pyfakefs/example.py doctest tests into unittest.'''
    return fake_filesystem_unittest.load_doctests(loader, tests, ignore, example)


class TestExample(fake_filesystem_unittest.TestCase): # pylint: disable=R0904
    '''Test the pyfakefs.example module.'''

    def setUp(self):
        '''Invoke the :py:class:`pyfakefs.fake_filesystem_unittest.TestCase`
        `self.setUp()` method.  This defines:
        
        * Attribute `self.fs`, an instance of \
          :py:class:`pyfakefs.fake_filesystem.FakeFilesystem`.  This is useful \
          for creating test files.
        * Attribute `self.stubs`, an instance of \
          :py:class:`mox.stubout.StubOutForTesting`.  Use this if you need to
          define additional stubs.
        '''
        self.setUpPyfakefs()

    def tearDown(self):
        # No longer need self.tearDownPyfakefs()
        pass
        
    def test_create_file(self):
        '''Test example.create_file()'''
        # The os module has been replaced with the fake os module so all of the
        # following occurs in the fake filesystem.
        self.assertFalse(os.path.isdir('/test'))
        os.mkdir('/test')
        self.assertTrue(os.path.isdir('/test'))
        
        self.assertFalse(os.path.exists('/test/file.txt'))
        example.create_file('/test/file.txt')
        self.assertTrue(os.path.exists('/test/file.txt'))
        
    def test_delete_file(self):
        '''Test example.delete_file()

        `self.fs.CreateFile()` is convenient because it automatically creates
        directories in the fake file system and allows you to specify the file
        contents.
        
        You could also use `open()` or `file()`.
        '''
        self.fs.CreateFile('/test/full.txt',
                           contents='First line\n'
                                    'Second Line\n')
        self.assertTrue(os.path.exists('/test/full.txt'))
        example.delete_file('/test/full.txt')
        self.assertFalse(os.path.exists('/test/full.txt'))

    def test_file_exists(self):
        '''Test example.path_exists()

        `self.fs.CreateFile()` is convenient because it automatically creates
        directories in the fake file system and allows you to specify the file
        contents.
        
        You could also use `open()` or `file()` if you wanted.
        '''
        self.assertFalse(example.path_exists('/test/empty.txt'))          
        self.fs.CreateFile('/test/empty.txt')
        self.assertTrue(example.path_exists('/test/empty.txt'))              
        
    def test_get_globs(self):
        '''Test example.get_glob()
        
        `self.fs.CreateDirectory()` creates directories.  However, you might
        prefer the familiar `os.makedirs()`, which also works fine on the fake
        file system.
        '''
        self.assertFalse(os.path.isdir('/test'))
        self.fs.CreateDirectory('/test/dir1/dir2a')
        self.assertTrue(os.path.isdir('/test/dir1/dir2a'))
        # os.mkdirs() works, too.
        os.makedirs('/test/dir1/dir2b')
        self.assertTrue(os.path.isdir('/test/dir1/dir2b'))
        
        self.assertCountEqual(example.get_glob('/test/dir1/nonexistent*'),
                              [])
        self.assertCountEqual(example.get_glob('/test/dir1/dir*'),
                              ['/test/dir1/dir2a', '/test/dir1/dir2b'])

    def test_rm_tree(self):
        '''Test example.rm_tree()
        
        `self.fs.CreateDirectory()` creates directories.  However, you might
        prefer the familiar `os.makedirs()`, which also works fine on the fake
        file system.
        '''
        self.fs.CreateDirectory('/test/dir1/dir2a')
        # os.mkdirs() works, too.
        os.makedirs('/test/dir1/dir2b')
        self.assertTrue(os.path.isdir('/test/dir1/dir2b'))
        self.assertTrue(os.path.isdir('/test/dir1/dir2a'))
       
        example.rm_tree('/test/dir1')
        self.assertFalse(os.path.exists('/test/dir1'))

if __name__ == "__main__":
    unittest.main()
