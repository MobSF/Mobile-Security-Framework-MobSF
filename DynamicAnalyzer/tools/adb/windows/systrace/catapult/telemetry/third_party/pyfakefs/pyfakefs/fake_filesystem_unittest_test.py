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
Test the :py:class`pyfakefs.fake_filesystem_unittest.TestCase` base class.
"""

import os
import glob
import shutil
import tempfile
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import fake_filesystem_unittest
import pytest

class TestPyfakefsUnittest(fake_filesystem_unittest.TestCase): # pylint: disable=R0904
    '''Test the pyfakefs.fake_filesystem_unittest.TestCase` base class.'''

    def setUp(self):
        '''Set up the fake file system'''
        self.setUpPyfakefs()

    def tearDown(self):
        '''Tear down the fake file system'''
        self.tearDownPyfakefs()

    @unittest.skipIf(sys.version_info > (2,), "file() was removed in Python 3")
    def test_file(self):
        '''Fake `file()` function is bound'''
        self.assertFalse(os.path.exists('/fake_file.txt'))
        with file('/fake_file.txt', 'w') as f:
            f.write("This test file was created using the file() function.\n")
        self.assertTrue(self.fs.Exists('/fake_file.txt'))
        with file('/fake_file.txt') as f:
            content = f.read()
        self.assertEqual(content,
                         'This test file was created using the file() function.\n')
            
    def test_open(self):
        '''Fake `open()` function is bound'''
        self.assertFalse(os.path.exists('/fake_file.txt'))
        with open('/fake_file.txt', 'w') as f:
            f.write("This test file was created using the open() function.\n")
        self.assertTrue(self.fs.Exists('/fake_file.txt'))
        with open('/fake_file.txt') as f:
            content = f.read()
        self.assertEqual(content,
                         'This test file was created using the open() function.\n')
            
    def test_os(self):
        '''Fake os module is bound'''
        self.assertFalse(self.fs.Exists('/test/dir1/dir2'))          
        os.makedirs('/test/dir1/dir2')
        self.assertTrue(self.fs.Exists('/test/dir1/dir2'))          
        
    def test_glob(self):
        '''Fake glob module is bound'''
        self.assertCountEqual(glob.glob('/test/dir1/dir*'),
                              [])
        self.fs.CreateDirectory('/test/dir1/dir2a')
        self.assertCountEqual(glob.glob('/test/dir1/dir*'),
                              ['/test/dir1/dir2a'])
        self.fs.CreateDirectory('/test/dir1/dir2b')
        self.assertCountEqual(glob.glob('/test/dir1/dir*'),
                              ['/test/dir1/dir2a', '/test/dir1/dir2b'])

    def test_shutil(self):
        '''Fake shutil module is bound'''
        self.fs.CreateDirectory('/test/dir1/dir2a')
        self.fs.CreateDirectory('/test/dir1/dir2b')
        self.assertTrue(self.fs.Exists('/test/dir1/dir2b'))
        self.assertTrue(self.fs.Exists('/test/dir1/dir2a'))
       
        shutil.rmtree('/test/dir1')
        self.assertFalse(self.fs.Exists('/test/dir1'))

    def test_tempfile(self):
        '''Fake tempfile module is bound'''
        with tempfile.NamedTemporaryFile() as tf:
            tf.write(b'Temporary file contents\n')
            name = tf.name
            self.assertTrue(self.fs.Exists(tf.name))
    
    def test_pytest(self):
        '''Compatibility with the :py:module:`pytest` module.'''
        pass
                      
if __name__ == "__main__":
    unittest.main()
