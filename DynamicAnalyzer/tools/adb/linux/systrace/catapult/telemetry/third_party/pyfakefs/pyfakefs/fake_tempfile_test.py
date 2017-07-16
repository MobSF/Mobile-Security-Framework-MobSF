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

"""Tests for the fake_tempfile module."""

#pylint: disable-all

import stat
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

try:
  import StringIO as io  # pylint: disable-msg=C6204
except ImportError:
  import io  # pylint: disable-msg=C6204

import fake_filesystem
import fake_tempfile


class FakeLogging(object):
  """Fake logging object for testGettempprefix."""

  def __init__(self, test_case):
    self._message = None
    self._test_case = test_case

  # pylint: disable-msg=C6409
  def error(self, message):
    if self._message is not None:
      self.FailOnMessage(message)
    self._message = message

  def FailOnMessage(self, message):
    self._test_case.fail('Unexpected message received: %s' % message)

  warn = FailOnMessage
  info = FailOnMessage
  debug = FailOnMessage
  fatal = FailOnMessage

  def message(self):
    return self._message


class FakeTempfileModuleTest(unittest.TestCase):
  """Test the 'tempfile' module mock."""

  def setUp(self):
    self.filesystem = fake_filesystem.FakeFilesystem(path_separator='/')
    self.tempfile = fake_tempfile.FakeTempfileModule(self.filesystem)
    self.orig_logging = fake_tempfile.logging
    self.fake_logging = FakeLogging(self)
    fake_tempfile.logging = self.fake_logging

  def tearDown(self):
    fake_tempfile.logging = self.orig_logging

  def testTempFilename(self):
    # pylint: disable-msg=C6002
    # TODO: test that tempdir is init'ed
    filename_a = self.tempfile._TempFilename()
    # expect /tmp/tmp######
    self.assertTrue(filename_a.startswith('/tmp/tmp'))
    self.assertLess(len('/tmp/tmpA'), len(filename_a))

    # see that random part changes
    filename_b = self.tempfile._TempFilename()
    self.assertTrue(filename_b.startswith('/tmp/tmp'))
    self.assertLess(len('/tmp/tmpB'), len(filename_a))
    self.assertNotEqual(filename_a, filename_b)

  def testTempFilenameSuffix(self):
    """test tempfile._TempFilename(suffix=)."""
    filename = self.tempfile._TempFilename(suffix='.suffix')
    self.assertTrue(filename.startswith('/tmp/tmp'))
    self.assertTrue(filename.endswith('.suffix'))
    self.assertLess(len('/tmp/tmpX.suffix'), len(filename))

  def testTempFilenamePrefix(self):
    """test tempfile._TempFilename(prefix=)."""
    filename = self.tempfile._TempFilename(prefix='prefix.')
    self.assertTrue(filename.startswith('/tmp/prefix.'))
    self.assertLess(len('/tmp/prefix.X'), len(filename))

  def testTempFilenameDir(self):
    """test tempfile._TempFilename(dir=)."""
    filename = self.tempfile._TempFilename(dir='/dir')
    self.assertTrue(filename.startswith('/dir/tmp'))
    self.assertLess(len('/dir/tmpX'), len(filename))

  def testTemporaryFile(self):
    obj = self.tempfile.TemporaryFile()
    self.assertEqual('<fdopen>', obj.name)
    self.assertTrue(isinstance(obj, io.StringIO))

  def testNamedTemporaryFile(self):
    obj = self.tempfile.NamedTemporaryFile()
    created_filenames = self.tempfile.FakeReturnedMktempValues()
    self.assertEqual(created_filenames[0], obj.name)
    self.assertTrue(self.filesystem.GetObject(obj.name))
    obj.close()
    self.assertRaises(IOError, self.filesystem.GetObject, obj.name)

  def testNamedTemporaryFileNoDelete(self):
    obj = self.tempfile.NamedTemporaryFile(delete=False)
    obj.write(b'foo')
    obj.close()
    file_obj = self.filesystem.GetObject(obj.name)
    self.assertEqual('foo', file_obj.contents)
    obj = self.tempfile.NamedTemporaryFile(mode='w', delete=False)
    obj.write('foo')
    obj.close()
    file_obj = self.filesystem.GetObject(obj.name)
    self.assertEqual('foo', file_obj.contents)

  def testMkstemp(self):
    next_fd = len(self.filesystem.open_files)
    temporary = self.tempfile.mkstemp()
    self.assertEqual(2, len(temporary))
    self.assertTrue(temporary[1].startswith('/tmp/tmp'))
    created_filenames = self.tempfile.FakeReturnedMktempValues()
    self.assertEqual(next_fd, temporary[0])
    self.assertEqual(temporary[1], created_filenames[0])
    self.assertTrue(self.filesystem.Exists(temporary[1]))
    self.assertEqual(self.filesystem.GetObject(temporary[1]).st_mode,
                     stat.S_IFREG|0o600)

  def testMkstempDir(self):
    """test tempfile.mkstemp(dir=)."""
    # expect fail: /dir does not exist
    self.assertRaises(OSError, self.tempfile.mkstemp, dir='/dir')
    # expect pass: /dir exists
    self.filesystem.CreateDirectory('/dir')
    next_fd = len(self.filesystem.open_files)
    temporary = self.tempfile.mkstemp(dir='/dir')
    self.assertEqual(2, len(temporary))
    self.assertEqual(next_fd, temporary[0])
    self.assertTrue(temporary[1].startswith('/dir/tmp'))
    created_filenames = self.tempfile.FakeReturnedMktempValues()
    self.assertEqual(temporary[1], created_filenames[0])
    self.assertTrue(self.filesystem.Exists(temporary[1]))
    self.assertEqual(self.filesystem.GetObject(temporary[1]).st_mode,
                     stat.S_IFREG|0o600)
    # pylint: disable-msg=C6002
    # TODO: add a test that /dir is actually writable.

  def testMkdtemp(self):
    dirname = self.tempfile.mkdtemp()
    self.assertTrue(dirname)
    created_filenames = self.tempfile.FakeReturnedMktempValues()
    self.assertEqual(dirname, created_filenames[0])
    self.assertTrue(self.filesystem.Exists(dirname))
    self.assertEqual(self.filesystem.GetObject(dirname).st_mode,
                     stat.S_IFDIR|0o700)

  def testGettempdir(self):
    self.assertEqual(None, self.tempfile.tempdir)
    self.assertEqual('/tmp', self.tempfile.gettempdir())
    self.assertEqual('/tmp', self.tempfile.tempdir)

  def testGettempprefix(self):
    """test tempfile.gettempprefix() and the tempfile.template setter."""
    self.assertEqual('tmp', self.tempfile.gettempprefix())
    # set and verify
    self.tempfile.template = 'strung'
    self.assertEqual('strung', self.tempfile.gettempprefix())
    self.assertEqual('tempfile.template= is a NOP in python2.4',
                     self.fake_logging.message())

  def testMktemp(self):
    self.assertRaises(NotImplementedError, self.tempfile.mktemp)

  def testTemplateGet(self):
    """verify tempfile.template still unimplemented."""
    self.assertRaises(NotImplementedError, getattr,
                      self.tempfile, 'template')


if __name__ == '__main__':
  unittest.main()
