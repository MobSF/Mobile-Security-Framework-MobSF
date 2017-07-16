# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import shutil
import tempfile
import unittest

from telemetry.core import util


class TestGetSequentialFileName(unittest.TestCase):

  def __init__(self, *args, **kwargs):
    super(TestGetSequentialFileName, self).__init__(*args, **kwargs)
    self.test_directory = None

  def setUp(self):
    self.test_directory = tempfile.mkdtemp()

  def testGetSequentialFileNameNoOtherSequentialFile(self):
    next_json_test_file_path = util.GetSequentialFileName(os.path.join(
        self.test_directory, 'test'))
    self.assertEquals(
        os.path.join(self.test_directory, 'test_000'), next_json_test_file_path)

  def testGetSequentialFileNameWithOtherSequentialFiles(self):
    # Create test_000.json, test_001.json, test_002.json in test directory.
    for i in xrange(3):
      with open(
          os.path.join(self.test_directory, 'test_%03d.json' % i), 'w') as _:
        pass
    next_json_test_file_path = util.GetSequentialFileName(os.path.join(
        self.test_directory, 'test'))
    self.assertEquals(
        os.path.join(self.test_directory, 'test_003'), next_json_test_file_path)

  def tearDown(self):
    shutil.rmtree(self.test_directory)
