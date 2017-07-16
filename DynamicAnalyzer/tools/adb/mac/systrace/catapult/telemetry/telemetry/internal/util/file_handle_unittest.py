# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import tempfile
import unittest

from telemetry.internal.util import file_handle


class FileHandleUnittest(unittest.TestCase):

  def setUp(self):
    self.temp_file_txt = tempfile.NamedTemporaryFile(
        suffix='.txt', delete=False)
    self.abs_path_html = tempfile.NamedTemporaryFile(
        suffix='.html', delete=False).name

  def tearDown(self):
    os.remove(self.abs_path_html)

  def testCreatingFileHandle(self):
    fh1 = file_handle.FromTempFile(self.temp_file_txt)
    self.assertEquals(fh1.extension, '.txt')

    fh2 = file_handle.FromFilePath(self.abs_path_html)
    self.assertEquals(fh2.extension, '.html')
    self.assertNotEquals(fh1.id, fh2.id)
