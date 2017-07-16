# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

class SampleUnittest(unittest.TestCase):
  def testPassing(self):
    self.assertTrue(1 + 1)

  def testFailing(self):
    self.assertFalse(True or False)
