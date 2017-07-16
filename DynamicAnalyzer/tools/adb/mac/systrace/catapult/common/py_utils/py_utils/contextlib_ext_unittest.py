# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from py_utils import contextlib_ext


class OptionalUnittest(unittest.TestCase):

  class SampleContextMgr(object):

    def __init__(self):
      self.entered = False
      self.exited = False

    def __enter__(self):
      self.entered = True

    def __exit__(self, exc_type, exc_val, exc_tb):
      self.exited = True

  def testConditionTrue(self):
    c = self.SampleContextMgr()
    with contextlib_ext.Optional(c, True):
      self.assertTrue(c.entered)
    self.assertTrue(c.exited)

  def testConditionFalse(self):
    c = self.SampleContextMgr()
    with contextlib_ext.Optional(c, False):
      self.assertFalse(c.entered)
    self.assertFalse(c.exited)
