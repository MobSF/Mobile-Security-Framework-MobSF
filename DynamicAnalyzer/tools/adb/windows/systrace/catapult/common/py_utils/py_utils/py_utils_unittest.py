# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import sys
import unittest

import py_utils


class PathTest(unittest.TestCase):

  def testIsExecutable(self):
    self.assertFalse(py_utils.IsExecutable('nonexistent_file'))
    # We use actual files on disk instead of pyfakefs because the executable is
    # set different on win that posix platforms and pyfakefs doesn't support
    # win platform well.
    self.assertFalse(py_utils.IsExecutable(_GetFileInTestDir('foo.txt')))
    self.assertTrue(py_utils.IsExecutable(sys.executable))


def _GetFileInTestDir(file_name):
  return os.path.join(os.path.dirname(__file__), 'test_data', file_name)


class WaitForTest(unittest.TestCase):

  def testWaitForTrue(self):
    def ReturnTrue():
      return True
    self.assertTrue(py_utils.WaitFor(ReturnTrue, .1))

  def testWaitForFalse(self):
    def ReturnFalse():
      return False

    with self.assertRaises(py_utils.TimeoutException):
      py_utils.WaitFor(ReturnFalse, .1)

  def testWaitForEventuallyTrue(self):
    # Use list to pass to inner function in order to allow modifying the
    # variable from the outer scope.
    c = [0]
    def ReturnCounterBasedValue():
      c[0] += 1
      return c[0] > 2

    self.assertTrue(py_utils.WaitFor(ReturnCounterBasedValue, .5))

  def testWaitForTrueLambda(self):
    self.assertTrue(py_utils.WaitFor(lambda: True, .1))

  def testWaitForFalseLambda(self):
    with self.assertRaises(py_utils.TimeoutException):
      py_utils.WaitFor(lambda: False, .1)
