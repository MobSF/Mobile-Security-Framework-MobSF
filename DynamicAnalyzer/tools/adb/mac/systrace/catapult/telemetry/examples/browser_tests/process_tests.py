# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from telemetry.testing import serially_executed_browser_test_case


class FailIfSetUpProcessCalledTwice(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):
  count = 0

  @classmethod
  def SetUpProcess(cls):
    cls.count += 1
    if cls.count >= 2:
      assert False, 'This should not be called more than once'

  @classmethod
  def GenerateTestCases_DummyTest(cls, options):
    del options  # Unused.
    for i in xrange(0, 3):
      yield 'Dummy_%i' % i, ()

  def DummyTest(self):
    pass


class FailIfTearDownProcessCalledTwice(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):
  count = 0

  @classmethod
  def TearDownProcess(cls):
    cls.count += 1
    if cls.count >= 2:
      assert False, 'This should not be called more than once'

  @classmethod
  def GenerateTestCases_DummyTest(cls, options):
    del options  # Unused.
    for i in xrange(0, 3):
      yield 'Dummy_%i' % i, ()

  def DummyTest(self):
    pass


def load_tests(loader, tests, pattern):
  del loader, tests, pattern  # Unused.
  return serially_executed_browser_test_case.LoadAllTestsInModule(
      sys.modules[__name__])
