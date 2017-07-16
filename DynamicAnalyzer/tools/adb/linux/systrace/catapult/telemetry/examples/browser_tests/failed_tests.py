# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from telemetry.testing import serially_executed_browser_test_case


class SetUpClassFailedTest(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  @classmethod
  def setUpClass(cls):
    raise Exception

  @classmethod
  def GenerateTestCases_DummyTest(cls, options):
    del options  # Unused.
    for i in xrange(0, 3):
      yield 'dummy_test_%i' % i, ()

  def DummyTest(self):
    pass


class TearDownClassFailedTest(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  @classmethod
  def tearDownClass(cls):
    raise Exception

  @classmethod
  def GenerateTestCases_DummyTest(cls, options):
    del options  # Unused.
    for i in xrange(0, 3):
      yield 'dummy_test_%i' % i, ()

  def DummyTest(self):
    pass


def load_tests(loader, tests, pattern):
  del loader, tests, pattern  # Unused.
  return serially_executed_browser_test_case.LoadAllTestsInModule(
      sys.modules[__name__])
