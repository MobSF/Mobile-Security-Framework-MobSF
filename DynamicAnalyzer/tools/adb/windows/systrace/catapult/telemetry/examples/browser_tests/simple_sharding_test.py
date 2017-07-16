# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from telemetry.testing import serially_executed_browser_test_case


class SimpleShardingTest(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  def Test1(self):
    pass

  def Test2(self):
    pass

  def Test3(self):
    pass

  @classmethod
  def GenerateTestCases_PassingTest(cls, options):
    del options  # unused
    for i in xrange(10):
      yield 'passing_test_' + str(i), (i,)

  def PassingTest(self, a):
    self.assertGreaterEqual(a, 0)


def load_tests(loader, tests, pattern):
  del loader, tests, pattern  # Unused.
  return serially_executed_browser_test_case.LoadAllTestsInModule(
      sys.modules[__name__])
