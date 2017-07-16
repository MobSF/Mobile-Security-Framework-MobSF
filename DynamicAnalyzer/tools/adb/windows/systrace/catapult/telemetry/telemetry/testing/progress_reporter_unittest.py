# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.testing import progress_reporter


class TestFoo(unittest.TestCase):
  # Test method doesn't have test- prefix intentionally. This is so that
  # run_test script won't run this test.
  def RunPassingTest(self):
    pass

  def RunFailingTest(self):
    self.fail('expected failure')


class LoggingProgressReporter(object):
  def __init__(self):
    self._call_log = []

  @property
  def call_log(self):
    return tuple(self._call_log)

  def __getattr__(self, name):
    def wrapper(*_):
      self._call_log.append(name)
    return wrapper


class ProgressReporterTest(unittest.TestCase):
  def testTestRunner(self):
    suite = progress_reporter.TestSuite()
    suite.addTest(TestFoo(methodName='RunPassingTest'))
    suite.addTest(TestFoo(methodName='RunFailingTest'))

    reporter = LoggingProgressReporter()
    runner = progress_reporter.TestRunner()
    progress_reporters = (reporter,)
    result = runner.run(suite, progress_reporters, 1, None)

    self.assertEqual(len(result.successes), 1)
    self.assertEqual(len(result.failures), 1)
    self.assertEqual(len(result.failures_and_errors), 1)
    expected = (
        'StartTestRun', 'StartTestSuite',
        'StartTest', 'Success', 'StopTest',
        'StartTest', 'Failure', 'StopTest',
        'StopTestSuite', 'StopTestRun',
    )
    self.assertEqual(reporter.call_log, expected)
