#!/usr/bin/python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unittests for timeout_and_retry.py."""

import logging
import time
import unittest

from devil.utils import reraiser_thread
from devil.utils import timeout_retry


_DEFAULT_TIMEOUT = .1


class TestException(Exception):
  pass


def _CountTries(tries):
  tries[0] += 1
  raise TestException


class TestRun(unittest.TestCase):
  """Tests for timeout_retry.Run."""

  def testRun(self):
    self.assertTrue(timeout_retry.Run(
        lambda x: x, 30, 3, [True], {}))

  def testTimeout(self):
    tries = [0]

    def _sleep():
      tries[0] += 1
      time.sleep(1)

    self.assertRaises(
        reraiser_thread.TimeoutError, timeout_retry.Run, _sleep, .01, 1,
        error_log_func=logging.debug)
    self.assertEqual(tries[0], 2)

  def testRetries(self):
    tries = [0]
    self.assertRaises(
        TestException, timeout_retry.Run, lambda: _CountTries(tries),
        _DEFAULT_TIMEOUT, 3, error_log_func=logging.debug)
    self.assertEqual(tries[0], 4)

  def testNoRetries(self):
    tries = [0]
    self.assertRaises(
        TestException, timeout_retry.Run, lambda: _CountTries(tries),
        _DEFAULT_TIMEOUT, 0, error_log_func=logging.debug)
    self.assertEqual(tries[0], 1)

  def testReturnValue(self):
    self.assertTrue(timeout_retry.Run(lambda: True, _DEFAULT_TIMEOUT, 3))

  def testCurrentTimeoutThreadGroup(self):
    def InnerFunc():
      current_thread_group = timeout_retry.CurrentTimeoutThreadGroup()
      self.assertIsNotNone(current_thread_group)

      def InnerInnerFunc():
        self.assertEqual(current_thread_group,
                         timeout_retry.CurrentTimeoutThreadGroup())
        return True
      return reraiser_thread.RunAsync((InnerInnerFunc,))[0]

    self.assertTrue(timeout_retry.Run(InnerFunc, _DEFAULT_TIMEOUT, 3))


if __name__ == '__main__':
  unittest.main()
