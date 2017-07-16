# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import logging
import platform
import sys
import unittest

from py_trace_event import trace_time


class TimerTest(unittest.TestCase):
  # Helper methods.
  @contextlib.contextmanager
  def ReplacePlatformProcessorCall(self, f):
    try:
      old_proc = platform.processor
      platform.processor = f
      yield
    finally:
      platform.processor = old_proc

  @contextlib.contextmanager
  def ReplaceQPCCheck(self, f):
    try:
      old_qpc = trace_time.IsQPCUsable
      trace_time.IsQPCUsable = f
      yield
    finally:
      trace_time.IsQPCUsable = old_qpc

  # Platform detection tests.
  def testInitializeNowFunction_platformNotSupported(self):
    with self.assertRaises(RuntimeError):
      trace_time.InitializeNowFunction('invalid_platform')

  def testInitializeNowFunction_windows(self):
    if not (sys.platform.startswith(trace_time._PLATFORMS['windows'])
            or sys.platform.startswith(trace_time._PLATFORMS['cygwin'])):
      return True
    trace_time.InitializeNowFunction(sys.platform)
    self.assertTrue(trace_time.GetClock() == trace_time._WIN_HIRES
                    or trace_time.GetClock() == trace_time._WIN_LORES)

  def testInitializeNowFunction_linux(self):
    if not sys.platform.startswith(trace_time._PLATFORMS['linux']):
      return True
    trace_time.InitializeNowFunction(sys.platform)
    self.assertEqual(trace_time.GetClock(), trace_time._LINUX_CLOCK)

  def testInitializeNowFunction_mac(self):
    if not sys.platform.startswith(trace_time._PLATFORMS['mac']):
      return True
    trace_time.InitializeNowFunction(sys.platform)
    self.assertEqual(trace_time.GetClock(), trace_time._MAC_CLOCK)

  # Windows Tests
  def testIsQPCUsable_buggyAthlonProcReturnsFalse(self):
    if not (sys.platform.startswith(trace_time._PLATFORMS['windows'])
            or sys.platform.startswith(trace_time._PLATFORMS['cygwin'])):
      return True

    def BuggyAthlonProc():
      return 'AMD64 Family 15 Model 23 Stepping 6, AuthenticAMD'

    with self.ReplacePlatformProcessorCall(BuggyAthlonProc):
      self.assertFalse(trace_time.IsQPCUsable())

  def testIsQPCUsable_returnsTrueOnWindows(self):
    if not (sys.platform.startswith(trace_time._PLATFORMS['windows'])
            or sys.platform.startswith(trace_time._PLATFORMS['cygwin'])):
      return True

    def Proc():
      return 'Intel64 Family 15 Model 23 Stepping 6, GenuineIntel'

    with self.ReplacePlatformProcessorCall(Proc):
      self.assertTrue(trace_time.IsQPCUsable())

  def testGetWinNowFunction_QPC(self):
    if not (sys.platform.startswith(trace_time._PLATFORMS['windows'])
            or sys.platform.startswith(trace_time._PLATFORMS['cygwin'])):
      return True
    # Test requires QPC to be available on platform.
    if not trace_time.IsQPCUsable():
      return True
    self.assertGreater(trace_time.monotonic(), 0)

  # Works even if QPC would work.
  def testGetWinNowFunction_GetTickCount(self):
    if not (sys.platform.startswith(trace_time._PLATFORMS['windows'])
            or sys.platform.startswith(trace_time._PLATFORMS['cygwin'])):
      return True
    with self.ReplaceQPCCheck(lambda: False):
      self.assertGreater(trace_time.monotonic(), 0)

  # Linux tests.
  def testGetClockGetTimeClockNumber_linux(self):
    self.assertEquals(trace_time.GetClockGetTimeClockNumber('linux'), 1)

  def testGetClockGetTimeClockNumber_freebsd(self):
    self.assertEquals(trace_time.GetClockGetTimeClockNumber('freebsd'), 4)

  def testGetClockGetTimeClockNumber_bsd(self):
    self.assertEquals(trace_time.GetClockGetTimeClockNumber('bsd'), 3)

  def testGetClockGetTimeClockNumber_sunos(self):
    self.assertEquals(trace_time.GetClockGetTimeClockNumber('sunos5'), 4)

  # Smoke Test.
  def testMonotonic(self):
    time_one = trace_time.Now()
    for _ in xrange(1000):
      time_two = trace_time.Now()
      self.assertLessEqual(time_one, time_two)
      time_one = time_two


if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
