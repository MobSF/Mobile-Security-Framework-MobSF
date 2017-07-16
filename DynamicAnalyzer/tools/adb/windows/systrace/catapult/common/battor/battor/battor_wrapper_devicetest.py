# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import platform
import os
import sys
import time
import unittest

if __name__ == '__main__':
  sys.path.append(
      os.path.join(os.path.dirname(__file__), '..'))

from battor import battor_wrapper
from devil.utils import battor_device_mapping
from devil.utils import find_usb_devices


_SUPPORTED_CQ_PLATFORMS = ['win', 'linux', 'mac']

class BattOrWrapperDeviceTest(unittest.TestCase):
  def setUp(self):
    test_platform = platform.system()
    self._battor_list = None
    if 'Win' in test_platform:
      self._platform = 'win'
    elif 'Linux' in test_platform:
      self._platform = 'linux'
      device_tree  = find_usb_devices.GetBusNumberToDeviceTreeMap()
      self._battor_list = battor_device_mapping.GetBattOrList(device_tree)
    elif 'Darwin' in test_platform:
      self._platform = 'mac'

    if not battor_wrapper.IsBattOrConnected(self._platform):
      self._battor_list = []

  def testFullRun(self):
    # If battor_list is an empty list, a BattOr was expected but not found.
    if self._battor_list is not None and not self._battor_list:
      logging.critical('No BattOrs attached. Cannot run tests.')
      return

    if self._platform not in _SUPPORTED_CQ_PLATFORMS:
      logging.critical('Platform %s is not supported on CQ.' % self._platform)
      return


    battor_path = (None if not self._battor_list
                   else '/dev/%s' % self._battor_list[0])
    battor = battor_wrapper.BattOrWrapper(self._platform,
                                          battor_path=battor_path)
    try:
      battor.StartShell()
      self.assertTrue(isinstance(battor.GetFirmwareGitHash(), basestring))
      # We expect the git hash to be a valid 6 character hexstring. This will
      # throw a ValueError exception otherwise.
      int(battor.GetFirmwareGitHash(), 16)
      self.assertTrue(len(battor.GetFirmwareGitHash()) == 7)
      battor.StopShell()

      battor.StartShell()
      battor.StartTracing()
      # TODO(rnephew): This sleep is required for now because crbug.com/602266
      # causes the BattOr to crash when the trace time is too short. Once that
      # bug is fixed, we should remove this delay.
      time.sleep(1)
      battor.RecordClockSyncMarker('abc')
      # Sleep here because clock sync marker will be flaky if not.
      time.sleep(1)
      battor.StopTracing()

      # Below is a work around for crbug.com/603309. On this short of a trace, 5
      # seconds is enough to ensure that the trace will finish flushing to the
      # file. The process is then killed so that BattOrWrapper knows that the
      # process has been closed after tracing stops.
      if self._platform == 'win':
        time.sleep(5)
        battor._battor_shell.kill()
      results = battor.CollectTraceData().splitlines()
    except:
      if battor._battor_shell is not None:
        battor._battor_shell.kill()
        battor._battor_shell = None
      raise

    self.assertTrue('# BattOr' in results[0])
    self.assertTrue('# voltage_range' in results[1])
    self.assertTrue('# current_range' in results[2])
    self.assertTrue('# sample_rate' in results[3])
    # First line with results. Should be 3 'words'.
    self.assertTrue(len(results[4].split()) == 3)
    clock_sync_found = False
    for entry in results:
      if '<abc>' in entry:
        clock_sync_found = True
        break
    self.assertTrue(clock_sync_found, 'BattOr Data:%s\n' % repr(results))


if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
