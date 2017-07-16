# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import mock
from telemetry.internal.platform.power_monitor import android_temperature_monitor

class AndroidTemperatureMonitorTest(unittest.TestCase):

  def testPowerMonitoringResultsWereUpdated(self):
    mock_device_utils = mock.Mock()
    mock_device_utils.ReadFile.side_effect = ['0', '24']

    monitor = android_temperature_monitor.AndroidTemperatureMonitor(
        mock_device_utils)
    self.assertTrue(monitor.CanMonitorPower())
    monitor.StartMonitoringPower(None)
    measurements = monitor.StopMonitoringPower()
    mock_device_utils.ReadFile.assert_has_calls(
        [mock.call(mock.ANY), mock.call(mock.ANY)])
    expected_return = {
        'identifier': 'android_temperature_monitor',
        'platform_info': {'average_temperature_c': 24.0}
    }
    self.assertDictEqual(expected_return, measurements)

  def testSysfsReadFailed(self):
    mock_device_utils = mock.Mock()
    mock_device_utils.ReadFile.side_effect = ['24', None]

    monitor = android_temperature_monitor.AndroidTemperatureMonitor(
        mock_device_utils)
    self.assertTrue(monitor.CanMonitorPower())
    monitor.StartMonitoringPower(None)
    measurements = monitor.StopMonitoringPower()
    mock_device_utils.ReadFile.assert_has_calls(
        [mock.call(mock.ANY), mock.call(mock.ANY)])
    self.assertTrue('identifier' in measurements)
    self.assertTrue('platform_info' not in measurements)

  def testSysfsReadFailedCanMonitor(self):
    mock_device_utils = mock.Mock()
    mock_device_utils.ReadFile.side_effect = [None]

    monitor = android_temperature_monitor.AndroidTemperatureMonitor(
        mock_device_utils)
    self.assertFalse(monitor.CanMonitorPower())
    mock_device_utils.ReadFile.assert_called_once_with(mock.ANY)
