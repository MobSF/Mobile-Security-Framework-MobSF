# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform import power_monitor as power_monitor
from telemetry.internal.platform.power_monitor import (
  android_power_monitor_controller)
import mock
from devil.android import battery_utils

# pylint: disable=import-error, unused-argument


class AndroidPowerMonitorControllerTest(unittest.TestCase):
  @mock.patch.object(battery_utils, 'BatteryUtils')
  def testComposition(self, _):

    class P1(power_monitor.PowerMonitor):
      def StartMonitoringPower(self, browser):
        raise NotImplementedError()
      def StopMonitoringPower(self):
        raise NotImplementedError()

    class P2(power_monitor.PowerMonitor):
      def __init__(self, value):
        super(P2, self).__init__()
        self._value = {'P2': value}
      def CanMonitorPower(self):
        return True
      def StartMonitoringPower(self, browser):
        pass
      def StopMonitoringPower(self):
        return self._value

    class P3(power_monitor.PowerMonitor):
      def __init__(self, value):
        super(P3, self).__init__()
        self._value = {'P3': value}
      def CanMonitorPower(self):
        return True
      def StartMonitoringPower(self, browser):
        pass
      def StopMonitoringPower(self):
        return self._value

    battery = battery_utils.BatteryUtils(None)
    controller = android_power_monitor_controller.AndroidPowerMonitorController(
        [P1(), P2(1), P3(2)], battery)
    self.assertEqual(controller.CanMonitorPower(), True)
    controller.StartMonitoringPower(None)
    controller_returns = controller.StopMonitoringPower()
    self.assertEqual(controller_returns['P2'], 1)
    self.assertEqual(controller_returns['P3'], 2)

  @mock.patch.object(battery_utils, 'BatteryUtils')
  def testReenableChargingIfNeeded(self, mock_battery):
    battery = battery_utils.BatteryUtils(None)
    battery.GetCharging.return_value = False
    android_power_monitor_controller._ReenableChargingIfNeeded(battery)

  def testMergePowerResultsOneEmpty(self):
    dict_one = {'platform_info': {}, 'component_utilization': {}}
    dict_two = {'test': 1, 'component_utilization': {'test': 2}}
    results = {
        'platform_info': {},
        'component_utilization': {'test': 2},
        'test': 1
    }
    (android_power_monitor_controller.AndroidPowerMonitorController.
     _MergePowerResults(dict_one, dict_two))
    self.assertDictEqual(dict_one, results)

  def testMergePowerResultsSameEntry(self):
    dict_one = {
        'test': 1,
        'component_utilization': {'test': 2},
        'platform_info': {'test2': 'a'}
    }
    dict_two = {'test': 3, 'platform_info': {'test': 4}}
    results = {
        'test' : 3,
        'component_utilization': {'test': 2},
        'platform_info': {'test': 4, 'test2': 'a'}
    }
    (android_power_monitor_controller.AndroidPowerMonitorController.
     _MergePowerResults(dict_one, dict_two))
    self.assertDictEqual(dict_one, results)
