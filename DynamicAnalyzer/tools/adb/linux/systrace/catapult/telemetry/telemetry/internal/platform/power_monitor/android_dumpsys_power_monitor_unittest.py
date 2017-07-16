# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform.power_monitor import android_dumpsys_power_monitor
from telemetry.internal.platform.power_monitor import pm_mock


_PACKAGE = 'com.google.android.apps.chrome'

_TYPICAL_POWER_DATA = {
      'system_total': 2000.0,
      'per_package': {
        _PACKAGE: {'data': [23.9], 'uid': '12345'}
      }
    }

_TYPICAL_POWER_DATA_MULTISAMPLE = {
      'system_total': 2000.0,
      'per_package': {
        _PACKAGE: {'data': [23.9, 26.1], 'uid': '12345'}
      }
    }


class DumpsysPowerMonitorMonitorTest(unittest.TestCase):

  def testApplicationEnergyConsumption(self):
    results = (
        android_dumpsys_power_monitor.DumpsysPowerMonitor.ProcessPowerData(
            _TYPICAL_POWER_DATA, 4.0, _PACKAGE))
    self.assertEqual(results['identifier'], 'dumpsys')
    self.assertAlmostEqual(results['application_energy_consumption_mwh'], 95.6)

  def testSystemEnergyConsumption(self):
    power_data = {
      'system_total': 2000.0,
      'per_package': {}
    }
    results = (
        android_dumpsys_power_monitor.DumpsysPowerMonitor.ProcessPowerData(
            power_data, 4.0, 'some.package'))
    self.assertEqual(results['identifier'], 'dumpsys')
    self.assertEqual(results['application_energy_consumption_mwh'], 0)
    self.assertEqual(results['energy_consumption_mwh'], 8000.0)

  def testMonitorCycle(self):
    browser = pm_mock.MockBrowser(_PACKAGE)
    battery = pm_mock.MockBattery(_TYPICAL_POWER_DATA_MULTISAMPLE, voltage=5.0)
    backend = pm_mock.MockPlatformBackend()
    pm = android_dumpsys_power_monitor.DumpsysPowerMonitor(battery, backend)
    pm.StartMonitoringPower(browser)
    result = pm.StopMonitoringPower()
    self.assertEqual(result['identifier'], 'dumpsys')
    self.assertEqual(result['power_samples_mw'], [])
    self.assertAlmostEqual(result['application_energy_consumption_mwh'], 250.0)
    self.assertAlmostEqual(result['energy_consumption_mwh'], 10000.0)

  def testDoubleStop(self):
    browser = pm_mock.MockBrowser(_PACKAGE)
    battery = pm_mock.MockBattery(_TYPICAL_POWER_DATA_MULTISAMPLE, voltage=5.0)
    backend = pm_mock.MockPlatformBackend()
    pm = android_dumpsys_power_monitor.DumpsysPowerMonitor(battery, backend)
    pm.StartMonitoringPower(browser)
    pm.StopMonitoringPower()
    with self.assertRaises(AssertionError):
      pm.StopMonitoringPower()

  def testDoubleStart(self):
    browser = pm_mock.MockBrowser(_PACKAGE)
    battery = pm_mock.MockBattery(_TYPICAL_POWER_DATA_MULTISAMPLE, voltage=5.0)
    backend = pm_mock.MockPlatformBackend()
    pm = android_dumpsys_power_monitor.DumpsysPowerMonitor(battery, backend)
    pm.StartMonitoringPower(browser)
    with self.assertRaises(AssertionError):
      pm.StartMonitoringPower(browser)

  def testBatteryChargingState(self):
    browser = pm_mock.MockBrowser(_PACKAGE)
    battery = pm_mock.MockBattery(_TYPICAL_POWER_DATA_MULTISAMPLE, voltage=5.0)
    backend = pm_mock.MockPlatformBackend()
    pm = android_dumpsys_power_monitor.DumpsysPowerMonitor(battery, backend)
    self.assertEqual(battery.GetCharging(), True)
    pm.StartMonitoringPower(browser)
    self.assertEqual(battery.GetCharging(), True)
    pm.StopMonitoringPower()
    self.assertEqual(battery.GetCharging(), True)

if __name__ == '__main__':
  unittest.main()
