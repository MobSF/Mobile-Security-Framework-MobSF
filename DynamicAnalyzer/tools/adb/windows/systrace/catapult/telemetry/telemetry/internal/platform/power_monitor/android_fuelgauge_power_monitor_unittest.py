# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform.power_monitor import (
    android_fuelgauge_power_monitor)
from telemetry.internal.platform.power_monitor import pm_mock


class FuelGaugePowerMonitorMonitorTest(unittest.TestCase):

  def testEnergyConsumption(self):
    fuel_gauge_delta = 100
    results = (
        android_fuelgauge_power_monitor.FuelGaugePowerMonitor.ProcessPowerData(
            4.0, fuel_gauge_delta))
    self.assertEqual(results['identifier'], 'fuel_gauge')
    self.assertEqual(
        results.get('fuel_gauge_energy_consumption_mwh'), 400)

  def testMonitorCycle(self):
    battery = pm_mock.MockBattery(None, voltage=5.0, fuelgauge=[5.e6, 3.e6])
    pm = android_fuelgauge_power_monitor.FuelGaugePowerMonitor(battery)
    pm.StartMonitoringPower(None)
    results = pm.StopMonitoringPower()
    self.assertEqual(results['identifier'], 'fuel_gauge')
    self.assertAlmostEqual(results['fuel_gauge_energy_consumption_mwh'], 10)

  def testDoubleStop(self):
    battery = pm_mock.MockBattery(None, voltage=5.0, fuelgauge=[5.e6, 3.e6])
    pm = android_fuelgauge_power_monitor.FuelGaugePowerMonitor(battery)
    pm.StartMonitoringPower(None)
    pm.StopMonitoringPower()
    with self.assertRaises(AssertionError):
      pm.StopMonitoringPower()

  def testDoubleStart(self):
    battery = pm_mock.MockBattery(None, voltage=5.0, fuelgauge=[5.e6, 3.e6])
    pm = android_fuelgauge_power_monitor.FuelGaugePowerMonitor(battery)
    pm.StartMonitoringPower(None)
    with self.assertRaises(AssertionError):
      pm.StartMonitoringPower(None)


if __name__ == '__main__':
  unittest.main()
