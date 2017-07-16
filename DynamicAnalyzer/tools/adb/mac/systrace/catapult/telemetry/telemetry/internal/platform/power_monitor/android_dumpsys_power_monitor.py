# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import csv
import logging

from telemetry.internal.platform.power_monitor import android_power_monitor_base

class DumpsysPowerMonitor(android_power_monitor_base.AndroidPowerMonitorBase):
  """PowerMonitor that relies on the dumpsys batterystats to monitor the power
  consumption of a single android application. This measure uses a heuristic
  and is the same information end-users see with the battery application.
  Available on Android L and higher releases.
  """
  def __init__(self, battery, platform_backend):
    """Constructor.

    Args:
        battery: A BatteryUtil instance.
        platform_backend: A LinuxBasedPlatformBackend instance.
    """
    super(DumpsysPowerMonitor, self).__init__()
    self._battery = battery
    self._browser = None
    self._platform = platform_backend

  def CanMonitorPower(self):
    result = self._platform.device.RunShellCommand(
        ['dumpsys', 'batterystats', '-c'], check_return=True)
    DUMP_VERSION_INDEX = 0
    # Dumpsys power data is present in dumpsys versions 8 and 9
    # which is found on L+ devices.
    return (csv.reader(result).next()[DUMP_VERSION_INDEX] in ['8', '9'])

  def StartMonitoringPower(self, browser):
    self._CheckStart()
    assert browser
    self._browser = browser
    # Disable the charging of the device over USB. This is necessary because the
    # device only collects information about power usage when the device is not
    # charging.

  def StopMonitoringPower(self):
    self._CheckStop()
    assert self._browser
    package = self._browser._browser_backend.package
    self._browser = None

    voltage = self._ParseVoltage(self._battery.GetBatteryInfo().get('voltage'))
    power_data = self._battery.GetPowerData()
    power_results = self.ProcessPowerData(power_data, voltage, package)
    self._LogPowerAnomalies(power_results, package)
    return power_results

  @staticmethod
  def ProcessPowerData(power_data, voltage, package):
    package_power_data = power_data['per_package'].get(package)
    if not package_power_data:
      logging.warning('No power data for %s in dumpsys output.' % package)
      package_power = 0
    else:
      package_power = sum(package_power_data['data'])

    return {'identifier': 'dumpsys',
            'power_samples_mw': [],
            'energy_consumption_mwh': power_data['system_total'] * voltage,
            'application_energy_consumption_mwh': package_power * voltage}
