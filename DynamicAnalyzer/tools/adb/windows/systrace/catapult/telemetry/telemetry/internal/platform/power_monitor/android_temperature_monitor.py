# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.internal.platform import power_monitor

try:
  from devil.android import device_errors  # pylint: disable=import-error
except ImportError:
  device_errors = None


_TEMPERATURE_FILE = '/sys/class/thermal/thermal_zone0/temp'


class AndroidTemperatureMonitor(power_monitor.PowerMonitor):
  """
  Returns temperature results in power monitor dictionary format.
  """
  def __init__(self, device):
    super(AndroidTemperatureMonitor, self).__init__()
    self._device = device

  def CanMonitorPower(self):
    return self._GetBoardTemperatureCelsius() is not None

  def StartMonitoringPower(self, browser):
    # don't call _CheckStart() because this is temperature, not power
    # therefore, StartMonitoringPower and StopMonitoringPower
    # do not need to be paired
    pass

  def StopMonitoringPower(self):
    avg_temp = self._GetBoardTemperatureCelsius()
    if avg_temp is None:
      return {'identifier': 'android_temperature_monitor'}
    else:
      return {'identifier': 'android_temperature_monitor',
              'platform_info': {'average_temperature_c': avg_temp}}

  def _GetBoardTemperatureCelsius(self):
    try:
      contents = self._device.ReadFile(_TEMPERATURE_FILE)
      return float(contents) if contents else None
    except ValueError:
      logging.warning('String returned from device.ReadFile(_TEMPERATURE_FILE) '
                      'in invalid format.')
      return None
    except device_errors.CommandFailedError:
      return None
