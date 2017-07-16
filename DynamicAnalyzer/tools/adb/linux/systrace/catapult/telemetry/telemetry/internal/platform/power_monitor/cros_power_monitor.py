# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import logging
import re

from telemetry import decorators
from telemetry.internal.platform.power_monitor import sysfs_power_monitor


class CrosPowerMonitor(sysfs_power_monitor.SysfsPowerMonitor):
  """PowerMonitor that relies on 'dump_power_status' to monitor power
  consumption of a single ChromeOS application.
  """
  def __init__(self, platform_backend):
    """Constructor.

    Args:
        platform_backend: A LinuxBasedPlatformBackend object.

    Attributes:
        _initial_power: The result of 'dump_power_status' before the test.
        _start_time: The epoch time at which the test starts executing.
    """
    super(CrosPowerMonitor, self).__init__(platform_backend)
    self._initial_power = None
    self._start_time = None

  @decorators.Cache
  def CanMonitorPower(self):
    return super(CrosPowerMonitor, self).CanMonitorPower()

  def StartMonitoringPower(self, browser):
    super(CrosPowerMonitor, self).StartMonitoringPower(browser)
    if self._IsOnBatteryPower():
      sample = self._platform.RunCommand(['dump_power_status;', 'date', '+%s'])
      self._initial_power, self._start_time = CrosPowerMonitor.SplitSample(
          sample)
    else:
      logging.warning('Device not on battery power during power monitoring. '
                      'Results may be incorrect.')

  def StopMonitoringPower(self):
    # Don't need to call self._CheckStop here; it's called by the superclass
    cpu_stats = super(CrosPowerMonitor, self).StopMonitoringPower()
    power_stats = {}
    if self._IsOnBatteryPower():
      sample = self._platform.RunCommand(['dump_power_status;', 'date', '+%s'])
      final_power, end_time = CrosPowerMonitor.SplitSample(sample)
      # The length of the test is used to measure energy consumption.
      length_h = (end_time - self._start_time) / 3600.0
      power_stats = CrosPowerMonitor.ParsePower(self._initial_power,
                                                final_power, length_h)
    else:
      logging.warning('Device not on battery power during power monitoring. '
                      'Results may be incorrect.')
    return CrosPowerMonitor.CombineResults(cpu_stats, power_stats)

  @staticmethod
  def SplitSample(sample):
    """Splits a power and time sample into the two separate values.

    Args:
        sample: The result of calling 'dump_power_status; date +%s' on the
            device.

    Returns:
        A tuple of power sample and epoch time of the sample.
    """
    sample = sample.strip()
    index = sample.rfind('\n')
    power = sample[:index]
    time = sample[index + 1:]
    return power, int(time)

  @staticmethod
  def IsOnBatteryPower(status, board):
    """Determines if the devices is being charged.

    Args:
        status: The parsed result of 'dump_power_status'
        board: The name of the board running the test.

    Returns:
        True if the device is on battery power; False otherwise.
    """
    on_battery = status['line_power_connected'] == '0'
    # Butterfly can incorrectly report AC online for some time after unplug.
    # Check battery discharge state to confirm.
    if board == 'butterfly':
      on_battery |= status['battery_discharging'] == '1'
    return on_battery

  def _IsOnBatteryPower(self):
    """Determines if the device is being charged.

    Returns:
        True if the device is on battery power; False otherwise.
    """
    status = CrosPowerMonitor.ParsePowerStatus(
        self._platform.RunCommand(['dump_power_status']))
    board_data = self._platform.RunCommand(['cat', '/etc/lsb-release'])
    board = re.search('BOARD=(.*)', board_data).group(1)
    return CrosPowerMonitor.IsOnBatteryPower(status, board)

  @staticmethod
  def ParsePowerStatus(sample):
    """Parses 'dump_power_status' command output.

    Args:
        sample: The output of 'dump_power_status'

    Returns:
        Dictionary containing all fields from 'dump_power_status'
    """
    rv = collections.defaultdict(dict)
    for ln in sample.splitlines():
      words = ln.split()
      assert len(words) == 2
      rv[words[0]] = words[1]
    return dict(rv)

  @staticmethod
  def ParsePower(initial_stats, final_stats, length_h):
    """Parse output of 'dump_power_status'

    Args:
        initial_stats: The output of 'dump_power_status' before the test.
        final_stats: The output of 'dump_power_status' after the test.
        length_h: The length of the test in hours.

    Returns:
        Dictionary in the format returned by StopMonitoringPower().
    """
    initial = CrosPowerMonitor.ParsePowerStatus(initial_stats)
    final = CrosPowerMonitor.ParsePowerStatus(final_stats)
    # The charge value reported by 'dump_power_status' is not precise enough to
    # give meaningful results across shorter tests, so average energy rate and
    # the length of the test are used.
    initial_power_mw = float(initial['battery_energy_rate']) * 10 ** 3
    final_power_mw = float(final['battery_energy_rate']) * 10 ** 3
    average_power_mw = (initial_power_mw + final_power_mw) / 2.0

    # Duplicating CrOS battery fields where applicable.
    def CopyFinalState(field, key):
      """Copy fields from battery final state."""
      if field in final:
        battery[key] = float(final[field])

    battery = {}
    CopyFinalState('battery_charge_full', 'charge_full')
    CopyFinalState('battery_charge_full_design', 'charge_full_design')
    CopyFinalState('battery_charge', 'charge_now')
    CopyFinalState('battery_current', 'current_now')
    CopyFinalState('battery_energy', 'energy')
    CopyFinalState('battery_energy_rate', 'energy_rate')
    CopyFinalState('battery_voltage', 'voltage_now')

    return {'identifier': 'dump_power_status',
            'power_samples_mw': [initial_power_mw, final_power_mw],
            'energy_consumption_mwh': average_power_mw * length_h,
            'component_utilization': {'battery': battery}}
