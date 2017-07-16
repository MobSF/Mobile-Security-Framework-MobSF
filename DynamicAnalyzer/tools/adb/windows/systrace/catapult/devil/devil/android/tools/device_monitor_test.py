#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import unittest

if __name__ == '__main__':
  sys.path.append(
        os.path.abspath(os.path.join(os.path.dirname(__file__),
                                           '..', '..', '..')))

from devil import devil_env
from devil.android import device_errors
from devil.android import device_utils
from devil.android.tools import device_monitor

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


class DeviceMonitorTest(unittest.TestCase):

  def setUp(self):
    self.device = mock.Mock(spec=device_utils.DeviceUtils,
        serial='device_cereal', build_id='abc123', build_product='clownfish')
    self.file_contents = {
        '/proc/meminfo': """
                         MemTotal:        1234567 kB
                         MemFree:         1000000 kB
                         MemUsed:          234567 kB
                         """,
        '/sys/class/thermal/thermal_zone0/type': 'CPU-therm',
        '/sys/class/thermal/thermal_zone0/temp': '30',
        '/proc/uptime': '12345 99999',
    }
    self.device.ReadFile = mock.MagicMock(
        side_effect=lambda file_name: self.file_contents[file_name])

    self.cmd_outputs = {
        'ps': ['headers', 'p1', 'p2', 'p3', 'p4', 'p5'],
        'grep': ['/sys/class/thermal/thermal_zone0/type'],
    }

    def mock_run_shell(cmd, **_kwargs):
      args = cmd.split() if isinstance(cmd, basestring) else cmd
      try:
        return self.cmd_outputs[args[0]]
      except KeyError:
        raise device_errors.AdbShellCommandFailedError(cmd, None, None)

    self.device.RunShellCommand = mock.MagicMock(side_effect=mock_run_shell)

    self.battery = mock.Mock()
    self.battery.GetBatteryInfo = mock.MagicMock(
        return_value={'level': '80', 'temperature': '123'})

    self.expected_status = {
      'device_cereal': {
        'processes': 5,
        'temp': {
          'CPU-therm': 30.0
         },
         'battery': {
           'temperature': 123,
           'level': 80
         },
         'uptime': 12345.0,
         'mem': {
           'total': 1234567,
           'free': 1000000
         },
         'build': {
           'build.id': 'abc123',
           'product.device': 'clownfish',
         },
         'state': 'available',
      }
    }

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_getStats(self, get_devices, get_battery):
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery

    status = device_monitor.get_all_status(None)
    self.assertEquals(self.expected_status, status['devices'])

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_getStatsNoBattery(self, get_devices, get_battery):
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery
    broken_battery_info = mock.Mock()
    broken_battery_info.GetBatteryInfo = mock.MagicMock(
        return_value={'level': '-1', 'temperature': 'not_a_number'})
    get_battery.return_value = broken_battery_info

    # Should be same status dict but without battery stats.
    expected_status_no_battery = self.expected_status.copy()
    expected_status_no_battery['device_cereal'].pop('battery')

    status = device_monitor.get_all_status(None)
    self.assertEquals(expected_status_no_battery, status['devices'])

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_getStatsNoPs(self, get_devices, get_battery):
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery
    del self.cmd_outputs['ps']  # Throw exception on run shell ps command.

    # Should be same status dict but without process stats.
    expected_status_no_ps = self.expected_status.copy()
    expected_status_no_ps['device_cereal'].pop('processes')

    status = device_monitor.get_all_status(None)
    self.assertEquals(expected_status_no_ps, status['devices'])

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_getStatsNoSensors(self, get_devices, get_battery):
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery
    del self.cmd_outputs['grep']  # Throw exception on run shell grep command.

    # Should be same status dict but without temp stats.
    expected_status_no_temp = self.expected_status.copy()
    expected_status_no_temp['device_cereal'].pop('temp')

    status = device_monitor.get_all_status(None)
    self.assertEquals(expected_status_no_temp, status['devices'])

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_getStatsWithBlacklist(self, get_devices, get_battery):
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery
    blacklist = mock.Mock()
    blacklist.Read = mock.MagicMock(
        return_value={'bad_device': {'reason': 'offline'}})

    # Should be same status dict but with extra blacklisted device.
    expected_status = self.expected_status.copy()
    expected_status['bad_device'] = {'state': 'offline'}

    status = device_monitor.get_all_status(blacklist)
    self.assertEquals(expected_status, status['devices'])

  @mock.patch('devil.android.battery_utils.BatteryUtils')
  @mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices')
  def test_brokenTempValue(self, get_devices, get_battery):
    self.file_contents['/sys/class/thermal/thermal_zone0/temp'] = 'n0t a numb3r'
    get_devices.return_value = [self.device]
    get_battery.return_value = self.battery

    expected_status_no_temp = self.expected_status.copy()
    expected_status_no_temp['device_cereal'].pop('temp')

    status = device_monitor.get_all_status(None)
    self.assertEquals(self.expected_status, status['devices'])


if __name__ == '__main__':
  sys.exit(unittest.main())
