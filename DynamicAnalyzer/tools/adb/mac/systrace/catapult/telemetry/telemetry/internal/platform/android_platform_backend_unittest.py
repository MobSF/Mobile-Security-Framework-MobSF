# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import decorators
from telemetry.internal.platform import android_device
from telemetry.internal.platform import android_platform_backend
from telemetry.testing import system_stub
import mock

from devil.android import battery_utils
from devil.android import device_utils

class AndroidPlatformBackendTest(unittest.TestCase):
  def setUp(self):
    self._stubs = system_stub.Override(
        android_platform_backend,
        ['perf_control', 'thermal_throttle'])

    # Skip _FixPossibleAdbInstability by setting psutil to None.
    self._actual_ps_util = android_platform_backend.psutil
    android_platform_backend.psutil = None
    self.battery_patcher = mock.patch.object(battery_utils, 'BatteryUtils')
    self.battery_patcher.start()

    def get_prop(name, cache=None):
      del cache  # unused
      return {'ro.product.cpu.abi': 'armeabi-v7a'}.get(name)

    self.device_patcher = mock.patch.multiple(
        device_utils.DeviceUtils,
        HasRoot=mock.MagicMock(return_value=True),
        GetProp=mock.MagicMock(side_effect=get_prop))
    self.device_patcher.start()

  def tearDown(self):
    self._stubs.Restore()
    android_platform_backend.psutil = self._actual_ps_util
    self.battery_patcher.stop()
    self.device_patcher.stop()

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testIsSvelte(self):
    with mock.patch('devil.android.device_utils.DeviceUtils.GetProp',
                    return_value='svelte'):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('12345'))
      self.assertTrue(backend.IsSvelte())

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testIsNotSvelte(self):
    with mock.patch('devil.android.device_utils.DeviceUtils.GetProp',
                    return_value='foo'):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('12345'))
      self.assertFalse(backend.IsSvelte())

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testGetCpuStats(self):
    proc_stat_content = (
        '7702 (.android.chrome) S 167 167 0 0 -1 1077936448 '
        '3247 0 0 0 4 1 0 0 20 0 9 0 5603962 337379328 5867 '
        '4294967295 1074458624 1074463824 3197495984 3197494152 '
        '1074767676 0 4612 0 38136 4294967295 0 0 17 0 0 0 0 0 0 '
        '1074470376 1074470912 1102155776\n')
    with mock.patch('devil.android.device_utils.DeviceUtils.ReadFile',
                    return_value=proc_stat_content):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('12345'))
      cpu_stats = backend.GetCpuStats('7702')
      self.assertEquals(cpu_stats, {'CpuProcessTime': 0.05})

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testGetCpuStatsInvalidPID(self):
    # Mock an empty /proc/pid/stat.
    with mock.patch('devil.android.device_utils.DeviceUtils.ReadFile',
                    return_value=''):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('1234'))
      cpu_stats = backend.GetCpuStats('7702')
      self.assertEquals(cpu_stats, {})

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testAndroidParseCpuStates(self):
    cstate = {
      'cpu0': 'C0\nC1\n103203424\n5342040\n300\n500\n1403232500',
      'cpu1': 'C0\n124361858\n300\n1403232500'
    }
    expected_cstate = {
      'cpu0': {
        'WFI': 103203424,
        'C0': 1403232391454536,
        'C1': 5342040
      },
      'cpu1': {
        'WFI': 124361858,
        'C0': 1403232375638142
      }
    }
    # Use mock start and end times to allow for the test to calculate C0.
    result = android_platform_backend.AndroidPlatformBackend.ParseCStateSample(
        cstate)
    for cpu in result:
      for state in result[cpu]:
        self.assertAlmostEqual(result[cpu][state], expected_cstate[cpu][state])

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testInstallTestCaSuccess(self):
    backend = android_platform_backend.AndroidPlatformBackend(
        android_device.AndroidDevice('success'))
    with mock.patch('adb_install_cert.AndroidCertInstaller'):
      backend.InstallTestCa('testca.pem')
      self.assertIsNotNone(backend._device_cert_util)

      backend.RemoveTestCa()
      self.assertIsNone(backend._device_cert_util)

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testIsScreenLockedTrue(self):
    test_input = ['a=b', 'mHasBeenInactive=true']
    backend = android_platform_backend.AndroidPlatformBackend(
        android_device.AndroidDevice('success'))
    self.assertTrue(backend._IsScreenLocked(test_input))

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testIsScreenLockedFalse(self):
    test_input = ['a=b', 'mHasBeenInactive=false']
    backend = android_platform_backend.AndroidPlatformBackend(
        android_device.AndroidDevice('success'))
    self.assertFalse(backend._IsScreenLocked(test_input))


class AndroidPlatformBackendPsutilTest(unittest.TestCase):

  class psutil_1_0(object):
    version_info = (1, 0)
    def __init__(self):
      self.set_cpu_affinity_args = []
    class Process(object):
      def __init__(self, parent):
        self._parent = parent
        self.name = 'adb'
      def set_cpu_affinity(self, cpus):
        self._parent.set_cpu_affinity_args.append(cpus)
    def process_iter(self):
      return [self.Process(self)]

  class psutil_2_0(object):
    version_info = (2, 0)
    def __init__(self):
      self.set_cpu_affinity_args = []
    class Process(object):
      def __init__(self, parent):
        self._parent = parent
        self.set_cpu_affinity_args = []
      def name(self):
        return 'adb'
      def cpu_affinity(self, cpus=None):
        self._parent.set_cpu_affinity_args.append(cpus)
    def process_iter(self):
      return [self.Process(self)]

  def setUp(self):
    self._stubs = system_stub.Override(
        android_platform_backend,
        ['perf_control'])
    self.battery_patcher = mock.patch.object(battery_utils, 'BatteryUtils')
    self.battery_patcher.start()
    self._actual_ps_util = android_platform_backend.psutil

    def get_prop(name, cache=None):
      del cache  # unused
      return {'ro.product.cpu.abi': 'armeabi-v7a'}.get(name)

    self.device_patcher = mock.patch.multiple(
        device_utils.DeviceUtils,
        FileExists=mock.MagicMock(return_value=False),
        GetProp=mock.MagicMock(side_effect=get_prop),
        HasRoot=mock.MagicMock(return_value=True))
    self.device_patcher.start()

  def tearDown(self):
    self._stubs.Restore()
    android_platform_backend.psutil = self._actual_ps_util
    self.battery_patcher.stop()
    self.device_patcher.stop()

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testPsutil1(self):
    psutil = self.psutil_1_0()
    android_platform_backend.psutil = psutil

    # Mock an empty /proc/pid/stat.
    with mock.patch('devil.android.device_utils.DeviceUtils.ReadFile',
                    return_value=''):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('1234'))
      cpu_stats = backend.GetCpuStats('7702')
      self.assertEquals({}, cpu_stats)
      self.assertEquals([[0]], psutil.set_cpu_affinity_args)

  @decorators.Disabled('chromeos', 'mac', 'win')
  def testPsutil2(self):
    psutil = self.psutil_2_0()
    android_platform_backend.psutil = psutil

    # Mock an empty /proc/pid/stat.
    with mock.patch('devil.android.device_utils.DeviceUtils.ReadFile',
                    return_value=''):
      backend = android_platform_backend.AndroidPlatformBackend(
          android_device.AndroidDevice('1234'))
      cpu_stats = backend.GetCpuStats('7702')
      self.assertEquals({}, cpu_stats)
      self.assertEquals([[0]], psutil.set_cpu_affinity_args)
