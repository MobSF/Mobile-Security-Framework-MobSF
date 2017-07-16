# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform import android_platform_backend
from telemetry.internal.platform.power_monitor import sysfs_power_monitor


class SysfsPowerMonitorMonitorTest(unittest.TestCase):
  initial_freq = {
    'cpu0': '1700000 6227\n1600000 0\n1500000 0\n1400000 28\n1300000 22\n'
            '1200000 14\n1100000 19\n1000000 22\n900000 14\n800000 20\n'
            '700000 15\n600000 23\n500000 23\n400000 9\n300000 28\n200000 179',
    'cpu1': '1700000 11491\n1600000 0\n1500000 0\n1400000 248\n1300000 1166\n'
            '1200000 2082\n1100000 2943\n1000000 6560\n900000 12517\n'
            '800000 8690\n700000 5105\n600000 3800\n500000 5131\n400000 5479\n'
            '300000 7571\n200000 133618',
    'cpu2': '1700000 1131',
    'cpu3': '1700000 1131'
  }
  final_freq = {
    'cpu0': '1700000 7159\n1600000 0\n1500000 0\n1400000 68\n1300000 134\n'
            '1200000 194\n1100000 296\n1000000 716\n900000 1301\n800000 851\n'
            '700000 554\n600000 343\n500000 612\n400000 691\n300000 855\n'
            '200000 15525',
    'cpu1': '1700000 12048\n1600000 0\n1500000 0\n1400000 280\n1300000 1267\n'
            '1200000 2272\n1100000 3163\n1000000 7039\n900000 13800\n'
            '800000 9599\n700000 5655\n600000 4144\n500000 5655\n400000 6005\n'
            '300000 8288\n200000 149724',
    'cpu2': None,
    'cpu3': ''
  }
  expected_initial_freq = {
    'cpu0': {
      1700000000: 6227,
      1600000000: 0,
      1500000000: 0,
      1400000000: 28,
      1300000000: 22,
      1200000000: 14,
      1100000000: 19,
      1000000000: 22,
      900000000: 14,
      800000000: 20,
      700000000: 15,
      600000000: 23,
      500000000: 23,
      400000000: 9,
      300000000: 28,
      200000000: 179
    },
    'cpu1': {
      1700000000: 11491,
      1600000000: 0,
      1500000000: 0,
      1400000000: 248,
      1300000000: 1166,
      1200000000: 2082,
      1100000000: 2943,
      1000000000: 6560,
      900000000: 12517,
      800000000: 8690,
      700000000: 5105,
      600000000: 3800,
      500000000: 5131,
      400000000: 5479,
      300000000: 7571,
      200000000: 133618
    },
    'cpu2': {
      1700000000: 1131
    },
    'cpu3': {
      1700000000: 1131
    }
  }
  expected_final_freq = {
    'cpu0': {
      1700000000: 7159,
      1600000000: 0,
      1500000000: 0,
      1400000000: 68,
      1300000000: 134,
      1200000000: 194,
      1100000000: 296,
      1000000000: 716,
      900000000: 1301,
      800000000: 851,
      700000000: 554,
      600000000: 343,
      500000000: 612,
      400000000: 691,
      300000000: 855,
      200000000: 15525
    },
    'cpu1': {
      1700000000: 12048,
      1600000000: 0,
      1500000000: 0,
      1400000000: 280,
      1300000000: 1267,
      1200000000: 2272,
      1100000000: 3163,
      1000000000: 7039,
      900000000: 13800,
      800000000: 9599,
      700000000: 5655,
      600000000: 4144,
      500000000: 5655,
      400000000: 6005,
      300000000: 8288,
      200000000: 149724
    },
    'cpu2': None,
    'cpu3': {}
  }
  expected_freq_percents = {
    'platform_info': {
      1700000000: 3.29254111574526,
      1600000000: 0.0,
      1500000000: 0.0,
      1400000000: 0.15926805099535601,
      1300000000: 0.47124116307273645,
      1200000000: 0.818756100807525,
      1100000000: 1.099381692400982,
      1000000000: 2.5942528544384302,
      900000000: 5.68661122326737,
      800000000: 3.850545467654628,
      700000000: 2.409691872245393,
      600000000: 1.4693702487650486,
      500000000: 2.4623575553879373,
      400000000: 2.672038150383057,
      300000000: 3.415770495015825,
      200000000: 69.59817400982045
    },
    'cpu0': {
      1700000000: 4.113700564971752,
      1600000000: 0.0,
      1500000000: 0.0,
      1400000000: 0.1765536723163842,
      1300000000: 0.4943502824858757,
      1200000000: 0.7944915254237288,
      1100000000: 1.2226341807909604,
      1000000000: 3.0632062146892656,
      900000000: 5.680614406779661,
      800000000: 3.6679025423728815,
      700000000: 2.379060734463277,
      600000000: 1.4124293785310735,
      500000000: 2.599752824858757,
      400000000: 3.0102401129943503,
      300000000: 3.650247175141243,
      200000000: 67.73481638418079
    },
    'cpu1': {
      1700000000: 2.4713816665187682,
      1600000000: 0.0,
      1500000000: 0.0,
      1400000000: 0.1419824296743278,
      1300000000: 0.44813204365959713,
      1200000000: 0.8430206761913214,
      1100000000: 0.9761292040110037,
      1000000000: 2.1252994941875945,
      900000000: 5.69260803975508,
      800000000: 4.033188392936374,
      700000000: 2.4403230100275093,
      600000000: 1.526311118999024,
      500000000: 2.3249622859171177,
      400000000: 2.3338361877717633,
      300000000: 3.1812938148904073,
      200000000: 71.46153163546012
    },
    'cpu2': {
      1700000000: 0.0,
    },
    'cpu3': {
      1700000000: 0.0,
   }
  }

  def testParseCpuFreq(self):
    initial = sysfs_power_monitor.SysfsPowerMonitor.ParseFreqSample(
        self.initial_freq)
    final = sysfs_power_monitor.SysfsPowerMonitor.ParseFreqSample(
        self.final_freq)
    self.assertDictEqual(initial, self.expected_initial_freq)
    self.assertDictEqual(final, self.expected_final_freq)

  def testComputeCpuStats(self):
    results = sysfs_power_monitor.SysfsPowerMonitor.ComputeCpuStats(
        self.expected_initial_freq, self.expected_final_freq)
    for cpu in self.expected_freq_percents:
      for freq in results[cpu]:
        self.assertAlmostEqual(results[cpu][freq],
                               self.expected_freq_percents[cpu][freq])

  def testComputeCpuStatsWithMissingData(self):
    results = sysfs_power_monitor.SysfsPowerMonitor.ComputeCpuStats(
        {'cpu1': {}}, {'cpu1': {}})
    self.assertEqual(results['cpu1'][12345], 0)

    results = sysfs_power_monitor.SysfsPowerMonitor.ComputeCpuStats(
        {'cpu1': {123: 0}}, {'cpu1': {123: 0}})
    self.assertEqual(results['cpu1'][123], 0)

    results = sysfs_power_monitor.SysfsPowerMonitor.ComputeCpuStats(
        {'cpu1': {123: 456}}, {'cpu1': {123: 456}})
    self.assertEqual(results['cpu1'][123], 0)

  def testComputeCpuStatsWithNumberChange(self):
    results = sysfs_power_monitor.SysfsPowerMonitor.ComputeCpuStats(
        {'cpu1': {'C0': 10, 'WFI': 20}},
        {'cpu1': {'C0': 20, 'WFI': 10}})
    self.assertEqual(results['cpu1']['C0'], 0)
    self.assertEqual(results['cpu1']['WFI'], 0)

  def testGetCpuStateForAndroidDevices(self):
    class PlatformStub(object):
      def __init__(self, run_command_return_value):
        self._run_command_return_value = run_command_return_value
      def RunCommand(self, cmd):
        del cmd  # unused
        return self._run_command_return_value
      def PathExists(self, path):
        return 'cpu0' in path or 'cpu1' in path

    cpu_state_from_samsung_note3 = (
        "C0\n\nC1\n\nC2\n\nC3\n\n"
        "53658520886\n1809072\n7073\n1722554\n"
        "1\n35\n300\n500\n"
        "1412949256\n")
    expected_cstate_dict = {
      'C0': 1412895593940415,
      'C1': 1809072,
      'C2': 7073,
      'C3': 1722554,
      'WFI': 53658520886
    }
    cpus = ["cpu%d" % cpu for cpu in range(4)]
    expected_result = dict(zip(cpus, [expected_cstate_dict]*2))

    sysfsmon = sysfs_power_monitor.SysfsPowerMonitor(
      PlatformStub(cpu_state_from_samsung_note3))
    # pylint: disable=protected-access
    sysfsmon._cpus = cpus
    cstate = sysfsmon.GetCpuState()
    result = android_platform_backend.AndroidPlatformBackend.ParseCStateSample(
        cstate)
    self.assertDictEqual(expected_result, result)

  def testStandAlone(self):
    class PlatformStub(object):
      def __init__(self, run_command_return_value):
        self._run_command_return_value = run_command_return_value
      def RunCommand(self, cmd):
        del cmd  # unused
        return self._run_command_return_value
      def PathExists(self, path):
        del path  # unused
        return True

    cpu_state_from_samsung_note3 = (
        "C0\n\nC1\n\nC2\n\nC3\n\n"
        "53658520886\n1809072\n7073\n1722554\n"
        "1\n35\n300\n500\n"
        "1412949256\n")
    expected_cstate_dict = {
        'C0': 1412895593940415,
        'C1': 1809072,
        'C2': 7073,
        'C3': 1722554,
        'WFI': 53658520886
    }
    cpus = ["cpu%d" % cpu for cpu in range(2)]
    expected_result = dict(zip(cpus, [expected_cstate_dict]*len(cpus)))

    sysfsmon = sysfs_power_monitor.SysfsPowerMonitor(
        PlatformStub(cpu_state_from_samsung_note3), standalone=True)
    # pylint: disable=protected-access
    sysfsmon._cpus = cpus
    cstate = sysfsmon.GetCpuState()
    result = android_platform_backend.AndroidPlatformBackend.ParseCStateSample(
        cstate)
    self.assertDictEqual(expected_result, result)
