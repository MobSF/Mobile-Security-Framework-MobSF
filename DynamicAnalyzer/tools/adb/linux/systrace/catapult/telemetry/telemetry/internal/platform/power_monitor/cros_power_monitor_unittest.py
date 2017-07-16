# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform.power_monitor import cros_power_monitor


class CrosPowerMonitorMonitorTest(unittest.TestCase):
  initial_power = ('''line_power_connected 0
battery_present 1
battery_percent 70.20
battery_charge 2.83
battery_charge_full 4.03
battery_charge_full_design 4.03
battery_current 1.08
battery_energy 31.83
battery_energy_rate 12.78
battery_voltage 11.82
battery_discharging 1''')
  final_power = ('''line_power_connected 0
battery_present 1
battery_percent 70.20
battery_charge 2.83
battery_charge_full 4.03
battery_charge_full_design 4.03
battery_current 1.08
battery_energy 31.83
battery_energy_rate 12.80
battery_voltage 12.24
battery_discharging 1''')
  incomplete_final_power = ('''line_power_connected 0
battery_present 1
battery_percent 70.20
battery_charge 2.83
battery_charge_full 4.03
battery_charge_full_design 4.03
battery_energy_rate 12.80
battery_discharging 1''')
  expected_power = {
    'energy_consumption_mwh': 2558.0,
    'power_samples_mw': [12780.0, 12800.0],
    'component_utilization': {
      'battery': {
        'charge_full': 4.03,
        'charge_full_design': 4.03,
        'charge_now': 2.83,
        'current_now': 1.08,
        'energy': 31.83,
        'energy_rate': 12.80,
        'voltage_now': 12.24
      }
    }
  }
  expected_incomplete_power = {
    'energy_consumption_mwh': 2558.0,
    'power_samples_mw': [12780.0, 12800.0],
    'component_utilization': {
      'battery': {
        'charge_full': 4.03,
        'charge_full_design': 4.03,
        'charge_now': 2.83,
        'energy_rate': 12.80,
      }
    }
  }
  expected_cpu = {
    'whole_package': {
      'frequency_percent': {
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
      'cstate_residency_percent': {
        'C0': 83.67623835616438535,
        'C1': 0.2698609589041096,
        'C2': 0.2780191780821918,
        'C3': 15.77588150684931505
      }
    },
    'cpu0': {
      'frequency_percent': {
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
      'cstate_residency_percent': {
        'C0': 76.76226164383562,
        'C1': 0.3189164383561644,
        'C2': 0.4544301369863014,
        'C3': 22.4643917808219178
      }
    },
    'cpu1': {
      'frequency_percent': {
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
      'cstate_residency_percent': {
        'C0': 90.5902150684931507,
        'C1': 0.2208054794520548,
        'C2': 0.1016082191780822,
        'C3': 9.0873712328767123
      }
    }
  }

  def _assertPowerEqual(self, results, expected):
    battery = results['component_utilization']['battery']
    expected_battery = expected['component_utilization']['battery']
    self.assertItemsEqual(battery.keys(), expected_battery.keys())
    for value in battery:
      self.assertAlmostEqual(battery[value], expected_battery[value])

    self.assertAlmostEqual(results['energy_consumption_mwh'],
                           expected['energy_consumption_mwh'])
    self.assertAlmostEqual(results['power_samples_mw'][0],
                           expected['power_samples_mw'][0])
    self.assertAlmostEqual(results['power_samples_mw'][1],
                           expected['power_samples_mw'][1])

  def testParsePower(self):
    results = cros_power_monitor.CrosPowerMonitor.ParsePower(
        self.initial_power, self.final_power, 0.2)
    self._assertPowerEqual(results, self.expected_power)

  def testParseIncompletePowerState(self):
    """Test the case where dump_power_status only outputs partial fields.

    CrosPowerMonitor hard-coded expected fields from dump_power_status,
    this test ensures it parses successfully when expected fields does not
    exist. It's mainly for backward compatibility.
    """
    results = cros_power_monitor.CrosPowerMonitor.ParsePower(
        self.initial_power, self.incomplete_final_power, 0.2)
    self._assertPowerEqual(results, self.expected_incomplete_power)


  def testSplitSample(self):
    sample = self.initial_power + '\n1408739546\n'
    power, time = cros_power_monitor.CrosPowerMonitor.SplitSample(sample)
    self.assertEqual(power, self.initial_power)
    self.assertEqual(time, 1408739546)

  def testCombineResults(self):
    result = cros_power_monitor.CrosPowerMonitor.CombineResults(
        self.expected_cpu, self.expected_power)
    comp_util = result['component_utilization']
    # Test power values.
    self.assertEqual(result['energy_consumption_mwh'],
                     self.expected_power['energy_consumption_mwh'])
    self.assertEqual(result['power_samples_mw'],
                     self.expected_power['power_samples_mw'])
    self.assertEqual(comp_util['battery'],
                     self.expected_power['component_utilization']['battery'])
    # Test frequency values.
    self.assertDictEqual(
        comp_util['whole_package']['frequency_percent'],
        self.expected_cpu['whole_package']['frequency_percent'])
    self.assertDictEqual(
        comp_util['cpu0']['frequency_percent'],
        self.expected_cpu['cpu0']['frequency_percent'])
    self.assertDictEqual(
        comp_util['cpu1']['frequency_percent'],
        self.expected_cpu['cpu1']['frequency_percent'])
    # Test c-state residency values.
    self.assertDictEqual(
        comp_util['whole_package']['cstate_residency_percent'],
        self.expected_cpu['whole_package']['cstate_residency_percent'])
    self.assertDictEqual(
        comp_util['cpu0']['cstate_residency_percent'],
        self.expected_cpu['cpu0']['cstate_residency_percent'])
    self.assertDictEqual(
        comp_util['cpu1']['cstate_residency_percent'],
        self.expected_cpu['cpu1']['cstate_residency_percent'])

  def testCanMonitorPower(self):
    # TODO(tmandel): Add a test here where the device cannot monitor power.
    initial_status = cros_power_monitor.CrosPowerMonitor.ParsePowerStatus(
        self.initial_power)
    final_status = cros_power_monitor.CrosPowerMonitor.ParsePowerStatus(
        self.final_power)
    self.assertTrue(cros_power_monitor.CrosPowerMonitor.IsOnBatteryPower(
        initial_status, 'peppy'))
    self.assertTrue(cros_power_monitor.CrosPowerMonitor.IsOnBatteryPower(
        final_status, 'butterfly'))
