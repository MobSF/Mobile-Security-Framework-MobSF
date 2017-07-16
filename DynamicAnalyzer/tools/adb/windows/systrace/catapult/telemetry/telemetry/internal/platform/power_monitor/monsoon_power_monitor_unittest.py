# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import unittest

from telemetry.internal.platform.power_monitor import monsoon_power_monitor


class MonsoonPowerMonitorTest(unittest.TestCase):

  def testEnergyComsumption(self):
    data = {
        'duration_s': 3600.0,
        'samples': [(1.0, 1.0), (2.0, 2.0), (3.0, 3.0), (4.0, 4.0)]
    }
    results = monsoon_power_monitor.MonsoonPowerMonitor.ParseSamplingOutput(
        json.dumps(data))
    self.assertEqual(results['power_samples_mw'], [1000, 4000, 9000, 16000])
    self.assertEqual(results['monsoon_energy_consumption_mwh'], 7500)
