# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.platform import cros_platform_backend


class CrosPlatformBackendTest(unittest.TestCase):
  initial_cstate = {
    'cpu0': 'POLL\nC1\nC2\nC3\n0\n138356189\n102416540\n'
            '17158209182\n0\n1\n500\n1000\n1403211341',
    'cpu1': 'POLL\nC1\nC2\nC3\n0\n107318149\n81786238\n'
            '17348563431\n0\n1\n500\n1000\n1403211341'
  }
  expected_cstate = {
    'cpu0': {
      'C0': 1403193942018089,
      'C1': 138356189,
      'C2': 102416540,
      'C3': 17158209182
    },
    'cpu1': {
      'C0': 1403193803332182,
      'C1': 107318149,
      'C2': 81786238,
      'C3': 17348563431
    }
  }
  def testCrosParseCpuStates(self):
    # Use mock start and end times to allow for the test to calculate C0.
    results = cros_platform_backend.CrosPlatformBackend.ParseCStateSample(
        self.initial_cstate)
    for cpu in results:
      for state in results[cpu]:
        self.assertAlmostEqual(results[cpu][state],
                               self.expected_cstate[cpu][state])
