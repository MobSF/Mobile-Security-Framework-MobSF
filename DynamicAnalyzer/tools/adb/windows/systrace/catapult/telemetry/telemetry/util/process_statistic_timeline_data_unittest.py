# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.util import process_statistic_timeline_data


class ProcessStatisticTimelineDataTest(unittest.TestCase):

  def testProcessStatisticValueMath(self):
    pid1 = 1
    pid2 = 2

    a = process_statistic_timeline_data.ProcessStatisticTimelineData(pid1, 5)
    b = process_statistic_timeline_data.ProcessStatisticTimelineData(pid2, 1)
    c = process_statistic_timeline_data.ProcessStatisticTimelineData(pid1, 1)

    # Test addition.
    addition_result = (a + b).value_by_pid
    self.assertEquals(5, addition_result[pid1])
    self.assertEquals(1, addition_result[pid2])
    self.assertEquals(2, len(addition_result.keys()))

    # Test subtraction.
    subtraction_result = ((a + b) - c).value_by_pid
    self.assertEquals(4, subtraction_result[pid1])
    self.assertEquals(1, subtraction_result[pid2])
    self.assertEquals(2, len(subtraction_result.keys()))

    # Test subtraction with a pid that exists only in rhs.
    subtraction_results1 = (a - (b + c)).value_by_pid
    self.assertEquals(4, subtraction_results1[pid1])
    self.assertEquals(1, len(subtraction_results1.keys()))

    # Test calculation of total sum.
    self.assertEquals(6, (a + b).total_sum())

  def testProcessStatisticValueSummary(self):
    pid1 = 1
    pid2 = 2

    a = process_statistic_timeline_data.ProcessStatisticTimelineData(pid1, 1)
    b = process_statistic_timeline_data.ProcessStatisticTimelineData(pid2, 99)
    c = a + b
    self.assertEquals(100, c.total_sum())
