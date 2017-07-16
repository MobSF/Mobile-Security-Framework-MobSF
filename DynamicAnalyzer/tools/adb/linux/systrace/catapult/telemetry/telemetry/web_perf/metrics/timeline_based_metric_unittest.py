# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import telemetry.web_perf.metrics.timeline_based_metric as tbm_module


class FakeEvent(object):
  def __init__(self, start, end):
    self.start = start
    self.end = end


class FakeRecord(object):
  def __init__(self, start, end):
    self.start = start
    self.end = end


class TimelineBasedMetricTest(unittest.TestCase):

  # pylint: disable=protected-access
  def testTimeRangesHasOverlap(self):
    # Test cases with overlap on one side
    self.assertTrue(tbm_module._TimeRangesHasOverlap([(10, 20), (5, 15)]))
    self.assertTrue(tbm_module._TimeRangesHasOverlap([(5, 15), (10, 20)]))
    self.assertTrue(tbm_module._TimeRangesHasOverlap(
        [(5, 15), (25, 30), (10, 20)]))

    # Test cases with one range fall in the middle of other
    self.assertTrue(tbm_module._TimeRangesHasOverlap([(10, 20), (15, 18)]))
    self.assertTrue(tbm_module._TimeRangesHasOverlap([(15, 18), (10, 20)]))
    self.assertTrue(tbm_module._TimeRangesHasOverlap(
        [(15, 18), (40, 50), (10, 20)]))

    self.assertFalse(tbm_module._TimeRangesHasOverlap([(15, 18), (20, 25)]))
    self.assertFalse(tbm_module._TimeRangesHasOverlap(
        [(1, 2), (2, 3), (0, 1)]))

  def testIsEventInInteractions(self):
    self.assertFalse(
        tbm_module.IsEventInInteractions(
        FakeEvent(0, 100),
        [FakeRecord(5, 105), FakeRecord(50, 200), FakeRecord(300, 400)]))
    self.assertFalse(
        tbm_module.IsEventInInteractions(
        FakeEvent(50, 100),
        [FakeRecord(105, 205), FakeRecord(0, 45), FakeRecord(0, 90)]))
    self.assertTrue(
        tbm_module.IsEventInInteractions(
        FakeEvent(50, 100),
        [FakeRecord(5, 105), FakeRecord(0, 45), FakeRecord(0, 90)]))
    self.assertTrue(
        tbm_module.IsEventInInteractions(
        FakeEvent(50, 100),
        [FakeRecord(5, 45), FakeRecord(0, 45), FakeRecord(0, 100)]))
