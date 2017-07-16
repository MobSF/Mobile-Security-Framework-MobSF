# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import telemetry.timeline.event as timeline_event
from telemetry.testing import test_page_test_results
from telemetry.web_perf.metrics import startup


class StartupTimelineMetricTest(unittest.TestCase):

  def setUp(self):
    self.events = []

  def AddEvent(self, event_name, start, duration=None):
    event = timeline_event.TimelineEvent('my_category', event_name,
                                         start, duration)
    self.events.append(event)

  # Attributes defined outside __init__
  # pylint: disable=attribute-defined-outside-init
  def ComputeStartupMetrics(self):
    results = test_page_test_results.TestPageTestResults(self)

    # Create a mock model usable by
    # StartupTimelineMetric.AddWholeTraceResults().
    def IterateEvents(event_predicate):
      for event in self.events:
        if event_predicate(event):
          yield event
    class MockClass(object):
      pass
    model = MockClass()
    model.browser_process = MockClass()
    model.browser_process.parent = MockClass()
    model.browser_process.parent.IterAllEvents = IterateEvents

    startup.StartupTimelineMetric().AddWholeTraceResults(model, results)
    return results

  def testUntrackedvents(self):
    # Code coverage for untracked events
    self.AddEvent('uknown_event_0', 0)
    self.AddEvent('uknown_event_1', 1)
    self.ComputeStartupMetrics()

  def testInstantEventsBasedValue(self):
    # Test case with instant events to measure the duration between the first
    # occurrences of two distinct events.
    START0 = 7
    START1 = 8
    DURATION0 = 17
    DURATION1 = 18

    # Generate duplicated events to make sure we consider only the first one.
    self.AddEvent(startup._MAIN_ENTRY_POINT, START0)
    self.AddEvent(startup._MAIN_ENTRY_POINT, START1)
    self.AddEvent('loadEventEnd', START0 + DURATION0)
    self.AddEvent('loadEventEnd', START1 + DURATION1)
    self.AddEvent('requestStart', START0 + DURATION0 * 2)
    self.AddEvent('requestStart', START1 + DURATION1 * 2)

    results = self.ComputeStartupMetrics()
    results.AssertHasPageSpecificScalarValue('foreground_tab_load_complete',
        'ms', DURATION0)
    results.AssertHasPageSpecificScalarValue('foreground_tab_request_start',
        'ms', DURATION0 * 2)

  def testDurationEventsBasedValues(self):
    DURATION_EVENTS = set([
        'messageloop_start_time',
        'window_display_time',
        'open_tabs_time',
        'first_non_empty_paint_time',
        'first_main_frame_load_time'])

    # Test case to get the duration of the first occurrence of a duration event.
    i = 1
    for display_name in DURATION_EVENTS:
      self.assertTrue(len(startup._METRICS[display_name]) == 1)
      event_name = startup._METRICS[display_name][0]

      duration = 13 * i
      i += 1

      # Generate duplicated events to make sure only the first event is
      # considered.
      self.AddEvent(event_name, 5, duration)
      self.AddEvent(event_name, 6, duration + 2)

    results = self.ComputeStartupMetrics()

    i = 1
    for display_name in DURATION_EVENTS:
      duration = 13 * i
      i += 1

      results.AssertHasPageSpecificScalarValue(display_name, 'ms', duration)
