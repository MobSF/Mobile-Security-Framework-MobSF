# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from collections import namedtuple
from telemetry.testing import test_page_test_results
from telemetry.timeline import model as model_module
from telemetry.timeline import slice as slice_module
from telemetry.web_perf import timeline_interaction_record
from telemetry.web_perf.metrics.trace_event_stats import TraceEventStats
from telemetry.web_perf.metrics.trace_event_stats import TraceEventStatsInput


FakeEvent = namedtuple('Event', 'name, start, end, thread_duration, args')
Interaction = timeline_interaction_record.TimelineInteractionRecord
TEST_INTERACTION_LABEL = 'Action_TestInteraction'

RENDERER_PROCESS = 'Renderer'
OTHER_PROCESS = 'Other'

EVENT_CATEGORY1 = 'Category1'
EVENT_CATEGORY2 = 'Category2'

EVENT_NAME1 = 'Name1'
EVENT_NAME2 = 'Name2'


def TestInteraction(start, end):
  return Interaction(TEST_INTERACTION_LABEL, start, end)

class TraceEventStatsUnittest(unittest.TestCase):

  def setUp(self):
    self.model = model_module.TimelineModel()
    self.renderer_process = self.model.GetOrCreateProcess(1)
    self.renderer_process.name = RENDERER_PROCESS
    self.main_thread = self.renderer_process.GetOrCreateThread(tid=11)
    self.other_process = self.model.GetOrCreateProcess(2)
    self.other_process.name = OTHER_PROCESS
    self.other_thread = self.other_process.GetOrCreateThread(tid=12)

  def GetThreadForProcessName(self, process_name):
    if process_name is RENDERER_PROCESS:
      return self.main_thread
    elif process_name is OTHER_PROCESS:
      return self.other_thread
    else:
      raise

  def AddEvent(self, process_name, event_category, event_name,
               start, duration, thread_start, thread_duration):
    thread = self.GetThreadForProcessName(process_name)
    record = slice_module.Slice(thread,
                             event_category,
                             event_name,
                             start, duration, thread_start, thread_duration)
    thread.PushSlice(record)

  def RunAggregator(self, aggregator, interactions):
    results = test_page_test_results.TestPageTestResults(self)
    aggregator.AddResults(self.model, self.renderer_process,
                          interactions, results)
    return results

  def testBasicUsage(self):
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 10, 8, 10, 5)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 14, 2, 14, 2)
    interactions = [TestInteraction(9, 14)]

    aggregator = TraceEventStats()
    aggregator.AddInput(TraceEventStatsInput(
      EVENT_CATEGORY1,
      EVENT_NAME1,
      'metric-name',
      'metric-description',
      'units',
      'Renderer'))

    results = self.RunAggregator(aggregator, interactions)
    results.AssertHasPageSpecificScalarValue('metric-name-count', 'count', 2)
    results.AssertHasPageSpecificListOfScalarValues(
      'metric-name', 'units', [5, 2])

  def testFiltering(self):
    # These should be recorded.
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 10, 8, 10, 5)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 14, 2, 14, 2)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 20, 6, 20, 1)

    # These should be filtered.
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 15, 1, 15, 1)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY2, EVENT_NAME1, 11, 4, 11, 4)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME2, 11, 3, 11, 3)
    self.AddEvent(OTHER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 11, 2, 11, 2)

    interactions = [TestInteraction(9, 14), TestInteraction(20, 21)]

    aggregator = TraceEventStats()
    # Test that we default to 'Renderer'
    aggregator.AddInput(TraceEventStatsInput(
      EVENT_CATEGORY1,
      EVENT_NAME1,
      'metric-name',
      'metric-description',
      'units'))

    results = self.RunAggregator(aggregator, interactions)
    results.AssertHasPageSpecificScalarValue('metric-name-count', 'count', 3)
    results.AssertHasPageSpecificListOfScalarValues(
      'metric-name', 'units', [5, 2, 1])

  def testNoInputs(self):
    # These should be recorded.
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 10, 8, 10, 5)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 14, 2, 14, 2)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 20, 6, 20, 1)

    # These should be filtered.
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 15, 1, 15, 1)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY2, EVENT_NAME1, 11, 4, 11, 4)
    self.AddEvent(RENDERER_PROCESS, EVENT_CATEGORY1, EVENT_NAME2, 11, 3, 11, 3)
    self.AddEvent(OTHER_PROCESS, EVENT_CATEGORY1, EVENT_NAME1, 11, 2, 11, 2)

    interactions = [TestInteraction(9, 14), TestInteraction(20, 21)]

    aggregator = TraceEventStats()

    results = self.RunAggregator(aggregator, interactions)
    self.assertEquals([], results.all_page_specific_values)


  def testNoEvents(self):
    interactions = [TestInteraction(9, 14)]

    aggregator = TraceEventStats()
    aggregator.AddInput(TraceEventStatsInput(
      EVENT_CATEGORY1,
      EVENT_NAME1,
      'metric-name',
      'metric-description',
      'units'))

    results = self.RunAggregator(aggregator, interactions)
    self.assertEquals([], results.all_page_specific_values)
