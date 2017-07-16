# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from collections import namedtuple
from telemetry.internal.results import page_test_results
from telemetry.page import page
from telemetry.web_perf.metrics import jitter_timeline
from telemetry.web_perf import timeline_interaction_record


FakeEvent = namedtuple('Event', 'name, start, end, thread_duration, args')
Interaction = timeline_interaction_record.TimelineInteractionRecord
TEST_INTERACTION_LABEL = 'Action_TestInteraction'
JITTER_EVENT_NAME = 'jitter'

def GetJitterMetrics(events, interactions):
  results = page_test_results.PageTestResults()
  test_page = page.Page('file://blank.html')
  results.WillRunPage(test_page)
  jitter_timeline.JitterTimelineMetric()._AddJitterResultsInternal(
      events, interactions, results)
  return_dict = dict((value.name, value.values) for value in
                     results.current_page_run.values)
  results.DidRunPage(test_page)
  return return_dict

def FakeJitterEvent(start, end, value, thread_duration=None):
  if not thread_duration:
    thread_duration = end - start
  return FakeEvent(jitter_timeline.JITTER_EVENT_NAME,
          start, end, thread_duration, {'value':value})

def TestInteraction(start, end):
  return Interaction(TEST_INTERACTION_LABEL, start, end)


class JitterTimelineMetricUnitTest(unittest.TestCase):
  def testJitterMetric(self):
    events = [FakeJitterEvent(0, 1, 10),
              FakeJitterEvent(5, 10, 5),
              FakeJitterEvent(15, 34, 45)]
    interactions = [TestInteraction(4, 14)]
    # The first and the last event do not start during the interaction, so
    # they are ignored. The second event starts during the interaction, and its
    # value is 5.
    self.assertEqual({'jitter-amount': [5]},
        GetJitterMetrics(events, interactions))
