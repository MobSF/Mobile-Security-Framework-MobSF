# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from collections import namedtuple
from telemetry.internal.results import page_test_results
from telemetry.page import page
from telemetry.web_perf.metrics import single_event
from telemetry.web_perf import timeline_interaction_record

TRACE_EVENT_NAME = 'FrameView::performLayout'
METRIC_NAME = 'layout'
FakeEventTuple = namedtuple(
    'Event',
    'start, end, name, duration, thread_duration, has_thread_timestamps')
Interaction = timeline_interaction_record.TimelineInteractionRecord

class SingleEventTestMetric(single_event._SingleEventMetric):
  def __init__(self):
    super(SingleEventTestMetric, self).__init__(TRACE_EVENT_NAME, METRIC_NAME)

def GetSingleEventMetrics(events, interactions):
  results = page_test_results.PageTestResults()
  results.WillRunPage(page.Page('file://blank.html'))
  SingleEventTestMetric()._AddResultsInternal(events, interactions, results)
  return dict((value.name, value.values) for value in
              results.current_page_run.values)

def FakeEvent(start, end, name=TRACE_EVENT_NAME):
  dur = end - start
  return FakeEventTuple(start, end, name, dur, dur, True)


class SingleEventMetricUnitTest(unittest.TestCase):
  def testSingleEventMetric(self):
    events = [FakeEvent(0, 1),
              FakeEvent(9, 11),
              FakeEventTuple(10, 13, TRACE_EVENT_NAME, 3, 0, False),
              FakeEvent(20, 24),
              FakeEvent(21, 26),
              FakeEvent(29, 35),
              FakeEvent(30, 37),
              FakeEvent(40, 48),
              FakeEvent(41, 50),
              FakeEvent(10, 13, name='something'),
              FakeEvent(20, 24, name='FrameView::something'),
              FakeEvent(30, 37, name='SomeThing::performLayout'),
              FakeEvent(40, 48, name='something else')]
    interactions = [Interaction('interaction', 10, 20),
                    Interaction('interaction', 30, 40)]

    self.assertFalse(GetSingleEventMetrics(events, []))
    self.assertFalse(GetSingleEventMetrics([], interactions))

    # The first event starts before the first interaction, so it is ignored.
    # The second event starts before the first interaction, so it is ignored.
    # The third event starts during the first interaction, and its duration is
    # 13 - 10 = 3.
    # The fourth event starts during the first interaction, and its duration is
    # 24 - 20 = 4.
    # The fifth event starts between the two interactions, so it is ignored.
    # The sixth event starts between the two interactions, so it is ignored.
    # The seventh event starts during the second interaction, and its duration
    # is 37 - 30 = 7.
    # The eighth event starts during the second interaction, and its duration is
    # 48 - 40 = 8.
    # The ninth event starts after the last interaction, so it is ignored.
    # The rest of the events have the wrong name, so they are ignored.
    self.assertEqual({METRIC_NAME: [3, 4, 7, 8]}, GetSingleEventMetrics(
        events, interactions))
