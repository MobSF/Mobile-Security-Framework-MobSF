# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from collections import namedtuple
from telemetry.internal.results import page_test_results
from telemetry.page import page
from telemetry.web_perf.metrics import blob_timeline
from telemetry.web_perf import timeline_interaction_record


FakeEvent = namedtuple('Event', 'name, start, end, thread_duration, args')
Interaction = timeline_interaction_record.TimelineInteractionRecord
TEST_INTERACTION_LABEL = 'Action_TestInteraction'
WRITE_EVENT_NAME = 'Registry::RegisterBlob'
READ_EVENT_NAME = 'BlobRequest'


def GetBlobMetrics(events, interactions):
  results = page_test_results.PageTestResults()
  test_page = page.Page('file://blank.html')
  results.WillRunPage(test_page)
  blob_timeline.BlobTimelineMetric()._AddWriteResultsInternal(
      events, interactions, results)  # pylint:disable=protected-access
  blob_timeline.BlobTimelineMetric()._AddReadResultsInternal(
      events, interactions, results)  # pylint:disable=protected-access
  return_dict = dict((value.name, value.values) for value in
                     results.current_page_run.values)
  results.DidRunPage(test_page)
  return return_dict

def FakeWriteEvent(start, end, thread_duration=None):
  if not thread_duration:
    thread_duration = end - start
  return FakeEvent(blob_timeline.WRITE_EVENT_NAME,
                   start, end, thread_duration, {'uuid':'fakeuuid'})

def FakeReadEvent(start, end, uuid, thread_duration=None):
  if not thread_duration:
    thread_duration = end - start
  return FakeEvent(blob_timeline.READ_EVENT_NAME,
                   start, end, thread_duration, {'uuid': uuid})

def TestInteraction(start, end):
  return Interaction(TEST_INTERACTION_LABEL, start, end)


class BlobTimelineMetricUnitTest(unittest.TestCase):
  def testWriteMetric(self):
    events = [FakeWriteEvent(0, 1),
              FakeWriteEvent(9, 11),
              FakeWriteEvent(10, 13),
              FakeWriteEvent(20, 24),
              FakeWriteEvent(21, 26),
              FakeWriteEvent(29, 35),
              FakeWriteEvent(30, 37),
              FakeWriteEvent(40, 48),
              FakeWriteEvent(41, 50),
              FakeEvent('something', 10, 13, 3, {}),
              FakeEvent('FrameView::something', 20, 24, 4, {}),
              FakeEvent('SomeThing::performLayout', 30, 37, 7, {}),
              FakeEvent('something else', 40, 48, 8, {})]
    interactions = [TestInteraction(10, 20),
                    TestInteraction(30, 40)]

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
    # The eighth event starts during the second interaction and its duration is
    # 48 - 40 = 8.
    # The ninth event starts after the last interaction, so it is ignored.
    # The rest of the events are not layout events, so they are ignored.
    self.assertEqual({'blob-reads': None, 'blob-writes': [3, 4, 7, 8]},
        GetBlobMetrics(events, interactions))

  def testReadMetric(self):
    events = [FakeReadEvent(0, 1, 'a'),
              FakeReadEvent(9, 11, 'a'),
              FakeReadEvent(10, 13, 'b', 1), # counts
              FakeReadEvent(15, 18, 'b'),    # counts
              FakeReadEvent(21, 26, 'b'),
              FakeReadEvent(29, 35, 'c'),
              FakeReadEvent(31, 32, 'e'),    # counts
              FakeReadEvent(34, 36, 'e', 1), # counts
              FakeReadEvent(32, 37, 'd'),    # counts
              FakeEvent('something', 10, 13, 3, {}),
              FakeEvent('something else', 40, 48, 8, {})]
    interactions = [TestInteraction(10, 20),
                    TestInteraction(30, 40)]

    # We ignore events outside of the interaction intervals, and we use the
    # beginning of the first event of the interval and the end of the last
    # event.
    # 18 - 10 = 8
    # 37 - 32 = 5
    self.assertEqual({'blob-reads': [4, 2, 5], 'blob-writes': None},
        GetBlobMetrics(events, interactions))

  def testReadAndWriteMetrics(self):
    events = [FakeReadEvent(0, 1, 'a'),
              FakeReadEvent(9, 11, 'a'),
              FakeReadEvent(10, 13, 'b'),     # counts
              FakeWriteEvent(15, 18),         # counts
              FakeReadEvent(21, 26, 'c'),
              FakeReadEvent(29, 35, 'd'),
              FakeWriteEvent(31, 34, 1), # counts
              FakeReadEvent(32, 33, 'e'),     # counts
              FakeReadEvent(34, 35, 'e'),     # counts
              FakeEvent('something', 31, 33, 2, {})]
    interactions = [TestInteraction(10, 20),
                    TestInteraction(30, 35)]

    # We use the read events in the interactions, so the same as the test above.
    self.assertEqual({'blob-reads': [3, 2], 'blob-writes': [3, 1]},
      GetBlobMetrics(events, interactions))
