# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import event


class TimelineEventTest(unittest.TestCase):
  def testHasThreadTimestamps(self):
    # No thread_start and no thread_duration
    event_1 = event.TimelineEvent('test', 'foo', 0, 10)
    # Has thread_start but no thread_duration
    event_2 = event.TimelineEvent('test', 'foo', 0, 10, 2)
    # Has thread_duration but no thread_start
    event_3 = event.TimelineEvent('test', 'foo', 0, 10, None, 4)
    # Has thread_start and thread_duration
    event_4 = event.TimelineEvent('test', 'foo', 0, 10, 2, 4)

    self.assertFalse(event_1.has_thread_timestamps)
    self.assertFalse(event_2.has_thread_timestamps)
    self.assertFalse(event_3.has_thread_timestamps)
    self.assertTrue(event_4.has_thread_timestamps)
