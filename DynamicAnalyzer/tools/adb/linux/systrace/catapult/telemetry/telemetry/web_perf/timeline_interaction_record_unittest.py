# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import async_slice
from telemetry.timeline import model as model_module
from telemetry.timeline import slice as slice_module
from telemetry.web_perf import timeline_interaction_record as tir_module


class ParseTests(unittest.TestCase):

  def testParse(self):
    self.assertTrue(tir_module.IsTimelineInteractionRecord(
        'Interaction.Foo'))
    self.assertTrue(tir_module.IsTimelineInteractionRecord(
        'Interaction.Foo/Bar'))
    self.assertFalse(tir_module.IsTimelineInteractionRecord(
        'SomethingRandom'))


class TimelineInteractionRecordTests(unittest.TestCase):

  def CreateSimpleRecordWithName(self, event_name):
    s = async_slice.AsyncSlice(
        'cat', event_name,
        timestamp=0, duration=200, thread_start=20, thread_duration=100)
    return tir_module.TimelineInteractionRecord.FromAsyncEvent(s)

  def CreateTestSliceFromTimeRanges(
      self, parent_thread, time_start, time_end, thread_start, thread_end):
    duration = time_end - time_start
    thread_duration = thread_end - thread_start
    return slice_module.Slice(parent_thread, 'Test', 'foo', time_start,
                              duration, thread_start, thread_duration)

  def testCreate(self):
    r = self.CreateSimpleRecordWithName('Interaction.LogicalName')
    self.assertEquals('LogicalName', r.label)
    self.assertEquals(False, r.repeatable)

    r = self.CreateSimpleRecordWithName('Interaction.LogicalName/repeatable')
    self.assertEquals('LogicalName', r.label)
    self.assertEquals(True, r.repeatable)

    r = self.CreateSimpleRecordWithName(
        'Interaction.LogicalNameWith/Slash/repeatable')
    self.assertEquals('LogicalNameWith/Slash', r.label)
    self.assertEquals(True, r.repeatable)

  def testGetJavaScriptMarker(self):
    repeatable_marker = tir_module.GetJavaScriptMarker(
        'MyLabel', [tir_module.REPEATABLE])
    self.assertEquals('Interaction.MyLabel/repeatable', repeatable_marker)

  def testGetOverlappedThreadTimeForSliceInSameThread(self):
    # Create a renderer thread.
    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    model.FinalizeImport()

   # Make a record that starts at 30ms and ends at 60ms in thread time.
    s = async_slice.AsyncSlice(
        'cat', 'Interaction.Test',
        timestamp=0, duration=200, start_thread=renderer_main,
        end_thread=renderer_main, thread_start=30, thread_duration=30)
    record = tir_module.TimelineInteractionRecord.FromAsyncEvent(s)

    # Non overlapped range on the left of event.
    s1 = self.CreateTestSliceFromTimeRanges(renderer_main, 0, 100, 10, 20)
    self.assertEquals(0, record.GetOverlappedThreadTimeForSlice(s1))

    # Non overlapped range on the right of event.
    s2 = self.CreateTestSliceFromTimeRanges(renderer_main, 0, 100, 70, 90)
    self.assertEquals(0, record.GetOverlappedThreadTimeForSlice(s2))

    # Overlapped range on the left of event.
    s3 = self.CreateTestSliceFromTimeRanges(renderer_main, 0, 100, 20, 50)
    self.assertEquals(20, record.GetOverlappedThreadTimeForSlice(s3))

    # Overlapped range in the middle of event.
    s4 = self.CreateTestSliceFromTimeRanges(renderer_main, 0, 100, 40, 50)
    self.assertEquals(10, record.GetOverlappedThreadTimeForSlice(s4))

    # Overlapped range on the left of event.
    s5 = self.CreateTestSliceFromTimeRanges(renderer_main, 0, 100, 50, 90)
    self.assertEquals(10, record.GetOverlappedThreadTimeForSlice(s5))

  def testRepr(self):
    # Create a renderer thread.
    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    model.FinalizeImport()

    s = async_slice.AsyncSlice(
        'cat', 'Interaction.Test/repeatable',
        timestamp=0, duration=200, start_thread=renderer_main,
        end_thread=renderer_main, thread_start=30, thread_duration=30)
    record = tir_module.TimelineInteractionRecord.FromAsyncEvent(s)
    expected_repr = (
        'TimelineInteractionRecord(label=\'Test\', '
        'start=0.000000, end=200.000000, flags=repeatable, '
        'async_event=TimelineEvent(name=\'Interaction.Test/repeatable\','
        ' start=0.000000, duration=200, thread_start=30, thread_duration=30))')
    self.assertEquals(expected_repr, repr(record))


  def testGetOverlappedThreadTimeForSliceInDifferentThread(self):
    # Create a renderer thread and another thread.
    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    another_thread = model.GetOrCreateProcess(1).GetOrCreateThread(3)
    model.FinalizeImport()

   # Make a record that starts at 50ms and ends at 150ms in wall time, and is
   # scheduled 75% of the time (hence thread_duration = 100ms*75% = 75ms).
    s = async_slice.AsyncSlice(
        'cat', 'Interaction.Test',
        timestamp=50, duration=100, start_thread=renderer_main,
        end_thread=renderer_main, thread_start=55, thread_duration=75)
    record = tir_module.TimelineInteractionRecord.FromAsyncEvent(s)

    # Non overlapped range on the left of event.
    s1 = self.CreateTestSliceFromTimeRanges(another_thread, 25, 40, 28, 30)
    self.assertEquals(0, record.GetOverlappedThreadTimeForSlice(s1))

    # Non overlapped range on the right of event.
    s2 = self.CreateTestSliceFromTimeRanges(another_thread, 200, 300, 270, 290)
    self.assertEquals(0, record.GetOverlappedThreadTimeForSlice(s2))

    # Overlapped range on the left of event, and slice is scheduled 50% of the
    # time.
    # The overlapped wall-time duration is 50ms.
    # The overlapped thread-time duration is 50ms * 75% * 50% = 18.75
    s3 = self.CreateTestSliceFromTimeRanges(another_thread, 0, 100, 20, 70)
    self.assertEquals(18.75, record.GetOverlappedThreadTimeForSlice(s3))

    # Overlapped range in the middle of event, and slice is scheduled 20% of the
    # time.
    # The overlapped wall-time duration is 40ms.
    # The overlapped thread-time duration is 40ms * 75% * 20% = 6
    s4 = self.CreateTestSliceFromTimeRanges(another_thread, 100, 140, 120, 128)
    self.assertEquals(6, record.GetOverlappedThreadTimeForSlice(s4))

    # Overlapped range on the left of event, and slice is scheduled 100% of the
    # time.
    # The overlapped wall-time duration is 32ms.
    # The overlapped thread-time duration is 32ms * 75% * 100% = 24
    s5 = self.CreateTestSliceFromTimeRanges(another_thread, 118, 170, 118, 170)
    self.assertEquals(24, record.GetOverlappedThreadTimeForSlice(s5))
