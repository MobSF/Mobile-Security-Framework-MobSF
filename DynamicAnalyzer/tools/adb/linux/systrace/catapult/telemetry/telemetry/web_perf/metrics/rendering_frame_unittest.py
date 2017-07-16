# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import telemetry.timeline.bounds as timeline_bounds
from telemetry.timeline import model
import telemetry.timeline.slice as tracing_slice
from telemetry.web_perf.metrics. \
    rendering_frame import GetFrameEventsInsideRange
from telemetry.web_perf.metrics.rendering_frame import MissingData
from telemetry.web_perf.metrics.rendering_frame import RenderingFrame


class RenderingFrameTestData(object):

  def __init__(self):
    self._begin_frame_id = 0
    self._events = []
    self._renderer_process = model.TimelineModel().GetOrCreateProcess(pid=1)
    self._main_thread = self._renderer_process.GetOrCreateThread(tid=11)
    self._compositor_thread = self._renderer_process.GetOrCreateThread(tid=12)

  @property
  def events(self):
    return self._events

  @property
  def renderer_process(self):
    return self._renderer_process

  def AddSendEvent(self, ts=0, duration=1):
    self._begin_frame_id += 1
    event = self._CreateEvent(
        RenderingFrame.send_begin_frame_event, ts, duration)
    self._compositor_thread.PushSlice(event)

  def AddBeginMainFrameEvent(self, ts=0, duration=1):
    event = self._CreateEvent(
        RenderingFrame.begin_main_frame_event, ts, duration)
    self._main_thread.PushSlice(event)

  def FinalizeImport(self):
    self._renderer_process.FinalizeImport()

  def _CreateEvent(self, event_name, ts, duration):
    event = tracing_slice.Slice(None, 'cc,benchmark', event_name, ts,
        duration=duration, args={'begin_frame_id': self._begin_frame_id})
    self._events.append(event)
    return event


def GenerateTimelineRange(start=0, end=100):
  timeline_range = timeline_bounds.Bounds()
  timeline_range.AddValue(start)
  timeline_range.AddValue(end)
  return timeline_range


class RenderingFrameUnitTest(unittest.TestCase):

  def testRenderingFrame(self):
    d = RenderingFrameTestData()
    d.AddSendEvent(ts=10)
    d.AddBeginMainFrameEvent(ts=20)
    d.FinalizeImport()

    frame = RenderingFrame(d.events)
    self.assertEquals(10, frame.queueing_duration)

  def testRenderingFrameMissingSendBeginFrameEvents(self):
    d = RenderingFrameTestData()
    d.AddBeginMainFrameEvent(ts=10)
    d.FinalizeImport()

    self.assertRaises(MissingData, RenderingFrame, d.events)

  def testRenderingFrameDuplicateSendBeginFrameEvents(self):
    d = RenderingFrameTestData()
    d.AddSendEvent(ts=10)
    d.AddBeginMainFrameEvent(ts=20)
    d.AddSendEvent(ts=30)
    d.FinalizeImport()

    self.assertRaises(MissingData, RenderingFrame, d.events)

  def testRenderingFrameMissingBeginMainFrameEvents(self):
    d = RenderingFrameTestData()
    d.AddSendEvent(ts=10)
    d.FinalizeImport()

    self.assertRaises(MissingData, RenderingFrame, d.events)

  def testRenderingFrameDuplicateBeginMainFrameEvents(self):
    d = RenderingFrameTestData()
    d.AddSendEvent(ts=10)
    d.AddBeginMainFrameEvent(ts=20)
    d.AddBeginMainFrameEvent(ts=30)
    d.AddBeginMainFrameEvent(ts=40)
    d.FinalizeImport()

    frame = RenderingFrame(d.events)
    self.assertEquals(30, frame.queueing_duration)

  def testFrameEventMissingBeginFrameId(self):
    timeline = model.TimelineModel()
    process = timeline.GetOrCreateProcess(pid=1)
    main_thread = process.GetOrCreateThread(tid=11)
    timeline_range = timeline_bounds.Bounds()

    # Create an event without the begin_frame_id argument
    event = tracing_slice.Slice(
        None, 'cc,benchmark', RenderingFrame.begin_main_frame_event, 0)
    main_thread.PushSlice(event)
    process.FinalizeImport()
    self.assertRaises(Exception, GetFrameEventsInsideRange, process,
                      timeline_range)

  def testGetFrameEventsInsideRange(self):
    """Test a basic sequenece, with expected frame queueing delays A and B.

                 |----A----|    |--B--|
         Main:        [1]  [1]        [2]

    Compositor:  [1]            [2]
    """
    d = RenderingFrameTestData()
    d.AddSendEvent(ts=10)
    d.AddBeginMainFrameEvent(ts=20)
    d.AddBeginMainFrameEvent(ts=30)
    d.AddSendEvent(ts=40)
    d.AddBeginMainFrameEvent(ts=50)
    d.FinalizeImport()

    timeline_range = GenerateTimelineRange()
    frame_events = GetFrameEventsInsideRange(d.renderer_process, timeline_range)

    self.assertEquals(2, len(frame_events))
    self.assertEquals(20, frame_events[0].queueing_duration)
    self.assertEquals(10, frame_events[1].queueing_duration)

  def testFrameEventsMissingDataNotIncluded(self):
    """Test a sequenece missing an initial SendBeginFrame.

    Only one frame should be returned, with expected frame queueing delay A.
                           |--A--|
          Main:  [0]  [0]        [2]

    Compositor:            [2]
    """
    d = RenderingFrameTestData()
    d.AddBeginMainFrameEvent(ts=20)
    d.AddBeginMainFrameEvent(ts=30)
    d.AddSendEvent(ts=40)
    d.AddBeginMainFrameEvent(ts=50)
    d.FinalizeImport()

    timeline_range = GenerateTimelineRange()
    frame_events = GetFrameEventsInsideRange(d.renderer_process, timeline_range)

    self.assertEquals(1, len(frame_events))
    self.assertEquals(10, frame_events[0].queueing_duration)
