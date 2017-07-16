# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from collections import defaultdict

from telemetry.timeline import bounds
from telemetry.timeline import slice as slice_module


class MissingData(Exception):
  pass


class NoBeginFrameIdException(Exception):
  pass


class RenderingFrame(object):
  """Object with information about the triggering of a BeginMainFrame event."""
  send_begin_frame_event = 'ThreadProxy::ScheduledActionSendBeginMainFrame'
  begin_main_frame_event = 'ThreadProxy::BeginMainFrame'

  def __init__(self, events):
    all_send_begin_frame_events = [e for e in events
                                   if e.name == self.send_begin_frame_event]
    if len(all_send_begin_frame_events) != 1:
      raise MissingData('There must be at exactly one %s event.' %
                        self.send_begin_frame_event)

    all_begin_main_frame_events = [e for e in events
                                   if e.name == self.begin_main_frame_event]
    if not all_begin_main_frame_events:
      raise MissingData('There must be at least one %s event.' %
                        self.begin_main_frame_event)
    all_begin_main_frame_events.sort(key=lambda e: e.start)

    self._send_begin_frame = all_send_begin_frame_events[0]
    self._begin_main_frame = all_begin_main_frame_events[-1]

    self._bounds = bounds.Bounds()
    self._bounds.AddEvent(self._begin_main_frame)
    self._bounds.AddEvent(self._send_begin_frame)

  @staticmethod
  def IsEventUseful(event):
    return event.name in [RenderingFrame.send_begin_frame_event,
                          RenderingFrame.begin_main_frame_event]

  @property
  def bounds(self):
    return self._bounds

  @property
  def queueing_duration(self):
    return self._begin_main_frame.start - self._send_begin_frame.start


def GetFrameEventsInsideRange(renderer_process, timeline_range):
  """Returns RenderingFrames for all relevant events in the timeline_range."""
  # First filter all events from the renderer_process and turn them into a
  # dictonary of the form:
  #   {0: [send_begin_frame, begin_main_frame, begin_main_frame],
  #    1: [begin_main_frame, send_begin_frame],
  #    2: [send_begin_frame, begin_main_frame]}
  begin_frame_events_by_id = defaultdict(list)
  for event in renderer_process.IterAllEvents(
      event_type_predicate=lambda t: t == slice_module.Slice,
      event_predicate=RenderingFrame.IsEventUseful):
    begin_frame_id = event.args.get('begin_frame_id', None)
    if begin_frame_id is None:
      raise NoBeginFrameIdException('Event is missing a begin_frame_id.')
    begin_frame_events_by_id[begin_frame_id].append(event)

  # Now, create RenderingFrames for events wherever possible.
  frames = []
  for events in begin_frame_events_by_id.values():
    try:
      frame = RenderingFrame(events)
      if frame.bounds.Intersects(timeline_range):
        frames.append(frame)
    except MissingData:
      continue
  frames.sort(key=lambda frame: frame.bounds.min)

  return frames
