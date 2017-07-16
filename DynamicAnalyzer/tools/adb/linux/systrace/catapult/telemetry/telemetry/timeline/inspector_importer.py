# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Imports event data obtained from the inspector's timeline."""

from telemetry.timeline import importer
import telemetry.timeline.slice as tracing_slice
import telemetry.timeline.thread as timeline_thread
from tracing.trace_data import trace_data as trace_data_module


class InspectorTimelineImporter(importer.TimelineImporter):
  def __init__(self, model, trace_data):
    super(InspectorTimelineImporter, self).__init__(model,
                                                    trace_data,
                                                    import_order=1)
    traces = trace_data.GetTracesFor(
      trace_data_module.INSPECTOR_TRACE_PART)
    assert len(traces) == 1
    self._events = traces[0]

  @staticmethod
  def GetSupportedPart():
    return trace_data_module.INSPECTOR_TRACE_PART

  def ImportEvents(self):
    render_process = self._model.GetOrCreateProcess(0)
    for raw_event in self._events:
      thread = render_process.GetOrCreateThread(raw_event.get('thread', 0))
      InspectorTimelineImporter.AddRawEventToThreadRecursive(thread, raw_event)

  def FinalizeImport(self):
    pass

  @staticmethod
  def AddRawEventToThreadRecursive(thread, raw_inspector_event):
    pending_slice = None
    if ('startTime' in raw_inspector_event and
        'type' in raw_inspector_event):
      args = {}
      for x in raw_inspector_event:
        if x in ('startTime', 'endTime', 'children'):
          continue
        args[x] = raw_inspector_event[x]
      if len(args) == 0:
        args = None
      start_time = raw_inspector_event['startTime']
      end_time = raw_inspector_event.get('endTime', start_time)

      pending_slice = tracing_slice.Slice(
        thread, 'inspector',
        raw_inspector_event['type'],
        start_time,
        thread_timestamp=None,
        args=args)

    for child in raw_inspector_event.get('children', []):
      InspectorTimelineImporter.AddRawEventToThreadRecursive(
          thread, child)

    if pending_slice:
      pending_slice.duration = end_time - pending_slice.start
      thread.PushSlice(pending_slice)

  @staticmethod
  def RawEventToTimelineEvent(raw_inspector_event):
    """Converts raw_inspector_event to TimelineEvent."""
    thread = timeline_thread.Thread(None, 0)
    InspectorTimelineImporter.AddRawEventToThreadRecursive(
        thread, raw_inspector_event)
    thread.FinalizeImport()
    assert len(thread.toplevel_slices) <= 1
    if len(thread.toplevel_slices) == 0:
      return None
    return thread.toplevel_slices[0]
