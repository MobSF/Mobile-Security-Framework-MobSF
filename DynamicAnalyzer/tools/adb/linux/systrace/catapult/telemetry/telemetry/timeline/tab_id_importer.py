# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.timeline import importer
from tracing.trace_data import trace_data as trace_data_module


class TraceBufferOverflowException(Exception):
  pass


class TabIdImporter(importer.TimelineImporter):
  def __init__(self, model, trace_data):
    # Needs to run after all other importers so overflow events have been
    # created on the model.
    super(TabIdImporter, self).__init__(
        model,
        trace_data,
        import_order=999)
    self._trace_data = trace_data

  @staticmethod
  def GetSupportedPart():
    return trace_data_module.TAB_ID_PART

  def ImportEvents(self):
    pass

  def FinalizeImport(self):
    self._CheckTraceBufferOverflow()
    self._CreateTabIdsToThreadsMap()

  def _CheckTraceBufferOverflow(self):
    # Since _CreateTabIdsToThreadsMap() relies on markers output on timeline
    # tracing data, it may not work in case we have trace events dropped due to
    # trace buffer overflow.
    for process in self._model.GetAllProcesses():
      if process.trace_buffer_did_overflow:
        raise TraceBufferOverflowException(
            'Trace buffer of process with pid=%d overflowed at timestamp %d. '
            'Raw trace data:\n%s' %
            (process.pid, process.trace_buffer_overflow_event.start,
             repr(self._trace_data)))

  def _CreateTabIdsToThreadsMap(self):
    tab_id_events = []
    for tab_ids in self._trace_data.GetTracesFor(trace_data_module.TAB_ID_PART):
      tab_id_events.extend(tab_ids)

    for tab_id in tab_id_events:
      try:
        timeline_markers = self._model.FindTimelineMarkers(tab_id)
      # If timeline_markers with name equals |tab_id| can't be found, it's
      # non-fatal.
      except Exception:
        logging.warning('Cannot find timeline marker for tab with id=%s' %
                        tab_id)
        continue
      assert len(timeline_markers) == 1
      assert timeline_markers[0].start_thread == timeline_markers[0].end_thread
      self._model.AddMappingFromTabIdToRendererThread(
          tab_id, timeline_markers[0].start_thread)
