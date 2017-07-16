# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.timeline import importer
from tracing.trace_data import trace_data as trace_data_module


class SurfaceFlingerTimelineImporter(importer.TimelineImporter):
  def __init__(self, model, trace_data):
    super(SurfaceFlingerTimelineImporter, self).__init__(
        model, trace_data, import_order=2)
    traces = trace_data.GetTracesFor(trace_data_module.SURFACE_FLINGER_PART)
    assert len(traces) == 1
    self._events = traces[0]
    self._surface_flinger_process = None

  @staticmethod
  def GetSupportedPart():
    return trace_data_module.SURFACE_FLINGER_PART

  def ImportEvents(self):
    for event in self._events:
      self._surface_flinger_process = self._model.GetOrCreateProcess(
          event['pid'])
      self._surface_flinger_process.name = 'SurfaceFlinger'
      thread = self._surface_flinger_process.GetOrCreateThread(event['tid'])
      thread.BeginSlice(event['cat'],
                        event['name'],
                        event['ts'],
                        args=event.get('args'))
      thread.EndSlice(event['ts'])

  def FinalizeImport(self):
    """Called by the Model after all other importers have imported their
    events."""
    self._model.UpdateBounds()
    self._model.surface_flinger_process = self._surface_flinger_process
