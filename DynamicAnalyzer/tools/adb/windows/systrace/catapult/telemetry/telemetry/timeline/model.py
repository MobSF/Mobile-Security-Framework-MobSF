# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A container for timeline-based events and traces and can handle importing
raw event data from different sources. This model closely resembles that in the
trace_viewer project:
https://code.google.com/p/trace-viewer/
"""

import logging
from operator import attrgetter

from telemetry.timeline import async_slice as async_slice_module
from telemetry.timeline import bounds
from telemetry.timeline import event_container
from telemetry.timeline import inspector_importer
from telemetry.timeline import process as process_module
from telemetry.timeline import slice as slice_module
from telemetry.timeline import surface_flinger_importer
from telemetry.timeline import tab_id_importer
from telemetry.timeline import trace_event_importer
from tracing.trace_data import trace_data as trace_data_module


# Register importers for data

_IMPORTERS = [
    inspector_importer.InspectorTimelineImporter,
    tab_id_importer.TabIdImporter,
    trace_event_importer.TraceEventTimelineImporter,
    surface_flinger_importer.SurfaceFlingerTimelineImporter
]


class MarkerMismatchError(Exception):
  def __init__(self):
    super(MarkerMismatchError, self).__init__(
        'Number or order of timeline markers does not match provided labels')


class MarkerOverlapError(Exception):
  def __init__(self):
    super(MarkerOverlapError, self).__init__(
        'Overlapping timeline markers found')


def IsSliceOrAsyncSlice(t):
  if t == async_slice_module.AsyncSlice:
    return True
  return t == slice_module.Slice


class TimelineModel(event_container.TimelineEventContainer):
  def __init__(self, trace_data=None, shift_world_to_zero=True):
    """ Initializes a TimelineModel.

    Args:
        trace_data: trace_data.TraceData containing events to import
        shift_world_to_zero: If true, the events will be shifted such that the
            first event starts at time 0.
    """
    super(TimelineModel, self).__init__(name='TimelineModel', parent=None)
    self._bounds = bounds.Bounds()
    self._thread_time_bounds = {}
    self._processes = {}
    self._browser_process = None
    self._gpu_process = None
    self._surface_flinger_process = None
    self._frozen = False
    self._tab_ids_to_renderer_threads_map = {}
    self.import_errors = []
    self.metadata = []
    self.flow_events = []
    self._global_memory_dumps = None
    if trace_data is not None:
      self.ImportTraces(trace_data, shift_world_to_zero=shift_world_to_zero)

  def SetGlobalMemoryDumps(self, global_memory_dumps):
    """Populates the model with a sequence of GlobalMemoryDump objects."""
    assert not self._frozen and self._global_memory_dumps is None
    # Keep dumps sorted in chronological order.
    self._global_memory_dumps = tuple(sorted(global_memory_dumps,
                                             key=lambda dump: dump.start))

  def IterGlobalMemoryDumps(self):
    """Iterate over the memory dump events of this model."""
    return iter(self._global_memory_dumps or [])

  def IterChildContainers(self):
    for process in self._processes.itervalues():
      yield process

  def GetAllProcesses(self):
    return self._processes.values()

  def GetAllThreads(self):
    threads = []
    for process in self._processes.values():
      threads.extend(process.threads.values())
    return threads

  @property
  def bounds(self):
    return self._bounds

  @property
  def processes(self):
    return self._processes

  @property
  def browser_process(self):
    return self._browser_process

  @browser_process.setter
  def browser_process(self, browser_process):
    self._browser_process = browser_process

  @property
  def gpu_process(self):
    return self._gpu_process

  @gpu_process.setter
  def gpu_process(self, gpu_process):
    self._gpu_process = gpu_process

  @property
  def surface_flinger_process(self):
    return self._surface_flinger_process

  @surface_flinger_process.setter
  def surface_flinger_process(self, surface_flinger_process):
    self._surface_flinger_process = surface_flinger_process

  def AddMappingFromTabIdToRendererThread(self, tab_id, renderer_thread):
    if self._frozen:
      raise Exception('Cannot add mapping from tab id to renderer thread once '
                      'trace is imported')
    self._tab_ids_to_renderer_threads_map[tab_id] = renderer_thread

  def ImportTraces(self, trace_data, shift_world_to_zero=True):
    """Populates the model with the provided trace data.

    trace_data must be an instance of TraceData.

    Passing shift_world_to_zero=True causes the events to be shifted such that
    the first event starts at time 0.
    """
    if self._frozen:
      raise Exception("Cannot add events once trace is imported")
    assert isinstance(trace_data, trace_data_module.TraceData)

    importers = self._CreateImporters(trace_data)

    for importer in importers:
      # TODO: catch exceptions here and add it to error list
      importer.ImportEvents()
    self.FinalizeImport(shift_world_to_zero, importers)

  def FinalizeImport(self, shift_world_to_zero=False, importers=None):
    if importers == None:
      importers = []
    self.UpdateBounds()
    if not self.bounds.is_empty:
      for process in self._processes.itervalues():
        process.AutoCloseOpenSlices(self.bounds.max,
                                    self._thread_time_bounds)

    for importer in importers:
      importer.FinalizeImport()

    for process in self.processes.itervalues():
      process.FinalizeImport()

    if shift_world_to_zero:
      self.ShiftWorldToZero()
    self.UpdateBounds()

    # Because of FinalizeImport, it would probably be a good idea
    # to prevent the timeline from from being modified.
    self._frozen = True

  def ShiftWorldToZero(self):
    self.UpdateBounds()
    if self._bounds.is_empty:
      return
    shift_amount = self._bounds.min
    for event in self.IterAllEvents():
      event.start -= shift_amount

  def UpdateBounds(self):
    self._bounds.Reset()
    for event in self.IterAllEvents():
      self._bounds.AddValue(event.start)
      self._bounds.AddValue(event.end)

    self._thread_time_bounds = {}
    for thread in self.GetAllThreads():
      self._thread_time_bounds[thread] = bounds.Bounds()
      for event in thread.IterEventsInThisContainer(
          event_type_predicate=lambda t: True,
          event_predicate=lambda e: True):
        if event.thread_start != None:
          self._thread_time_bounds[thread].AddValue(event.thread_start)
        if event.thread_end != None:
          self._thread_time_bounds[thread].AddValue(event.thread_end)

  def GetOrCreateProcess(self, pid):
    if pid not in self._processes:
      assert not self._frozen
      self._processes[pid] = process_module.Process(self, pid)
    return self._processes[pid]

  def FindTimelineMarkers(self, timeline_marker_names):
    """Find the timeline events with the given names.

    If the number and order of events found does not match the names,
    raise an error.
    """
    # Make sure names are in a list and remove all None names
    if not isinstance(timeline_marker_names, list):
      timeline_marker_names = [timeline_marker_names]
    names = [x for x in timeline_marker_names if x is not None]

    # Gather all events that match the names and sort them.
    events = []
    name_set = set()
    for name in names:
      name_set.add(name)

    def IsEventNeeded(event):
      if event.parent_slice != None:
        return
      return event.name in name_set

    events = list(self.IterAllEvents(
      recursive=True,
      event_type_predicate=IsSliceOrAsyncSlice,
      event_predicate=IsEventNeeded))
    events.sort(key=attrgetter('start'))

    # Check if the number and order of events matches the provided names,
    # and that the events don't overlap.
    if len(events) != len(names):
      raise MarkerMismatchError()
    for (i, event) in enumerate(events):
      if event.name != names[i]:
        raise MarkerMismatchError()
    for i in xrange(0, len(events)):
      for j in xrange(i+1, len(events)):
        if events[j].start < events[i].start + events[i].duration:
          raise MarkerOverlapError()

    return events

  def GetRendererProcessFromTabId(self, tab_id):
    renderer_thread = self.GetRendererThreadFromTabId(tab_id)
    if renderer_thread:
      return renderer_thread.parent
    return None

  def GetRendererThreadFromTabId(self, tab_id):
    return self._tab_ids_to_renderer_threads_map.get(tab_id, None)

  def _CreateImporters(self, trace_data):
    def FindImporterClassForPart(part):
      for importer_class in _IMPORTERS:
        if importer_class.GetSupportedPart() == part:
          return importer_class

    importers = []
    for part in trace_data.active_parts:
      importer_class = FindImporterClassForPart(part)
      if not importer_class:
        logging.warning('No importer found for %s' % repr(part))
      else:
        importers.append(importer_class(self, trace_data))
        importers.sort(key=lambda k: k.import_order)

    return importers
