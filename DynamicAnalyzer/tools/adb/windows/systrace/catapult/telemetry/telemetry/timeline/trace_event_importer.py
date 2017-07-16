# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""TraceEventImporter imports TraceEvent-formatted data
into the provided model.
This is a port of the trace event importer from
https://code.google.com/p/trace-viewer/
"""

import collections
import copy

import telemetry.timeline.async_slice as tracing_async_slice
import telemetry.timeline.flow_event as tracing_flow_event
from telemetry.timeline import importer
from telemetry.timeline import memory_dump_event
from tracing.trace_data import trace_data as trace_data_module


class TraceEventTimelineImporter(importer.TimelineImporter):
  def __init__(self, model, trace_data):
    super(TraceEventTimelineImporter, self).__init__(
        model, trace_data, import_order=1)
    assert isinstance(trace_data, trace_data_module.TraceData)
    self._trace_data = trace_data

    self._all_async_events = []
    self._all_object_events = []
    self._all_flow_events = []
    self._all_memory_dumps_by_dump_id = collections.defaultdict(list)

    self._events = []
    self._metadata = []
    for trace in trace_data.GetTracesFor(trace_data_module.CHROME_TRACE_PART):
      self._events.extend(trace['traceEvents'])
      self.CollectMetadataRecords(trace)

  def CollectMetadataRecords(self, trace):
    part_field_names = {p.raw_field_name for p in
                        trace_data_module.ALL_TRACE_PARTS}
    for k, v in trace.iteritems():
      if k in part_field_names:
        continue
      self._metadata.append({'name': k, 'value': v})


  @staticmethod
  def GetSupportedPart():
    return trace_data_module.CHROME_TRACE_PART

  def _GetOrCreateProcess(self, pid):
    return self._model.GetOrCreateProcess(pid)

  def _DeepCopyIfNeeded(self, obj):
    if self._trace_data.events_are_safely_mutable:
      return obj
    return copy.deepcopy(obj)

  def _ProcessAsyncEvent(self, event):
    """Helper to process an 'async finish' event, which will close an
    open slice.
    """
    thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
    self._all_async_events.append({
        'event': event,
        'thread': thread})

  def _ProcessCounterEvent(self, event):
    """Helper that creates and adds samples to a Counter object based on
    'C' phase events.
    """
    if 'id' in event:
      ctr_name = event['name'] + '[' + str(event['id']) + ']'
    else:
      ctr_name = event['name']

    ctr = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateCounter(event['cat'], ctr_name))
    # Initialize the counter's series fields if needed.
    if len(ctr.series_names) == 0:
      #TODO: implement counter object
      for series_name in event['args']:
        ctr.series_names.append(series_name)
      if len(ctr.series_names) == 0:
        self._model.import_errors.append('Expected counter ' + event['name'] +
            ' to have at least one argument to use as a value.')
        # Drop the counter.
        del ctr.parent.counters[ctr.full_name]
        return

    # Add the sample values.
    ctr.timestamps.append(event['ts'] / 1000.0)
    for series_name in ctr.series_names:
      if series_name not in event['args']:
        ctr.samples.append(0)
        continue
      ctr.samples.append(event['args'][series_name])

  def _ProcessObjectEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
      .GetOrCreateThread(event['tid']))
    self._all_object_events.append({
        'event': event,
        'thread': thread})

  def _ProcessDurationEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
      .GetOrCreateThread(event['tid']))
    if not thread.IsTimestampValidForBeginOrEnd(event['ts'] / 1000.0):
      self._model.import_errors.append(
          'Timestamps are moving backward.')
      return

    if event['ph'] == 'B':
      thread.BeginSlice(event['cat'],
                        event['name'],
                        event['ts'] / 1000.0,
                        event['tts'] / 1000.0 if 'tts' in event else None,
                        event['args'])
    elif event['ph'] == 'E':
      thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
      if not thread.IsTimestampValidForBeginOrEnd(event['ts'] / 1000.0):
        self._model.import_errors.append(
            'Timestamps are moving backward.')
        return
      if not thread.open_slice_count:
        self._model.import_errors.append(
            'E phase event without a matching B phase event.')
        return

      new_slice = thread.EndSlice(
          event['ts'] / 1000.0,
          event['tts'] / 1000.0 if 'tts' in event else None)
      for arg_name, arg_value in event.get('args', {}).iteritems():
        if arg_name in new_slice.args:
          self._model.import_errors.append(
              'Both the B and E phases of ' + new_slice.name +
              ' provided values for argument ' + arg_name + '. ' +
              'The value of the E phase event will be used.')
        new_slice.args[arg_name] = arg_value

  def _ProcessCompleteEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
    thread.PushCompleteSlice(
        event['cat'],
        event['name'],
        event['ts'] / 1000.0,
        event['dur'] / 1000.0 if 'dur' in event else None,
        event['tts'] / 1000.0 if 'tts' in event else None,
        event['tdur'] / 1000.0 if 'tdur' in event else None,
        event['args'])

  def _ProcessMarkEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
    thread.PushMarkSlice(
        event['cat'],
        event['name'],
        event['ts'] / 1000.0,
        event['tts'] / 1000.0 if 'tts' in event else None,
        event['args'] if 'args' in event else None)

  def _ProcessMetadataEvent(self, event):
    if event['name'] == 'thread_name':
      thread = (self._GetOrCreateProcess(event['pid'])
          .GetOrCreateThread(event['tid']))
      thread.name = event['args']['name']
    elif event['name'] == 'process_name':
      process = self._GetOrCreateProcess(event['pid'])
      process.name = event['args']['name']
    elif event['name'] == 'process_labels':
      process = self._GetOrCreateProcess(event['pid'])
      process.labels = event['args']['labels']
    elif event['name'] == 'process_uptime_seconds':
      process = self._GetOrCreateProcess(event['pid'])
      process.uptime_seconds = event['args']['uptime']
    elif event['name'] == 'trace_buffer_overflowed':
      process = self._GetOrCreateProcess(event['pid'])
      process.SetTraceBufferOverflowTimestamp(event['args']['overflowed_at_ts'])
    else:
      self._model.import_errors.append(
          'Unrecognized metadata name: ' + event['name'])

  def _ProcessInstantEvent(self, event):
    # Treat an Instant event as a duration 0 slice.
    # SliceTrack's redraw() knows how to handle this.
    thread = (self._GetOrCreateProcess(event['pid'])
      .GetOrCreateThread(event['tid']))
    thread.BeginSlice(event['cat'],
                      event['name'],
                      event['ts'] / 1000.0,
                      args=event.get('args'))
    thread.EndSlice(event['ts'] / 1000.0)

  def _ProcessSampleEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
    thread.AddSample(event['cat'],
                     event['name'],
                     event['ts'] / 1000.0,
                     event.get('args'))

  def _ProcessFlowEvent(self, event):
    thread = (self._GetOrCreateProcess(event['pid'])
        .GetOrCreateThread(event['tid']))
    self._all_flow_events.append({
        'event': event,
        'thread': thread})

  def _ProcessMemoryDumpEvents(self, events):
    # Dictionary to order dumps by id and process.
    global_dumps = {}
    for event in events:
      global_dump = global_dumps.setdefault(event['id'], {})
      dump_events = global_dump.setdefault(event['pid'], [])
      dump_events.append(event)
    for dump_id, global_dump in global_dumps.iteritems():
      for pid, dump_events in global_dump.iteritems():
        process = self._GetOrCreateProcess(pid)
        memory_dump = memory_dump_event.ProcessMemoryDumpEvent(process,
                                                               dump_events)
        process.AddMemoryDumpEvent(memory_dump)
        self._all_memory_dumps_by_dump_id[dump_id].append(memory_dump)

  def ImportEvents(self):
    """Walks through the events_ list and outputs the structures discovered to
    model_.
    """
    for r in self._metadata:
      self._model.metadata.append(r)
    memory_dump_events = []
    for event in self._events:
      phase = event.get('ph', None)
      if phase == 'B' or phase == 'E':
        self._ProcessDurationEvent(event)
      elif phase == 'X':
        self._ProcessCompleteEvent(event)
      # Note, S, F, T are deprecated and replaced by 'b' and 'e'. For
      # backwards compatibility continue to support them here.
      elif phase == 'S' or phase == 'F' or phase == 'T':
        self._ProcessAsyncEvent(event)
      elif phase == 'b' or phase == 'e':
        self._ProcessAsyncEvent(event)
      # Note, I is historic. The instant event marker got changed, but we
      # want to support loading old trace files so we have both I and i.
      elif phase == 'I' or phase == 'i':
        self._ProcessInstantEvent(event)
      elif phase == 'P':
        self._ProcessSampleEvent(event)
      elif phase == 'C':
        self._ProcessCounterEvent(event)
      elif phase == 'M':
        self._ProcessMetadataEvent(event)
      elif phase == 'N' or phase == 'D' or phase == 'O':
        self._ProcessObjectEvent(event)
      elif phase == 's' or phase == 't' or phase == 'f':
        self._ProcessFlowEvent(event)
      elif phase == 'v':
        memory_dump_events.append(event)
      elif phase == 'R':
        self._ProcessMarkEvent(event)
      else:
        self._model.import_errors.append('Unrecognized event phase: ' +
            phase + '(' + event['name'] + ')')

    # Memory dumps of a process with the same dump id need to be merged before
    # processing. So, memory dump events are processed all at once.
    self._ProcessMemoryDumpEvents(memory_dump_events)
    return self._model

  def FinalizeImport(self):
    """Called by the Model after all other importers have imported their
    events."""
    self._model.UpdateBounds()

    # We need to reupdate the bounds in case the minimum start time changes
    self._model.UpdateBounds()
    self._CreateAsyncSlices()
    self._CreateFlowSlices()
    self._SetBrowserProcess()
    self._SetGpuProcess()
    self._CreateExplicitObjects()
    self._CreateImplicitObjects()
    self._CreateMemoryDumps()

  def _CreateAsyncSlices(self):
    if len(self._all_async_events) == 0:
      return

    self._all_async_events.sort(key=lambda x: x['event']['ts'])

    async_event_states_by_name_then_id = {}

    all_async_events = self._all_async_events
    for async_event_state in all_async_events:
      event = async_event_state['event']
      name = event.get('name', None)
      if name is None:
        self._model.import_errors.append(
            'Async events (ph: b, e, S, T or F) require an name parameter.')
        continue

      event_id = event.get('id')
      if event_id is None:
        self._model.import_errors.append(
            'Async events (ph: b, e, S, T or F) require an id parameter.')
        continue

      # TODO(simonjam): Add a synchronous tick on the appropriate thread.

      if event['ph'] == 'S' or event['ph'] == 'b':
        if not name in async_event_states_by_name_then_id:
          async_event_states_by_name_then_id[name] = {}
        if event_id in async_event_states_by_name_then_id[name]:
          self._model.import_errors.append(
              'At %d, a slice of the same id %s was already open.' % (
                  event['ts'], event_id))
          continue

        async_event_states_by_name_then_id[name][event_id] = []
        async_event_states_by_name_then_id[name][event_id].append(
            async_event_state)
      else:
        if name not in async_event_states_by_name_then_id:
          self._model.import_errors.append(
              'At %d, no slice named %s was open.' % (event['ts'], name,))
          continue
        if event_id not in async_event_states_by_name_then_id[name]:
          self._model.import_errors.append(
              'At %d, no slice named %s with id=%s was open.' % (
                  event['ts'], name, event_id))
          continue
        events = async_event_states_by_name_then_id[name][event_id]
        events.append(async_event_state)

        if event['ph'] == 'F' or event['ph'] == 'e':
          # Create a slice from start to end.
          async_slice = tracing_async_slice.AsyncSlice(
              events[0]['event']['cat'],
              name,
              events[0]['event']['ts'] / 1000.0)

          async_slice.duration = ((event['ts'] / 1000.0)
              - (events[0]['event']['ts'] / 1000.0))

          async_slice.start_thread = events[0]['thread']
          async_slice.end_thread = async_event_state['thread']
          if async_slice.start_thread == async_slice.end_thread:
            if 'tts' in event and 'tts' in events[0]['event']:
              async_slice.thread_start = events[0]['event']['tts'] / 1000.0
              async_slice.thread_duration = ((event['tts'] / 1000.0)
                  - (events[0]['event']['tts'] / 1000.0))
          async_slice.id = event_id
          async_slice.args = events[0]['event']['args']

          # Create sub_slices for each step.
          for j in xrange(1, len(events)):
            sub_name = name
            if events[j - 1]['event']['ph'] == 'T':
              sub_name = name + ':' + events[j - 1]['event']['args']['step']
            sub_slice = tracing_async_slice.AsyncSlice(
                events[0]['event']['cat'],
                sub_name,
                events[j - 1]['event']['ts'] / 1000.0)
            sub_slice.parent_slice = async_slice

            sub_slice.duration = ((events[j]['event']['ts'] / 1000.0)
                - (events[j - 1]['event']['ts'] / 1000.0))

            sub_slice.start_thread = events[j - 1]['thread']
            sub_slice.end_thread = events[j]['thread']
            if sub_slice.start_thread == sub_slice.end_thread:
              if 'tts' in events[j]['event'] and \
                  'tts' in events[j - 1]['event']:
                sub_slice.thread_duration = \
                    ((events[j]['event']['tts'] / 1000.0)
                        - (events[j - 1]['event']['tts'] / 1000.0))

            sub_slice.id = event_id
            sub_slice.args = events[j - 1]['event']['args']

            async_slice.AddSubSlice(sub_slice)

          # The args for the finish event go in the last sub_slice.
          last_slice = async_slice.sub_slices[-1]
          for arg_name, arg_value in event['args'].iteritems():
            last_slice.args[arg_name] = arg_value

          # Add |async_slice| to the start-thread's async_slices.
          async_slice.start_thread.AddAsyncSlice(async_slice)
          del async_event_states_by_name_then_id[name][event_id]

  def _CreateExplicitObjects(self):
    # TODO(tengs): Implement object instance parsing
    pass

  def _CreateImplicitObjects(self):
    # TODO(tengs): Implement object instance parsing
    pass

  def _CreateFlowSlices(self):
    if len(self._all_flow_events) == 0:
      return

    self._all_flow_events.sort(key=lambda x: x['event']['ts'])

    flow_id_to_event = {}
    for data in self._all_flow_events:
      event = data['event']
      thread = data['thread']
      if 'name' not in event:
        self._model.import_errors.append(
          'Flow events (ph: s, t or f) require a name parameter.')
        continue
      if 'id' not in event:
        self._model.import_errors.append(
          'Flow events (ph: s, t or f) require an id parameter.')
        continue

      flow_event = tracing_flow_event.FlowEvent(
          event['cat'],
          event['id'],
          event['name'],
          event['ts'] / 1000.0,
          event['args'])
      thread.AddFlowEvent(flow_event)

      if event['ph'] == 's':
        if event['id'] in flow_id_to_event:
          self._model.import_errors.append(
              'event id %s already seen when encountering start of'
              'flow event.' % event['id'])
          continue
        flow_id_to_event[event['id']] = flow_event
      elif event['ph'] == 't' or event['ph'] == 'f':
        if not event['id'] in flow_id_to_event:
          self._model.import_errors.append(
            'Found flow phase %s for id: %s but no flow start found.' % (
                event['ph'], event['id']))
          continue
        flow_position = flow_id_to_event[event['id']]
        self._model.flow_events.append([flow_position, flow_event])

        if event['ph'] == 'f':
          del flow_id_to_event[event['id']]
        else:
          # Make this event the next start event in this flow.
          flow_id_to_event[event['id']] = flow_event

  def _CreateMemoryDumps(self):
    self._model.SetGlobalMemoryDumps(
        memory_dump_event.GlobalMemoryDump(events)
        for events in self._all_memory_dumps_by_dump_id.itervalues())

  def _SetBrowserProcess(self):
    for thread in self._model.GetAllThreads():
      if thread.name == 'CrBrowserMain':
        self._model.browser_process = thread.parent

  def _SetGpuProcess(self):
    for thread in self._model.GetAllThreads():
      if thread.name == 'CrGpuMain':
        self._model.gpu_process = thread.parent
