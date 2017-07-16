# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import telemetry.timeline.counter as tracing_counter
import telemetry.timeline.event as event_module
import telemetry.timeline.event_container as event_container
import telemetry.timeline.thread as tracing_thread
from telemetry.timeline import memory_dump_event


class Process(event_container.TimelineEventContainer):
  """The Process represents a single userland process in the trace.
  """
  def __init__(self, parent, pid):
    super(Process, self).__init__('process %s' % pid, parent)
    self.pid = pid
    self.labels = None
    self.uptime_seconds = None
    self._threads = {}
    self._counters = {}
    self._trace_buffer_overflow_event = None
    self._memory_dump_events = {}

  @property
  def trace_buffer_did_overflow(self):
    return self._trace_buffer_overflow_event is not None

  @property
  def trace_buffer_overflow_event(self):
    return self._trace_buffer_overflow_event

  @property
  def threads(self):
    return self._threads

  @property
  def counters(self):
    return self._counters

  def IterChildContainers(self):
    for thread in self._threads.itervalues():
      yield thread
    for counter in self._counters.itervalues():
      yield counter

  def IterEventsInThisContainer(self, event_type_predicate, event_predicate):
    if (self.trace_buffer_did_overflow and
        event_type_predicate(event_module.TimelineEvent) and
        event_predicate(self._trace_buffer_overflow_event)):
      yield self._trace_buffer_overflow_event
    if (self._memory_dump_events and
        event_type_predicate(memory_dump_event.ProcessMemoryDumpEvent)):
      for memory_dump in self._memory_dump_events.itervalues():
        if event_predicate(memory_dump):
          yield memory_dump

  def GetOrCreateThread(self, tid):
    thread = self.threads.get(tid, None)
    if thread:
      return thread
    thread = tracing_thread.Thread(self, tid)
    self._threads[tid] = thread
    return thread

  def GetCounter(self, category, name):
    counter_id = category + '.' + name
    if counter_id in self.counters:
      return self.counters[counter_id]
    raise ValueError(
        'Counter %s not found in process with id %s.' % (counter_id,
                                                         self.pid))
  def GetOrCreateCounter(self, category, name):
    try:
      return self.GetCounter(category, name)
    except ValueError:
      ctr = tracing_counter.Counter(self, category, name)
      self._counters[ctr.full_name] = ctr
      return ctr

  def AutoCloseOpenSlices(self, max_timestamp, thread_time_bounds):
    for thread in self._threads.itervalues():
      thread.AutoCloseOpenSlices(max_timestamp, thread_time_bounds[thread].max)

  def SetTraceBufferOverflowTimestamp(self, timestamp):
    # TODO: use instant event for trace_buffer_overflow_event
    self._trace_buffer_overflow_event = event_module.TimelineEvent(
        "TraceBufferInfo", "trace_buffer_overflowed", timestamp, 0)

  def AddMemoryDumpEvent(self, memory_dump):
    """Add a ProcessMemoryDumpEvent to this process."""
    if memory_dump.dump_id in self._memory_dump_events:
      raise ValueError('Duplicate memory dump id %s in process with id %s.' % (
          memory_dump.dump_id, self.pid))
    self._memory_dump_events[memory_dump.dump_id] = memory_dump

  def FinalizeImport(self):
    for thread in self._threads.itervalues():
      thread.FinalizeImport()
    for counter in self._counters.itervalues():
      counter.FinalizeImport()
