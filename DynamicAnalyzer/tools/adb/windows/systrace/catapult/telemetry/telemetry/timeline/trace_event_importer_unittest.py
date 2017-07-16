# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=too-many-lines

import unittest

import telemetry.timeline.counter as tracing_counter
import telemetry.timeline.model as timeline_model
from tracing.trace_data import trace_data as trace_data_module


def FindEventNamed(events, name):
  for event in events:
    if event.name == name:
      return event
  raise ValueError('No event found with name %s' % name)

class TraceEventTimelineImporterTest(unittest.TestCase):

  def testBasicSingleThreadNonnestedParsing(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 520, 'tts': 280, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 560, 'tts': 310, 'cat': 'foo',
       'tid': 53, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 629, 'tts': 356, 'cat': 'bar',
       'tid': 53, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 631, 'tts': 357, 'cat': 'bar',
       'tid': 53, 'ph': 'E'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 633, 'cat': 'baz',
       'tid': 53, 'ph': 'B'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 637, 'cat': 'baz',
       'tid': 53, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]
    self.assertEqual(52, p.pid)

    self.assertEqual(1, len(p.threads))
    t = p.threads[53]
    self.assertEqual(3, len(t.all_slices))
    self.assertEqual(53, t.tid)
    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual((560 - 520) / 1000.0, slice_event.duration)
    self.assertAlmostEqual((560 - 520) / 1000.0, slice_event.end)
    self.assertAlmostEqual(280 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((310 - 280) / 1000.0, slice_event.thread_duration)
    self.assertAlmostEqual(310 / 1000.0, slice_event.thread_end)
    self.assertEqual(0, len(slice_event.sub_slices))

    slice_event = t.all_slices[1]
    self.assertEqual('b', slice_event.name)
    self.assertEqual('bar', slice_event.category)
    self.assertAlmostEqual((629 - 520) / 1000.0, slice_event.start)
    self.assertAlmostEqual((631 - 629) / 1000.0, slice_event.duration)
    self.assertAlmostEqual((631 - 520) / 1000.0, slice_event.end)
    self.assertAlmostEqual(356 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((357 - 356) / 1000.0, slice_event.thread_duration)
    self.assertAlmostEqual(357 / 1000.0, slice_event.thread_end)
    self.assertEqual(0, len(slice_event.sub_slices))

    slice_event = t.all_slices[2]
    self.assertEqual('c', slice_event.name)
    self.assertEqual('baz', slice_event.category)
    self.assertAlmostEqual((633 - 520) / 1000.0, slice_event.start)
    self.assertAlmostEqual((637 - 633) / 1000.0, slice_event.duration)
    self.assertEqual(None, slice_event.thread_start)
    self.assertEqual(None, slice_event.thread_duration)
    self.assertEqual(None, slice_event.thread_end)
    self.assertEqual(0, len(slice_event.sub_slices))


  def testArgumentDupeCreatesNonFailingImportError(self):
    events = [
      {'name': 'a', 'args': {'x': 1}, 'pid': 1, 'ts': 520, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {'x': 2}, 'pid': 1, 'ts': 560, 'cat': 'foo',
       'tid': 1, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    t = processes[0].threads[1]
    slice_a = FindEventNamed(t.all_slices, 'a')

    self.assertEqual(2, slice_a.args['x'])
    self.assertEqual(1, len(m.import_errors))

  def testCategoryBeginEndMismatchPreferslice_begin(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 520, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 560, 'cat': 'bar',
       'tid': 53, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]
    self.assertEqual(52, p.pid)

    self.assertEqual(1, len(p.threads))
    t = p.threads[53]
    self.assertEqual(1, len(t.all_slices))
    self.assertEqual(53, t.tid)
    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)

  def testNestedParsing(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'tts': 2, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 3, 'tts': 3, 'cat': 'bar',
       'tid': 1, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 5, 'tts': 4, 'cat': 'bar',
       'tid': 1, 'ph': 'E'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 7, 'tts': 5, 'cat': 'foo',
       'tid': 1, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    t = m.GetAllProcesses()[0].threads[1]

    slice_a = FindEventNamed(t.all_slices, 'a')
    slice_b = FindEventNamed(t.all_slices, 'b')

    self.assertEqual('a', slice_a.name)
    self.assertEqual('foo', slice_a.category)
    self.assertAlmostEqual(0.001, slice_a.start)
    self.assertAlmostEqual(0.006, slice_a.duration)
    self.assertAlmostEqual(0.002, slice_a.thread_start)
    self.assertAlmostEqual(0.003, slice_a.thread_duration)

    self.assertEqual('b', slice_b.name)
    self.assertEqual('bar', slice_b.category)
    self.assertAlmostEqual(0.003, slice_b.start)
    self.assertAlmostEqual(0.002, slice_b.duration)
    self.assertAlmostEqual(0.003, slice_b.thread_start)
    self.assertAlmostEqual(0.001, slice_b.thread_duration)

  def testAutoclosing(self):
    events = [
      # Slices that don't finish.
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 2, 'cat': 'foo',
       'tid': 2, 'ph': 'B'},

      # Slices on thread 1 and 2 that do finish to give an 'end time' to make
      # autoclosing work.
      {'name': 'c', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 1.5, 'cat': 'bar',
       'tid': 1, 'ph': 'B'},
      {'name': 'c', 'args': {}, 'pid': 1, 'ts': 4, 'tts': 3, 'cat': 'bar',
       'tid': 1, 'ph': 'E'},
      {'name': 'd', 'args': {}, 'pid': 1, 'ts': 3, 'tts': 2.5, 'cat': 'bar',
       'tid': 2, 'ph': 'B'},
      {'name': 'd', 'args': {}, 'pid': 1, 'ts': 7, 'tts': 5, 'cat': 'bar',
       'tid': 2, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t1 = p.threads[1]
    slice_event = FindEventNamed(t1.all_slices, 'a')
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertTrue(slice_event.did_not_finish)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual((7 - 1) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(1 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((3 - 1) / 1000.0, slice_event.thread_duration)

    t2 = p.threads[2]
    slice_event = FindEventNamed(t2.all_slices, 'b')
    self.assertEqual('b', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertTrue(slice_event.did_not_finish)
    self.assertAlmostEqual((2 - 1) / 1000.0, slice_event.start)
    self.assertAlmostEqual((7 - 2) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(2 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((5 - 2) / 1000.0, slice_event.thread_duration)

  def testAutoclosingLoneBegin(self):
    events = [
      # Slice that doesn't finish.
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[1]
    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertTrue(slice_event.did_not_finish)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual(0, slice_event.duration)
    self.assertAlmostEqual(1 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual(0, slice_event.thread_duration)

  def testAutoclosingWithSubTasks(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'b1', 'args': {}, 'pid': 1, 'ts': 2, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'b1', 'args': {}, 'pid': 1, 'ts': 3, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'b2', 'args': {}, 'pid': 1, 'ts': 3, 'cat': 'foo',
       'tid': 1, 'ph': 'B'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    t = m.GetAllProcesses()[0].threads[1]

    slice_a = FindEventNamed(t.all_slices, 'a')
    slice_b1 = FindEventNamed(t.all_slices, 'b1')
    slice_b2 = FindEventNamed(t.all_slices, 'b2')

    self.assertAlmostEqual(0.003, slice_a.end)
    self.assertAlmostEqual(0.003, slice_b1.end)
    self.assertAlmostEqual(0.003, slice_b2.end)

  def testAutoclosingWithEventsOutsideBounds(self):
    events = [
      # Slice that begins before min and ends after max of the other threads.
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 0, 'tts': 0, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 6, 'tts': 3, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},

      # Slice that does finish to give an 'end time' to establish a basis
      {'name': 'c', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 1, 'cat': 'bar',
       'tid': 2, 'ph': 'B'},
      {'name': 'c', 'args': {}, 'pid': 1, 'ts': 4, 'tts': 2, 'cat': 'bar',
       'tid': 2, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    p = m.GetAllProcesses()[0]
    t1 = p.threads[1]
    t1_thread_time_bounds = (
        m._thread_time_bounds[t1]) # pylint: disable=protected-access
    self.assertAlmostEqual(0.000, t1_thread_time_bounds.min)
    self.assertAlmostEqual(0.003, t1_thread_time_bounds.max)
    self.assertEqual(2, len(t1.all_slices))

    slice_event = FindEventNamed(t1.all_slices, 'a')
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual(0.006, slice_event.duration)
    self.assertAlmostEqual(0, slice_event.thread_start)
    self.assertAlmostEqual(0.003, slice_event.thread_duration)

    t2 = p.threads[2]
    t2_thread_time_bounds = (
        m._thread_time_bounds[t2]) # pylint: disable=protected-access
    self.assertAlmostEqual(0.001, t2_thread_time_bounds.min)
    self.assertAlmostEqual(0.002, t2_thread_time_bounds.max)
    slice2 = FindEventNamed(t2.all_slices, 'c')
    self.assertEqual('c', slice2.name)
    self.assertEqual('bar', slice2.category)
    self.assertAlmostEqual(0.002, slice2.start)
    self.assertAlmostEqual(0.002, slice2.duration)
    self.assertAlmostEqual(0.001, slice2.thread_start)
    self.assertAlmostEqual(0.001, slice2.thread_duration)

    self.assertAlmostEqual(0.000, m.bounds.min)
    self.assertAlmostEqual(0.006, m.bounds.max)

  def testNestedAutoclosing(self):
    events = [
      # Tasks that don't finish.
      {'name': 'a1', 'args': {}, 'pid': 1, 'ts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a2', 'args': {}, 'pid': 1, 'ts': 1.5, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},

      # Slice that does finish to give an 'end time' to make autoclosing work.
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 1, 'cat': 'foo',
       'tid': 2, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 2, 'cat': 'foo',
       'tid': 2, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    t1 = m.GetAllProcesses()[0].threads[1]
    t2 = m.GetAllProcesses()[0].threads[2]

    slice_a1 = FindEventNamed(t1.all_slices, 'a1')
    slice_a2 = FindEventNamed(t1.all_slices, 'a2')
    FindEventNamed(t2.all_slices, 'b')

    self.assertAlmostEqual(0.002, slice_a1.end)
    self.assertAlmostEqual(0.002, slice_a2.end)

  def testMultipleThreadParsing(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 4, 'tts': 2, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 6, 'tts': 3, 'cat': 'bar',
       'tid': 2, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 1, 'ts': 8, 'tts': 4, 'cat': 'bar',
       'tid': 2, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]

    self.assertEqual(2, len(p.threads))

    # Check thread 1.
    t = p.threads[1]
    self.assertAlmostEqual(1, len(t.all_slices))
    self.assertAlmostEqual(1, t.tid)

    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual((4 - 2) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(1 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((2 - 1) / 1000.0, slice_event.thread_duration)

    # Check thread 2.
    t = p.threads[2]
    self.assertAlmostEqual(1, len(t.all_slices))
    self.assertAlmostEqual(2, t.tid)

    slice_event = t.all_slices[0]
    self.assertEqual('b', slice_event.name)
    self.assertEqual('bar', slice_event.category)
    self.assertAlmostEqual((6 - 2) / 1000.0, slice_event.start)
    self.assertAlmostEqual((8 - 6) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(3 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((4 - 3) / 1000.0, slice_event.thread_duration)

  def testMultiplePidParsing(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 4, 'tts': 2, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 6, 'tts': 3, 'cat': 'bar',
       'tid': 2, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 8, 'tts': 4, 'cat': 'bar',
       'tid': 2, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(2, len(processes))

    p = processes[0]
    self.assertEqual(1, p.pid)
    self.assertEqual(1, len(p.threads))

    # Check process 1 thread 1.
    t = p.threads[1]
    self.assertEqual(1, len(t.all_slices))
    self.assertEqual(1, t.tid)

    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertAlmostEqual(0, slice_event.start)
    self.assertAlmostEqual((4 - 2) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(1 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((2 - 1) / 1000.0, slice_event.thread_duration)

    # Check process 2 thread 2.
    # TODO: will this be in deterministic order?
    p = processes[1]
    self.assertEqual(2, p.pid)
    self.assertEqual(1, len(p.threads))
    t = p.threads[2]
    self.assertEqual(1, len(t.all_slices))
    self.assertEqual(2, t.tid)

    slice_event = t.all_slices[0]
    self.assertEqual('b', slice_event.name)
    self.assertEqual('bar', slice_event.category)
    self.assertAlmostEqual((6 - 2) / 1000.0, slice_event.start)
    self.assertAlmostEqual((8 - 6) / 1000.0, slice_event.duration)
    self.assertAlmostEqual(3 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual((4 - 3) / 1000.0, slice_event.thread_duration)

    # Check getAllThreads.
    self.assertEqual([processes[0].threads[1],
                      processes[1].threads[2]],
                      m.GetAllThreads())

  def testThreadNames(self):
    events = [
      {'name': 'thread_name', 'args': {'name': 'Thread 1'},
        'pid': 1, 'ts': 0, 'tid': 1, 'ph': 'M'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 2, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 3, 'cat': 'foo',
       'tid': 2, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 4, 'cat': 'foo',
       'tid': 2, 'ph': 'E'},
      {'name': 'thread_name', 'args': {'name': 'Thread 2'},
        'pid': 2, 'ts': 0, 'tid': 2, 'ph': 'M'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual('Thread 1', processes[0].threads[1].name)
    self.assertEqual('Thread 2', processes[1].threads[2].name)

  def testParsingWhenEndComesFirst(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 1, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 4, 'tts': 4, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 5, 'tts': 5, 'cat': 'foo',
       'tid': 1, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    p = m.GetAllProcesses()[0]
    t = p.threads[1]
    self.assertEqual(1, len(t.all_slices))
    self.assertEqual('a', t.all_slices[0].name)
    self.assertEqual('foo', t.all_slices[0].category)
    self.assertEqual(0.004, t.all_slices[0].start)
    self.assertEqual(0.001, t.all_slices[0].duration)
    self.assertEqual(0.004, t.all_slices[0].thread_start)
    self.assertEqual(0.001, t.all_slices[0].thread_duration)
    self.assertEqual(1, len(m.import_errors))

  def testImmediateParsing(self):
    events = [
      # Need to include immediates inside a task so the timeline
      # recentering/zeroing doesn't clobber their timestamp.
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 2, 'tts': 1, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'immediate', 'args': {}, 'pid': 1, 'ts': 4, 'cat': 'bar',
       'tid': 1, 'ph': 'I'},
      {'name': 'slower', 'args': {}, 'pid': 1, 'ts': 8, 'cat': 'baz',
       'tid': 1, 'ph': 'i'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 8, 'tts': 4, 'cat': 'foo',
       'tid': 1, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    p = m.GetAllProcesses()[0]
    t = p.threads[1]
    self.assertEqual(3, len(t.all_slices))

    i = m.GetAllEventsOfName('immediate')[0]
    self.assertEqual('immediate', i.name)
    self.assertEqual('bar', i.category)
    self.assertAlmostEqual(0.004, i.start)
    self.assertAlmostEqual(0, i.duration)

    slower = m.GetAllEventsOfName('slower')[0]
    self.assertEqual('slower', slower.name)
    self.assertEqual('baz', slower.category)
    self.assertAlmostEqual(0.008, slower.start)
    self.assertAlmostEqual(0, slower.duration)

    a = m.GetAllEventsOfName('a')[0]
    self.assertEqual('a', a.name)
    self.assertEqual('foo', a.category)
    self.assertAlmostEqual(0.002, a.start)
    self.assertAlmostEqual(0.006, a.duration)
    self.assertAlmostEqual(0.001, a.thread_start)
    self.assertAlmostEqual(0.003, a.thread_duration)


  def testSimpleCounter(self):
    events = [
      {'name': 'ctr', 'args': {'value': 0}, 'pid': 1, 'ts': 0, 'cat': 'foo',
       'tid': 1, 'ph': 'C'},
      {'name': 'ctr', 'args': {'value': 10}, 'pid': 1, 'ts': 10, 'cat': 'foo',
       'tid': 1, 'ph': 'C'},
      {'name': 'ctr', 'args': {'value': 0}, 'pid': 1, 'ts': 20, 'cat': 'foo',
       'tid': 1, 'ph': 'C'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    ctr = p.counters['foo.ctr']

    self.assertEqual('ctr', ctr.name)
    self.assertEqual('foo', ctr.category)
    self.assertEqual(3, ctr.num_samples)
    self.assertEqual(1, ctr.num_series)

    self.assertEqual(['value'], ctr.series_names)
    self.assertEqual([0, 0.01, 0.02], ctr.timestamps)
    self.assertEqual([0, 10, 0], ctr.samples)
    self.assertEqual([0, 10, 0], ctr.totals)
    self.assertEqual(10, ctr.max_total)

  def testInstanceCounter(self):
    events = [
      {'name': 'ctr', 'args': {'value': 0}, 'pid': 1, 'ts': 0, 'cat': 'foo',
       'tid': 1,
       'ph': 'C', 'id': 0},
      {'name': 'ctr', 'args': {'value': 10}, 'pid': 1, 'ts': 10, 'cat': 'foo',
       'tid': 1,
       'ph': 'C', 'id': 0},
      {'name': 'ctr', 'args': {'value': 10}, 'pid': 1, 'ts': 10, 'cat': 'foo',
       'tid': 1,
       'ph': 'C', 'id': 1},
      {'name': 'ctr', 'args': {'value': 20}, 'pid': 1, 'ts': 15, 'cat': 'foo',
       'tid': 1,
       'ph': 'C', 'id': 1},
      {'name': 'ctr', 'args': {'value': 30}, 'pid': 1, 'ts': 18, 'cat': 'foo',
       'tid': 1,
       'ph': 'C', 'id': 1},
      {'name': 'ctr', 'args': {'value': 40}, 'pid': 1, 'ts': 20, 'cat': 'bar',
       'tid': 1,
       'ph': 'C', 'id': 2}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    ctr = p.counters['foo.ctr[0]']
    self.assertEqual('ctr[0]', ctr.name)
    self.assertEqual('foo', ctr.category)
    self.assertEqual(2, ctr.num_samples)
    self.assertEqual(1, ctr.num_series)
    self.assertEqual([0, 0.01], ctr.timestamps)
    self.assertEqual([0, 10], ctr.samples)

    ctr = m.GetAllProcesses()[0].counters['foo.ctr[1]']
    self.assertEqual('ctr[1]', ctr.name)
    self.assertEqual('foo', ctr.category)
    self.assertEqual(3, ctr.num_samples)
    self.assertEqual(1, ctr.num_series)
    self.assertEqual([0.01, 0.015, 0.018], ctr.timestamps)
    self.assertEqual([10, 20, 30], ctr.samples)

    ctr = m.GetAllProcesses()[0].counters['bar.ctr[2]']
    self.assertEqual('ctr[2]', ctr.name)
    self.assertEqual('bar', ctr.category)
    self.assertEqual(1, ctr.num_samples)
    self.assertEqual(1, ctr.num_series)
    self.assertEqual([0.02], ctr.timestamps)
    self.assertEqual([40], ctr.samples)

  def testMultiCounterUpdateBounds(self):
    ctr = tracing_counter.Counter(None, 'testBasicCounter',
        'testBasicCounter')
    ctr.series_names = ['value1', 'value2']
    ctr.timestamps = [0, 1, 2, 3, 4, 5, 6, 7]
    ctr.samples = [0, 0,
                   1, 0,
                   1, 1,
                   2, 1.1,
                   3, 0,
                   1, 7,
                   3, 0,
                   3.1, 0.5]
    ctr.FinalizeImport()
    self.assertEqual(8, ctr.max_total)
    self.assertEqual([0, 0,
                       1, 1,
                       1, 2,
                       2, 3.1,
                       3, 3,
                       1, 8,
                       3, 3,
                       3.1, 3.6], ctr.totals)

  def testMultiCounter(self):
    events = [
      {'name': 'ctr', 'args': {'value1': 0, 'value2': 7}, 'pid': 1, 'ts': 0,
       'cat': 'foo', 'tid': 1, 'ph': 'C'},
      {'name': 'ctr', 'args': {'value1': 10, 'value2': 4}, 'pid': 1, 'ts': 10,
       'cat': 'foo', 'tid': 1, 'ph': 'C'},
      {'name': 'ctr', 'args': {'value1': 0, 'value2': 1}, 'pid': 1, 'ts': 20,
       'cat': 'foo', 'tid': 1, 'ph': 'C'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    ctr = p.counters['foo.ctr']
    self.assertEqual('ctr', ctr.name)

    self.assertEqual('ctr', ctr.name)
    self.assertEqual('foo', ctr.category)
    self.assertEqual(3, ctr.num_samples)
    self.assertEqual(2, ctr.num_series)

    self.assertEqual(sorted(['value1', 'value2']), sorted(ctr.series_names))
    self.assertEqual(sorted([0, 0.01, 0.02]), sorted(ctr.timestamps))
    self.assertEqual(sorted([0, 7, 10, 4, 0, 1]), sorted(ctr.samples))
    # We can't check ctr.totals here because it can change depending on
    # the order in which the series names are added.
    self.assertEqual(14, ctr.max_total)

  def testStartFinishOneSliceOneThread(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 560, 'cat': 'cat',
       'tid': 53,
         'ph': 'F', 'id': 72},
      {'name': 'a', 'pid': 52, 'ts': 524, 'cat': 'cat',
       'tid': 53,
         'ph': 'S', 'id': 72, 'args': {'foo': 'bar'}}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)

    events = list(m.IterAllEvents())
    self.assertEqual(2, len(events))

    processes = m.GetAllProcesses()
    t = processes[0].threads[53]
    slices = t.async_slices
    self.assertEqual(1, len(slices))
    self.assertEqual('a', slices[0].name)
    self.assertEqual('cat', slices[0].category)
    self.assertEqual(72, slices[0].id)
    self.assertEqual('bar', slices[0].args['foo'])
    self.assertEqual(0, slices[0].start)
    self.assertAlmostEqual((60 - 24) / 1000.0, slices[0].duration)
    self.assertEqual(t, slices[0].start_thread)
    self.assertEqual(t, slices[0].end_thread)

  def testEndArgsAddedToSlice(self):
    events = [
      {'name': 'a', 'args': {'x': 1}, 'pid': 52, 'ts': 520, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'a', 'args': {'y': 2}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]

    self.assertEqual(1, len(p.threads))
    t = p.threads[53]
    self.assertEqual(1, len(t.all_slices))
    self.assertEqual(53, t.tid)
    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertEqual(0, slice_event.start)
    self.assertEqual(1, slice_event.args['x'])
    self.assertEqual(2, slice_event.args['y'])

  def testEndArgOverrwritesOriginalArgValueIfDuplicated(self):
    events = [
      {'name': 'b', 'args': {'z': 3}, 'pid': 52, 'ts': 629, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'b', 'args': {'z': 4}, 'pid': 52, 'ts': 631, 'cat': 'foo',
       'tid': 53, 'ph': 'E'}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]

    self.assertEqual(1, len(p.threads))
    t = p.threads[53]
    slice_event = t.all_slices[0]
    self.assertEqual('b', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertEqual(0, slice_event.start)
    self.assertEqual(4, slice_event.args['z'])

  def testSliceHierarchy(self):
    """The slice hierarchy should look something like this:
           [            a            ]
              [      b      ]  [ d ]
              [ c ]     [ e ]
    """
    events = [
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 100, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 200, 'cat': 'foo',
       'tid': 53, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 125, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 165, 'cat': 'foo',
       'tid': 53, 'ph': 'E'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 125, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 135, 'cat': 'foo',
       'tid': 53, 'ph': 'E'},
      {'name': 'd', 'args': {}, 'pid': 52, 'ts': 175, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'd', 'args': {}, 'pid': 52, 'ts': 190, 'cat': 'foo',
       'tid': 53, 'ph': 'E'},
      {'name': 'e', 'args': {}, 'pid': 52, 'ts': 155, 'cat': 'foo',
       'tid': 53, 'ph': 'B'},
      {'name': 'e', 'args': {}, 'pid': 52, 'ts': 165, 'cat': 'foo',
       'tid': 53, 'ph': 'E'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data, shift_world_to_zero=False)
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    p = processes[0]

    self.assertEqual(1, len(p.threads))
    t = p.threads[53]

    slice_a = t.all_slices[0]
    self.assertEqual(4, len(slice_a.GetAllSubSlices()))
    self.assertEqual('a', slice_a.name)
    self.assertEqual(100 / 1000.0, slice_a.start)
    self.assertEqual(200 / 1000.0, slice_a.end)
    self.assertEqual(2, len(slice_a.sub_slices))

    slice_b = slice_a.sub_slices[0]
    self.assertEqual('b', slice_b.name)
    self.assertEqual(2, len(slice_b.sub_slices))
    self.assertEqual('c', slice_b.sub_slices[0].name)
    self.assertEqual('e', slice_b.sub_slices[1].name)

    slice_d = slice_a.sub_slices[1]
    self.assertEqual('d', slice_d.name)
    self.assertEqual(0, len(slice_d.sub_slices))

  def testAsyncEndArgAddedToSlice(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'c', 'args': {'y': 2}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53,
         'ph': 'F', 'id': 72},
      {'name': 'c', 'args': {'x': 1}, 'pid': 52, 'ts': 524, 'cat': 'foo',
       'tid': 53,
         'ph': 'S', 'id': 72}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    t = m.GetAllProcesses()[0].threads[53]
    self.assertEqual(1, len(t.async_slices))
    parent_slice = t.async_slices[0]
    self.assertEqual('c', parent_slice.name)
    self.assertEqual('foo', parent_slice.category)

    self.assertEqual(1, len(parent_slice.sub_slices))
    sub_slice = parent_slice.sub_slices[0]
    self.assertEqual(1, sub_slice.args['x'])
    self.assertEqual(2, sub_slice.args['y'])

  def testAsyncEndArgOverrwritesOriginalArgValueIfDuplicated(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'd', 'args': {'z': 4}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53,
         'ph': 'F', 'id': 72},
      {'name': 'd', 'args': {'z': 3}, 'pid': 52, 'ts': 524, 'cat': 'foo',
       'tid': 53,
         'ph': 'S', 'id': 72}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    t = m.GetAllProcesses()[0].threads[53]
    self.assertEqual(1, len(t.async_slices))
    parent_slice = t.async_slices[0]
    self.assertEqual('d', parent_slice.name)
    self.assertEqual('foo', parent_slice.category)

    self.assertEqual(1, len(parent_slice.sub_slices))
    sub_slice = parent_slice.sub_slices[0]
    self.assertEqual(4, sub_slice.args['z'])

  def testAsyncStepsInOneThread(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'a', 'args': {'z': 3}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53, 'ph': 'F', 'id': 72, 'tts': 25},
      {'name': 'a', 'args': {'step': 's1', 'y': 2}, 'pid': 52, 'ts': 548,
       'cat': 'foo', 'tid': 53, 'ph': 'T', 'id': 72, 'tts': 20},
      {'name': 'a', 'args': {'x': 1}, 'pid': 52, 'ts': 524, 'cat': 'foo',
       'tid': 53, 'ph': 'S', 'id': 72, 'tts': 17}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    t = m.GetAllProcesses()[0].threads[53]
    self.assertEqual(1, len(t.async_slices))
    parent_slice = t.async_slices[0]
    self.assertEqual('a', parent_slice.name)
    self.assertEqual('foo', parent_slice.category)
    self.assertEqual(0, parent_slice.start)
    self.assertAlmostEqual(17/1000.0, parent_slice.thread_start)
    self.assertAlmostEqual(25/1000.0, parent_slice.thread_end)

    self.assertEqual(2, len(parent_slice.sub_slices))
    sub_slice = parent_slice.sub_slices[0]
    self.assertEqual('a', sub_slice.name)
    self.assertEqual('foo', sub_slice.category)
    self.assertAlmostEqual(0, sub_slice.start)
    self.assertAlmostEqual((548 - 524) / 1000.0, sub_slice.duration)
    self.assertAlmostEqual((20 - 17) / 1000.0, sub_slice.thread_duration)
    self.assertEqual(1, sub_slice.args['x'])

    sub_slice = parent_slice.sub_slices[1]
    self.assertEqual('a:s1', sub_slice.name)
    self.assertEqual('foo', sub_slice.category)
    self.assertAlmostEqual((548 - 524) / 1000.0, sub_slice.start)
    self.assertAlmostEqual((560 - 548) / 1000.0, sub_slice.duration)
    self.assertAlmostEqual((25 - 20) / 1000.0, sub_slice.thread_duration)
    self.assertEqual(2, sub_slice.args['y'])
    self.assertEqual(3, sub_slice.args['z'])

  def testAsyncStepsMissingStart(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'a', 'args': {'z': 3}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53, 'ph': 'F', 'id': 72},
      {'name': 'a', 'args': {'step': 's1', 'y': 2}, 'pid': 52, 'ts': 548,
       'cat': 'foo', 'tid': 53, 'ph': 'T', 'id': 72}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    t = m.GetAllProcesses()[0].threads[53]
    self.assertTrue(t is not None)

  def testAsyncStepsMissingFinish(self):
    events = [
      # Time is intentionally out of order.
      {'name': 'a', 'args': {'step': 's1', 'y': 2}, 'pid': 52, 'ts': 548,
       'cat': 'foo', 'tid': 53, 'ph': 'T', 'id': 72},
      {'name': 'a', 'args': {'z': 3}, 'pid': 52, 'ts': 560, 'cat': 'foo',
       'tid': 53, 'ph': 'S', 'id': 72}
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    t = m.GetAllProcesses()[0].threads[53]
    self.assertTrue(t is not None)

  def testImportSamples(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 548, 'cat': 'test',
       'tid': 53, 'ph': 'P'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 548, 'cat': 'test',
       'tid': 53, 'ph': 'P'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 558, 'cat': 'test',
       'tid': 53, 'ph': 'P'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[53]
    self.assertEqual(3, len(t.samples))
    self.assertEqual(0.0, t.samples[0].start)
    self.assertEqual(0.0, t.samples[1].start)
    self.assertAlmostEqual(0.01, t.samples[2].start)
    self.assertEqual('a', t.samples[0].name)
    self.assertEqual('b', t.samples[1].name)
    self.assertEqual('c', t.samples[2].name)
    self.assertEqual(0, len(m.import_errors))

  def testImportSamplesMissingArgs(self):
    events = [
      {'name': 'a', 'pid': 52, 'ts': 548, 'cat': 'test',
       'tid': 53, 'ph': 'P'},
      {'name': 'b', 'pid': 52, 'ts': 548, 'cat': 'test',
       'tid': 53, 'ph': 'P'},
      {'name': 'c', 'pid': 52, 'ts': 549, 'cat': 'test',
       'tid': 53, 'ph': 'P'}
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[53]
    self.assertEqual(3, len(t.samples))
    self.assertEqual(0, len(m.import_errors))

  def testImportCompleteEvent(self):
    events = [
      {'name': 'a', 'args': {}, 'pid': 52, 'ts': 629, 'tts': 538, 'dur': 1,
       'tdur': 1, 'cat': 'baz', 'tid': 53, 'ph': 'X'},
      {'name': 'b', 'args': {}, 'pid': 52, 'ts': 730, 'tts': 620, 'dur': 20,
       'tdur': 14, 'cat': 'foo', 'tid': 53, 'ph': 'X'},
      {'name': 'c', 'args': {}, 'pid': 52, 'ts': 740, 'tts': 625, 'cat': 'baz',
       'tid': 53, 'ph': 'X'},
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[53]
    self.assertEqual(3, len(t.all_slices))

    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertAlmostEqual(0.0, slice_event.start)
    self.assertAlmostEqual(1 / 1000.0, slice_event.duration)
    self.assertAlmostEqual(538 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual(1 / 1000.0, slice_event.thread_duration)
    self.assertFalse(slice_event.did_not_finish)
    self.assertEqual(0, len(slice_event.sub_slices))

    slice_event = t.all_slices[1]
    self.assertEqual('b', slice_event.name)
    self.assertAlmostEqual((730 - 629) / 1000.0, slice_event.start)
    self.assertAlmostEqual(20 / 1000.0, slice_event.duration)
    self.assertAlmostEqual(620 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual(14 / 1000.0, slice_event.thread_duration)
    self.assertFalse(slice_event.did_not_finish)
    self.assertEqual(1, len(slice_event.sub_slices))
    self.assertEqual(t.all_slices[2], slice_event.sub_slices[0])

    slice_event = t.all_slices[2]
    self.assertEqual('c', slice_event.name)
    self.assertAlmostEqual((740 - 629) / 1000.0, slice_event.start)
    self.assertAlmostEqual(10 / 1000.0, slice_event.duration)
    self.assertAlmostEqual(625 / 1000.0, slice_event.thread_start)
    self.assertAlmostEqual(9 / 1000.0, slice_event.thread_duration)
    self.assertTrue(slice_event.did_not_finish)
    self.assertEqual(0, len(slice_event.sub_slices))

  def testImportMarkEvent(self):
    events = [
      {'name': 'a', 'pid': 52, 'ts': 629, 'cat': 'baz', 'tid': 53, 'ph': 'R'},
      {'name': 'b', 'pid': 52, 'ts': 730, 'cat': 'foo', 'tid': 53, 'ph': 'R'},
      {'name': 'c', 'pid': 52, 'ts': 740, 'cat': 'baz', 'tid': 53, 'ph': 'R'},
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[53]
    self.assertEqual(3, len(t.all_slices))

    slice_event = t.all_slices[0]
    self.assertEqual('a', slice_event.name)
    self.assertEqual('baz', slice_event.category)
    self.assertAlmostEqual(0.0, slice_event.start)
    self.assertFalse(slice_event.did_not_finish)
    self.assertEqual(0, len(slice_event.sub_slices))

    slice_event = t.all_slices[1]
    self.assertEqual('b', slice_event.name)
    self.assertEqual('foo', slice_event.category)
    self.assertAlmostEqual((730 - 629) / 1000.0, slice_event.start)
    self.assertFalse(slice_event.did_not_finish)
    self.assertEqual(0, len(slice_event.sub_slices))

    slice_event = t.all_slices[2]
    self.assertEqual('c', slice_event.name)
    self.assertEqual('baz', slice_event.category)
    self.assertAlmostEqual((740 - 629) / 1000.0, slice_event.start)
    self.assertFalse(slice_event.did_not_finish)
    self.assertEqual(0, len(slice_event.sub_slices))

  def testImportFlowEvent(self):
    events = [
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 548,
       'ph': 's', 'args': {}},
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 560,
       'ph': 't', 'args': {}},
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 580,
       'ph': 'f', 'args': {}},
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    p = m.GetAllProcesses()[0]
    t = p.threads[53]
    self.assertTrue(t is not None)
    self.assertEqual(2, len(m.flow_events))

    start = m.flow_events[0][0]
    step = m.flow_events[0][1]
    finish = m.flow_events[1][1]

    self.assertEqual('a', start.name)
    self.assertEqual('foo', start.category)
    self.assertEqual(72, start.event_id)
    self.assertEqual(0, start.start)
    self.assertEqual(0, start.duration)

    self.assertEqual(start.name, step.name)
    self.assertEqual(start.category, step.category)
    self.assertEqual(start.event_id, step.event_id)
    self.assertAlmostEqual(12 / 1000.0, step.start)
    self.assertEquals(0, step.duration)

    self.assertEqual(start.name, finish.name)
    self.assertEqual(start.category, finish.category)
    self.assertEqual(start.event_id, finish.event_id)
    self.assertAlmostEqual((20 + 12) / 1000.0, finish.start)
    self.assertEqual(0, finish.duration)

  def testImportOutOfOrderFlowEvent(self):
    events = [
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 548,
       'ph': 's', 'args': {}},
      {'name': 'b', 'cat': 'foo', 'id': 73, 'pid': 52, 'tid': 53, 'ts': 148,
       'ph': 's', 'args': {}},
      {'name': 'b', 'cat': 'foo', 'id': 73, 'pid': 52, 'tid': 53, 'ts': 570,
       'ph': 'f', 'args': {}},
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 560,
       'ph': 't', 'args': {}},
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 580,
       'ph': 'f', 'args': {}},
    ]

    expected = [[0.4, 0.412], [0.0, 0.422], [0.412, 0.432]]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    self.assertEqual(3, len(m.flow_events))

    for i in range(len(expected)):
      self.assertAlmostEqual(expected[i][0], m.flow_events[i][0].start)
      self.assertAlmostEqual(expected[i][1], m.flow_events[i][1].start)

  def testImportErrornousFlowEvent(self):
    events = [
      {'name': 'a', 'cat': 'foo', 'id': 70, 'pid': 52, 'tid': 53, 'ts': 548,
       'ph': 's', 'args': {}},
      {'name': 'a2', 'cat': 'foo', 'id': 70, 'pid': 52, 'tid': 53, 'ts': 550,
       'ph': 's', 'args': {}},
      {'name': 'b', 'cat': 'foo', 'id': 73, 'pid': 52, 'tid': 53, 'ts': 570,
       'ph': 'f', 'args': {}},
      {'name': 'a', 'cat': 'foo', 'id': 72, 'pid': 52, 'tid': 53, 'ts': 560,
       'ph': 't', 'args': {}},
    ]

    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    self.assertEqual(0, len(m.flow_events))

  def testImportMemoryDumpEvents(self):
    events = [
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 123,
       'id': '1234ABCD'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 54, 'ts': 134,
       'id': '1234ABCD'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 144,
       'id': '1234ABCD'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 245,
       'id': '1234ABDF'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 54, 'ts': 256,
       'id': '1234ABDF'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 233,
       'id': '1234ABDF'},
    ]

    expected_processes = set([52, 54])
    expected_results = [['1234ABCD', 0, 21], ['1234ABDF', 110, 23]]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    assert set(p.pid for p in m.GetAllProcesses()) == expected_processes

    memory_dumps = list(m.IterGlobalMemoryDumps())
    self.assertEqual(len(expected_results), len(memory_dumps))
    for memory_dump, test_values in zip(memory_dumps, expected_results):
      assert len(list(memory_dump.IterProcessMemoryDumps())) == len(
          expected_processes)
      dump_id, start, duration = test_values
      self.assertEquals(dump_id, memory_dump.dump_id)
      self.assertAlmostEqual(start / 1000.0, memory_dump.start)
      self.assertAlmostEqual(duration / 1000.0, memory_dump.duration)

  def testImportOutOfOrderMemoryDumpEvents(self):
    events = [
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 245,
       'id': '1234ABDF'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 54, 'ts': 134,
       'id': '1234ABCD'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 54, 'ts': 256,
       'id': '1234ABDF'},
      {'name': 'a', 'cat': 'b', 'ph': 'v', 'pid': 52, 'ts': 123,
       'id': '1234ABCD'},
    ]

    expected = [['1234ABCD', 0, 11], ['1234ABDF', 122, 11]]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    memory_dumps = list(m.IterGlobalMemoryDumps())
    self.assertEqual(len(expected), len(memory_dumps))
    for memory_dump, test_values in zip(memory_dumps, expected):
      dump_id, start, duration = test_values
      self.assertEquals(dump_id, memory_dump.dump_id)
      self.assertAlmostEqual(start / 1000.0, memory_dump.start)
      self.assertAlmostEqual(duration / 1000.0, memory_dump.duration)

  def testMetadataImport(self):
    events = [
      {'cat': '__metadata', 'pid': 14689, 'tid': 14740, 'ts': 245,
       'ph': 'M', 'name': 'process_name', 'args': {'name': 'Browser'}},
      {'cat': '__metadata', 'pid': 23828, 'tid': 23828, 'ts': 0,
       'ph': 'M', 'name': 'process_labels',
       'args': {'labels': 'huge image - Google Search'}}
    ]

    expected = [
      [None, 'Browser'],
      ['huge image - Google Search', 'process 23828']
    ]
    trace_data = trace_data_module.CreateTraceDataFromRawData(events)
    m = timeline_model.TimelineModel(trace_data)
    processes = m.GetAllProcesses()

    self.assertEqual(len(processes), len(expected))
    for process, test_values in zip(processes, expected):
      process_labels, process_name = test_values
      self.assertEquals(process_labels, process.labels)
      self.assertEquals(process_name, process.name)
