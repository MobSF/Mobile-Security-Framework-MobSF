# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import model as timeline_model
from telemetry.timeline import tab_id_importer
from tracing.trace_data import trace_data as trace_data_module


class TabIdImporterUnitTest(unittest.TestCase):
  def testImportOverflowedTrace(self):
    builder = trace_data_module.TraceDataBuilder()
    builder.AddTraceFor(trace_data_module.CHROME_TRACE_PART, {'traceEvents': [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 7, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 8, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 9, 'cat': 'foo',
       'tid': 2, 'ph': 'B'},
      {'name': 'b', 'args': {}, 'pid': 2, 'ts': 10, 'cat': 'foo',
       'tid': 2, 'ph': 'E'},
      {'name': 'trace_buffer_overflowed',
       'args': {'overflowed_at_ts': 12},
        'pid': 2, 'ts': 0, 'tid': 2, 'ph': 'M'}
    ]})
    builder.AddTraceFor(
        trace_data_module.TAB_ID_PART, ['tab-id-1', 'tab-id-2'])

    with self.assertRaises(tab_id_importer.TraceBufferOverflowException) \
        as context:
      timeline_model.TimelineModel(builder.AsData())
    self.assertTrue(
        'Trace buffer of process with pid=2 overflowed at timestamp 12' in
        context.exception.message)

  def testTraceEventsWithTabIdsMarkers(self):
    builder = trace_data_module.TraceDataBuilder()
    builder.AddTraceFor(trace_data_module.CHROME_TRACE_PART, {'traceEvents': [
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 20, 'tts': 10, 'cat': 'foo',
       'tid': 1, 'ph': 'B'},
      # tab-id-1
      {'name': 'tab-id-1', 'args': {}, 'pid': 1, 'ts': 25, 'cat': 'foo',
       'tid': 1,
         'ph': 'S', 'id': 72},
      {'name': 'a', 'args': {}, 'pid': 1, 'ts': 30, 'tts': 20, 'cat': 'foo',
       'tid': 1, 'ph': 'E'},
      {'name': 'tab-id-1', 'args': {}, 'pid': 1, 'ts': 35, 'cat': 'foo',
       'tid': 1,
         'ph': 'F', 'id': 72},
      # tab-id-2
      {'name': 'tab-id-2', 'args': {}, 'pid': 1, 'ts': 25, 'cat': 'foo',
       'tid': 2,
         'ph': 'S', 'id': 72},
      {'name': 'tab-id-2', 'args': {}, 'pid': 1, 'ts': 26, 'cat': 'foo',
       'tid': 2,
         'ph': 'F', 'id': 72},
     ]})
    builder.AddTraceFor(
        trace_data_module.TAB_ID_PART, ['tab-id-1', 'tab-id-2'])

    m = timeline_model.TimelineModel(builder.AsData())
    processes = m.GetAllProcesses()
    self.assertEqual(1, len(processes))
    self.assertIs(processes[0], m.GetRendererProcessFromTabId('tab-id-1'))
    self.assertIs(processes[0], m.GetRendererProcessFromTabId('tab-id-2'))

    p = processes[0]
    self.assertEqual(2, len(p.threads))
    self.assertIs(p.threads[1], m.GetRendererThreadFromTabId('tab-id-1'))
    self.assertIs(p.threads[2], m.GetRendererThreadFromTabId('tab-id-2'))
