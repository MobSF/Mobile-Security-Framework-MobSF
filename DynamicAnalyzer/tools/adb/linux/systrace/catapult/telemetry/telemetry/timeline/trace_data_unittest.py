# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import exceptions
import os
import shutil
import tempfile
import unittest

from tracing_build import html2trace
from telemetry.timeline import trace_data


class TraceDataTest(unittest.TestCase):
  def testSerialize(self):
    test_dir = tempfile.mkdtemp()
    trace_path = os.path.join(test_dir, 'test_trace.json')
    try:
      ri = trace_data.CreateTraceDataFromRawData({'traceEvents': [1, 2, 3]})
      ri.Serialize(trace_path)
      with open(trace_path) as f:
        json_traces = html2trace.ReadTracesFromHTMLFilePath(f)
      self.assertEqual(json_traces, [{'traceEvents': [1, 2, 3]}])
    finally:
      shutil.rmtree(test_dir)

  def testEmptyArrayValue(self):
    # We can import empty lists and empty string.
    d = trace_data.CreateTraceDataFromRawData([])
    self.assertFalse(d.HasTracesFor(trace_data.CHROME_TRACE_PART))

  def testInvalidTrace(self):
    with self.assertRaises(AssertionError):
      trace_data.CreateTraceDataFromRawData({'hello': 1})

  def testListForm(self):
    d = trace_data.CreateTraceDataFromRawData([{'ph': 'B'}])
    self.assertTrue(d.HasTracesFor(trace_data.CHROME_TRACE_PART))
    events = d.GetTracesFor(trace_data.CHROME_TRACE_PART)[0].get(
        'traceEvents', [])
    self.assertEquals(1, len(events))

  def testStringForm(self):
    d = trace_data.CreateTraceDataFromRawData('[{"ph": "B"}]')
    self.assertTrue(d.HasTracesFor(trace_data.CHROME_TRACE_PART))
    events = d.GetTracesFor(trace_data.CHROME_TRACE_PART)[0].get(
        'traceEvents', [])
    self.assertEquals(1, len(events))


class TraceDataBuilderTest(unittest.TestCase):
  def testBasicChrome(self):
    builder = trace_data.TraceDataBuilder()
    builder.AddTraceFor(trace_data.CHROME_TRACE_PART,
                        {'traceEvents': [1, 2, 3]})
    builder.AddTraceFor(trace_data.TAB_ID_PART, ['tab-7'])
    builder.AddTraceFor(trace_data.BATTOR_TRACE_PART, 'battor data here')

    d = builder.AsData()
    self.assertTrue(d.HasTracesFor(trace_data.CHROME_TRACE_PART))
    self.assertTrue(d.HasTracesFor(trace_data.TAB_ID_PART))
    self.assertTrue(d.HasTracesFor(trace_data.BATTOR_TRACE_PART))

    self.assertRaises(Exception, builder.AsData)

  def testSetTraceFor(self):
    telemetry_trace = {
        'traceEvents': [1, 2, 3],
        'metadata': {
          'field1': 'value1'
        }
    }

    builder = trace_data.TraceDataBuilder()
    builder.AddTraceFor(trace_data.TELEMETRY_PART, telemetry_trace)
    d = builder.AsData()

    self.assertEqual(d.GetTracesFor(trace_data.TELEMETRY_PART),
                     [telemetry_trace])

  def testSetTraceForRaisesWithInvalidPart(self):
    builder = trace_data.TraceDataBuilder()

    self.assertRaises(exceptions.AssertionError,
                      lambda: builder.AddTraceFor('not_a_trace_part', {}))

  def testSetTraceForRaisesWithInvalidTrace(self):
    builder = trace_data.TraceDataBuilder()

    self.assertRaises(exceptions.AssertionError, lambda:
        builder.AddTraceFor(trace_data.TELEMETRY_PART, datetime.time.min))

  def testSetTraceForRaisesAfterAsData(self):
    builder = trace_data.TraceDataBuilder()
    builder.AsData()

    self.assertRaises(exceptions.Exception,
        lambda: builder.AddTraceFor(trace_data.TELEMETRY_PART, {}))
