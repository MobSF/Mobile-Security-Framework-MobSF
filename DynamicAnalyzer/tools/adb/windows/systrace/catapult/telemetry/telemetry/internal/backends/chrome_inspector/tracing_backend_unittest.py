# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import timeit
import unittest

from telemetry import decorators
from telemetry.internal.backends.chrome_inspector import tracing_backend
from telemetry.internal.backends.chrome_inspector.tracing_backend import _DevToolsStreamReader
from telemetry.testing import fakes
from telemetry.testing import tab_test_case
from telemetry.timeline import chrome_trace_config
from telemetry.timeline import model as model_module
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


class TracingBackendTest(tab_test_case.TabTestCase):

  # Number of consecutively requested memory dumps.
  _REQUESTED_DUMP_COUNT = 3

  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.logging_verbosity = options.VERBOSE_LOGGING
    options.AppendExtraBrowserArgs([
        # Memory maps currently cannot be retrieved on sandboxed processes.
        # See crbug.com/461788.
        '--no-sandbox',
    ])

  def setUp(self):
    super(TracingBackendTest, self).setUp()
    self._tracing_controller = self._browser.platform.tracing_controller
    if not self._tracing_controller.IsChromeTracingSupported():
      self.skipTest('Browser does not support tracing, skipping test.')
    if not self._browser.supports_memory_dumping:
      self.skipTest('Browser does not support memory dumping, skipping test.')

  # win: https://github.com/catapult-project/catapult/issues/3131.
  # chromeos: http://crbug.com/622836.
  @decorators.Disabled('win', 'chromeos')
  def testDumpMemorySuccess(self):
    # Check that dumping memory before tracing starts raises an exception.
    self.assertRaises(Exception, self._browser.DumpMemory)

    # Start tracing with memory dumps enabled.
    config = tracing_config.TracingConfig()
    config.chrome_trace_config.category_filter.AddDisabledByDefault(
        'disabled-by-default-memory-infra')
    config.chrome_trace_config.SetMemoryDumpConfig(
        chrome_trace_config.MemoryDumpConfig())
    config.enable_chrome_trace = True
    self._tracing_controller.StartTracing(config)

    # Request several memory dumps in a row and test that they were all
    # successfully created with unique IDs.
    expected_dump_ids = []
    for _ in xrange(self._REQUESTED_DUMP_COUNT):
      dump_id = self._browser.DumpMemory()
      self.assertIsNotNone(dump_id)
      self.assertNotIn(dump_id, expected_dump_ids)
      expected_dump_ids.append(dump_id)

    tracing_data = self._tracing_controller.StopTracing()

    # Check that clock sync data is in tracing data.
    clock_sync_found = False
    trace = tracing_data.GetTraceFor(trace_data.CHROME_TRACE_PART)
    for event in trace['traceEvents']:
      if event['name'] == 'clock_sync' or 'ClockSyncEvent' in event['name']:
        clock_sync_found = True
        break
    self.assertTrue(clock_sync_found)

    # Check that dumping memory after tracing stopped raises an exception.
    self.assertRaises(Exception, self._browser.DumpMemory)

    # Test that trace data is parsable.
    model = model_module.TimelineModel(tracing_data)
    self.assertGreater(len(model.processes), 0)

    # Test that the resulting model contains the requested memory dumps in the
    # correct order (and nothing more).
    actual_dump_ids = [d.dump_id for d in model.IterGlobalMemoryDumps()]
    self.assertEqual(actual_dump_ids, expected_dump_ids)

  def testDumpMemoryFailure(self):
    # Check that dumping memory before tracing starts raises an exception.
    self.assertRaises(Exception, self._browser.DumpMemory)

    # Start tracing with memory dumps disabled.
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    self._tracing_controller.StartTracing(config)

    # Check that the method returns None if the dump was not successful.
    self.assertIsNone(self._browser.DumpMemory())

    tracing_data = self._tracing_controller.StopTracing()

    # Check that dumping memory after tracing stopped raises an exception.
    self.assertRaises(Exception, self._browser.DumpMemory)

    # Test that trace data is parsable.
    model = model_module.TimelineModel(tracing_data)
    self.assertGreater(len(model.processes), 0)

    # Test that the resulting model contains no memory dumps.
    self.assertEqual(len(list(model.IterGlobalMemoryDumps())), 0)


class TracingBackendUnittest(unittest.TestCase):
  def setUp(self):
    self._fake_timer = fakes.FakeTimer(tracing_backend)
    self._inspector_socket = fakes.FakeInspectorWebsocket(self._fake_timer)

  def tearDown(self):
    self._fake_timer.Restore()

  def _GetRawChromeTracesFor(self, trace_data_builder):
    data = trace_data_builder.AsData().GetTracesFor(
        trace_data.CHROME_TRACE_PART)
    traces = []
    for d in data:
      traces.append(d)
    return traces

  def testCollectTracingDataTimeout(self):
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': {'traceEvents': [{'ph': 'B'}]}}, 9)
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': {'traceEvents': [{'ph': 'E'}]}}, 19)
    self._inspector_socket.AddEvent('Tracing.tracingComplete', {}, 35)
    backend = tracing_backend.TracingBackend(self._inspector_socket)

    trace_data_builder = trace_data.TraceDataBuilder()
    # The third response is 16 seconds after the second response, so we expect
    # a TracingTimeoutException.
    with self.assertRaises(tracing_backend.TracingTimeoutException):
      backend._CollectTracingData(trace_data_builder, 10)
    traces = self._GetRawChromeTracesFor(trace_data_builder)
    self.assertEqual(2, len(traces))
    self.assertEqual(1, len(traces[0].get('traceEvents', [])))
    self.assertEqual(1, len(traces[1].get('traceEvents', [])))
    self.assertFalse(backend._has_received_all_tracing_data)

  def testCollectTracingDataNoTimeout(self):
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': {'traceEvents': [{'ph': 'B'}]}}, 9)
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': {'traceEvents': [{'ph': 'E'}]}}, 14)
    self._inspector_socket.AddEvent('Tracing.tracingComplete', {}, 19)
    backend = tracing_backend.TracingBackend(self._inspector_socket)
    trace_data_builder = trace_data.TraceDataBuilder()
    backend._CollectTracingData(trace_data_builder, 10)
    traces = self._GetRawChromeTracesFor(trace_data_builder)
    self.assertEqual(2, len(traces))
    self.assertEqual(1, len(traces[0].get('traceEvents', [])))
    self.assertEqual(1, len(traces[1].get('traceEvents', [])))
    self.assertTrue(backend._has_received_all_tracing_data)

  def testCollectTracingDataFromStreamNoContainer(self):
    self._inspector_socket.AddEvent(
        'Tracing.tracingComplete', {'stream': '42'}, 1)
    self._inspector_socket.AddAsyncResponse(
        'IO.read', {'data': '{"traceEvents": [{},{},{'}, 2)
    self._inspector_socket.AddAsyncResponse(
        'IO.read', {'data': '},{},{}]}', 'eof': True}, 3)
    backend = tracing_backend.TracingBackend(self._inspector_socket)
    trace_data_builder = trace_data.TraceDataBuilder()
    backend._CollectTracingData(trace_data_builder, 10)
    trace_events = self._GetRawChromeTracesFor(trace_data_builder)[0].get(
        'traceEvents', [])
    self.assertEqual(5, len(trace_events))
    self.assertTrue(backend._has_received_all_tracing_data)

  def testCollectTracingDataFromStreamJSONContainer(self):
    self._inspector_socket.AddEvent(
        'Tracing.tracingComplete', {'stream': '42'}, 1)
    self._inspector_socket.AddAsyncResponse(
        'IO.read', {'data': '{"traceEvents": [{},{},{}],'}, 2)
    self._inspector_socket.AddAsyncResponse(
        'IO.read', {'data': '"metadata": {"a": "b"}'}, 3)
    self._inspector_socket.AddAsyncResponse(
        'IO.read', {'data': '}', 'eof': True}, 4)
    backend = tracing_backend.TracingBackend(self._inspector_socket)
    trace_data_builder = trace_data.TraceDataBuilder()
    backend._CollectTracingData(trace_data_builder, 10)
    chrome_trace = self._GetRawChromeTracesFor(trace_data_builder)[0]

    self.assertEqual(3, len(chrome_trace.get('traceEvents', [])))
    self.assertEqual(dict, type(chrome_trace.get('metadata')))
    self.assertTrue(backend._has_received_all_tracing_data)

  def testDumpMemorySuccess(self):
    self._inspector_socket.AddResponseHandler(
        'Tracing.requestMemoryDump',
        lambda req: {'result': {'success': True, 'dumpGuid': '42abc'}})
    backend = tracing_backend.TracingBackend(self._inspector_socket)

    self.assertEqual(backend.DumpMemory(), '42abc')

  def testDumpMemoryFailure(self):
    self._inspector_socket.AddResponseHandler(
        'Tracing.requestMemoryDump',
        lambda req: {'result': {'success': False, 'dumpGuid': '42abc'}})
    backend = tracing_backend.TracingBackend(self._inspector_socket)

    self.assertIsNone(backend.DumpMemory())

  def testStartTracingFailure(self):
    self._inspector_socket.AddResponseHandler(
        'Tracing.start',
        lambda req: {'error': {'message': 'Tracing is already started'}})
    self._inspector_socket.AddResponseHandler(
        'Tracing.hasCompleted', lambda req: {})
    backend = tracing_backend.TracingBackend(self._inspector_socket)
    config = tracing_config.TracingConfig()
    self.assertRaisesRegexp(
        tracing_backend.TracingUnexpectedResponseException,
        'Tracing is already started',
        backend.StartTracing, config.chrome_trace_config)

  def testStartTracingWithoutCollection(self):
    self._inspector_socket.AddResponseHandler('Tracing.start', lambda req: {})
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': [{'ph': 'B'}]}, 1)
    self._inspector_socket.AddEvent(
        'Tracing.dataCollected', {'value': [{'ph': 'E'}]}, 2)
    self._inspector_socket.AddEvent('Tracing.tracingComplete', {}, 3)
    self._inspector_socket.AddResponseHandler(
        'Tracing.hasCompleted', lambda req: {})

    backend = tracing_backend.TracingBackend(self._inspector_socket)
    config = tracing_config.TracingConfig()
    backend.StartTracing(config._chrome_trace_config)
    backend.StopTracing()
    with self.assertRaisesRegexp(AssertionError, 'Data not collected from .*'):
      backend.StartTracing(config._chrome_trace_config)


class DevToolsStreamPerformanceTest(unittest.TestCase):
  def setUp(self):
    self._fake_timer = fakes.FakeTimer(tracing_backend)
    self._inspector_socket = fakes.FakeInspectorWebsocket(self._fake_timer)

  def _MeasureReadTime(self, count):
    fake_time = self._fake_timer.time() + 1
    payload = ','.join(['{}'] * 5000)
    self._inspector_socket.AddAsyncResponse('IO.read', {'data': '[' + payload},
                                            fake_time)
    startClock = timeit.default_timer()

    done = {'done': False}
    def mark_done(data):
      del data  # unused
      done['done'] = True

    reader = _DevToolsStreamReader(self._inspector_socket, 'dummy')
    reader.Read(mark_done)
    while not done['done']:
      fake_time += 1
      if count > 0:
        self._inspector_socket.AddAsyncResponse('IO.read', {'data': payload},
            fake_time)
      elif count == 0:
        self._inspector_socket.AddAsyncResponse('IO.read',
            {'data': payload + ']', 'eof': True}, fake_time)
      count -= 1
      self._inspector_socket.DispatchNotifications(10)
    return timeit.default_timer() - startClock

  def testReadTime(self):
    n1 = 1000
    while True:
      t1 = self._MeasureReadTime(n1)
      if t1 > 0.01:
        break
      n1 *= 5
    t2 = self._MeasureReadTime(n1 * 10)
    # Time is an illusion, CPU time is doubly so, allow great deal of tolerance.
    toleranceFactor = 5
    self.assertLess(t2, t1 * 10 * toleranceFactor)
