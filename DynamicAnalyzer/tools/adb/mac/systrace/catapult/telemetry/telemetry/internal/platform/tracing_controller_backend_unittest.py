# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import gc
import platform as _platform
import unittest

from telemetry import decorators
from telemetry.internal.platform import linux_based_platform_backend
from telemetry.internal.platform import tracing_agent
from telemetry.internal.platform import tracing_controller_backend
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


class PlatformDevice(object):
  def __init__(self):
    self.build_version_sdk = 99

class PlatformBackend(linux_based_platform_backend.LinuxBasedPlatformBackend):
  # pylint: disable=abstract-method
  def __init__(self):
    super(PlatformBackend, self).__init__()
    self._mock_files = {}

  def GetOSName(self):
    if 'Win' in _platform.system():
      return 'win'
    elif 'Linux' in _platform.system():
      return 'android'
    elif 'Darwin' in _platform.system():
      return 'mac'

  @property
  def device(self):
    return PlatformDevice()


class FakeTracingAgentBase(tracing_agent.TracingAgent):
  def __init__(
      self, platform, start=True, clock_sync=True, split_collection=True):
    super(FakeTracingAgentBase, self).__init__(platform)
    self._start = start
    self._clock_sync = clock_sync
    self._sync_seen = False
    self._split_collection = split_collection

  def StartAgentTracing(self, config, timeout):
    return self._start

  def StopAgentTracing(self):
    pass

  def SupportsExplicitClockSync(self):
    return self._clock_sync

  def RecordClockSyncMarker(self, sync_id, callback):
    if not self._clock_sync:
      raise NotImplementedError
    self._sync_seen = True
    callback(sync_id, 1)

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    pass


class FakeTracingAgentStartAndClockSync(FakeTracingAgentBase):
  def __init__(self, platform):
    super(FakeTracingAgentStartAndClockSync, self).__init__(
        platform, start=True, clock_sync=True, split_collection=False)


class FakeTracingAgentStartAndNoClockSync(FakeTracingAgentBase):
  def __init__(self, platform):
    super(FakeTracingAgentStartAndNoClockSync, self).__init__(platform,
                                                            start=True,
                                                            clock_sync=False)


class FakeTracingAgentNoStartAndNoClockSync(FakeTracingAgentBase):
  def __init__(self, platform):
    super(FakeTracingAgentNoStartAndNoClockSync, self).__init__(platform,
                                                            start=False,
                                                            clock_sync=False)


class FakeTracingAgentNoStartAndClockSync(FakeTracingAgentBase):
  def __init__(self, platform):
    super(FakeTracingAgentNoStartAndClockSync, self).__init__(platform,
                                                              start=False,
                                                              clock_sync=True)


class TracingControllerBackendTest(unittest.TestCase):
  def _getControllerEventsAslist(self, data):
    traces = data.GetTracesFor(trace_data.TELEMETRY_PART)
    if not traces:
      return []
    assert len(traces) == 1
    telemetry_trace = traces[0]
    return telemetry_trace["traceEvents"]

  def _getControllerClockDomain(self, data):
    traces = data.GetTracesFor(trace_data.TELEMETRY_PART)
    if not traces:
      return []
    assert len(traces) == 1
    telemetry_trace = traces[0]
    telemetry_trace = data.GetTracesFor(trace_data.TELEMETRY_PART)[0]
    if not telemetry_trace or not telemetry_trace["metadata"]:
      return ""
    return telemetry_trace["metadata"]["clock-domain"]

  def _getSyncCount(self, data):
    return len([entry for entry in self._getControllerEventsAslist(data)
                if entry.get('name') == 'clock_sync'])

  def setUp(self):
    self.platform = PlatformBackend()
    self.controller = (
        tracing_controller_backend.TracingControllerBackend(self.platform))
    self.controller._supported_agents_classes = [FakeTracingAgentBase]
    self.config = tracing_config.TracingConfig()
    self.controller_log = self.controller._trace_log

  def tearDown(self):
    if self.controller.is_tracing_running:
      self.controller.StopTracing()

  @decorators.Isolated
  def testStartTracing(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)

  @decorators.Isolated
  def testDoubleStartTracing(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertFalse(self.controller.StartTracing(self.config, 30))

  @decorators.Isolated
  def testStopTracingNotStarted(self):
    with self.assertRaises(AssertionError):
      self.controller.StopTracing()

  @decorators.Isolated
  def testStopTracing(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    data = self.controller.StopTracing()
    self.assertEqual(self._getSyncCount(data), 1)
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEqual(self.controller._trace_log, None)

  @decorators.Isolated
  def testDoubleStopTracing(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    with self.assertRaises(AssertionError):
      self.controller.StopTracing()

  @decorators.Isolated
  def testMultipleStartStop(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    data = self.controller.StopTracing()
    self.assertEqual(self._getSyncCount(data), 1)
    sync_event_one = [x for x in self._getControllerEventsAslist(data)
                      if x.get('name') == 'clock_sync'][0]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEqual(self.controller._trace_log, None)
    # Run 2
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    data = self.controller.StopTracing()
    self.assertEqual(self._getSyncCount(data), 1)
    sync_event_two = [x for x in self._getControllerEventsAslist(data)
                      if x.get('name') == 'clock_sync'][0]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertFalse(self.controller._trace_log, None)
    # Test difference between events
    self.assertNotEqual(sync_event_one, sync_event_two)

  @decorators.Isolated
  def testCollectAgentDataBeforeStoppingTracing(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    with self.assertRaises(AssertionError):
      self.controller.CollectAgentTraceData(None)

  @decorators.Isolated
  def testFlush(self):
    self.assertFalse(self.controller.is_tracing_running)
    self.assertIsNone(self.controller._current_state)

    # Start tracing.
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertIs(self.controller._current_state.config, self.config)
    self.assertEqual(self.controller._current_state.timeout, 30)
    self.assertIsNotNone(self.controller._current_state.builder)

    # Flush tracing several times.
    for _ in xrange(5):
      self.controller.FlushTracing()
      self.assertTrue(self.controller.is_tracing_running)
      self.assertIs(self.controller._current_state.config, self.config)
      self.assertEqual(self.controller._current_state.timeout, 30)
      self.assertIsNotNone(self.controller._current_state.builder)

    # Stop tracing.
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertIsNone(self.controller._current_state)

    self.assertEqual(self._getSyncCount(data), 6)

  @decorators.Isolated
  def testNoWorkingAgents(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentNoStartAndNoClockSync
    ]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertEquals(self.controller._active_agents_instances, [])
    data = self.controller.StopTracing()
    self.assertEqual(self._getSyncCount(data), 0)
    self.assertFalse(self.controller.is_tracing_running)

  @decorators.Isolated
  def testNoClockSyncSupport(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentStartAndNoClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
    ]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEquals(self._getSyncCount(data), 0)

  @decorators.Isolated
  def testClockSyncSupport(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentStartAndNoClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndNoClockSync
    ]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertEquals(len(self.controller._active_agents_instances), 3)
    # No sync event before running StopTracing().
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEquals(self._getSyncCount(data), 2)
    self.assertEquals(self._getControllerClockDomain(data), "TELEMETRY")

  @decorators.Isolated
  def testMultipleAgents(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync
    ]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertEquals(len(self.controller._active_agents_instances), 4)
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEquals(self._getSyncCount(data), 2)

  @decorators.Isolated
  def testGenerateRandomSyncId(self):
    ids = []
    for _ in xrange(1000):
      i = self.controller._GenerateClockSyncId()
      self.assertFalse(i in ids)
      ids.append(i)

  @decorators.Isolated
  def testRecordIssuerClockSyncMarker(self):
    sync_id = 'test_id'
    ts = 1
    self.controller._supported_agents_classes = [
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync
    ]
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.controller._RecordIssuerClockSyncMarker(sync_id, ts)
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEquals(self._getSyncCount(data), 1)
    self.assertEquals(self._getControllerClockDomain(data), "TELEMETRY")
    log = self._getControllerEventsAslist(data)
    for entry in log:
      if entry.get('name') == 'clock_sync':
        self.assertEqual(entry['args']['sync_id'], sync_id)
        self.assertEqual(entry['args']['issue_ts'], 1)

  @decorators.Isolated
  def testIssueClockSyncMarker_normalUse(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync
    ]
    self.assertFalse(self.controller.is_tracing_running)
    self.assertTrue(self.controller.StartTracing(self.config, 30))
    self.assertTrue(self.controller.is_tracing_running)
    self.assertEquals(len(self.controller._active_agents_instances), 4)
    self.controller._IssueClockSyncMarker()
    data = self.controller.StopTracing()
    self.assertFalse(self.controller.is_tracing_running)
    self.assertEquals(self._getSyncCount(data), 4)
    self.assertEquals(self._getControllerClockDomain(data), "TELEMETRY")

  @decorators.Isolated
  def testIssueClockSyncMarker_tracingNotControllable(self):
    self.controller._supported_agents_classes = [
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentNoStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync,
        FakeTracingAgentStartAndNoClockSync
    ]
    original_controllable = self.controller._IsTracingControllable
    self.controller._IsTracingControllable = lambda: False
    try:
      self.assertFalse(self.controller.is_tracing_running)
      self.assertTrue(self.controller.StartTracing(self.config, 30))
      self.assertTrue(self.controller.is_tracing_running)
      self.assertEquals(len(self.controller._active_agents_instances), 4)
      self.controller._IssueClockSyncMarker()
      data = self.controller.StopTracing()
      self.assertFalse(self.controller.is_tracing_running)
      self.assertEquals(self._getSyncCount(data), 0)
    finally:
      self.controller._IsTracingControllable = original_controllable

  @decorators.Isolated
  def testDisableGarbageCollection(self):
    self.assertTrue(gc.isenabled())
    with self.controller._DisableGarbageCollection():
      self.assertFalse(gc.isenabled())
    self.assertTrue(gc.isenabled())
