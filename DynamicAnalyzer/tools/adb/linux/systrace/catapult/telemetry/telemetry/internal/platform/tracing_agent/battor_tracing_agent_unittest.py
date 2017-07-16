# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from battor import battor_error
from battor import battor_wrapper
from devil.android import battery_utils
from telemetry.internal.platform.tracing_agent import battor_tracing_agent
from telemetry.timeline import trace_data
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


_BATTOR_RETURN = 'fake\nbattor\ndata'


class FakeBatteryUtils(object):
  def __init__(self, device):
    self._device = device
    self._charging_state = True

  def SetCharging(self, state):
    self._charging_state = state

  def GetCharging(self):
    return self._charging_state


class FakePlatformBackend(object):
  def GetOSName(self):
    return ''


class FakeAndroidPlatformBackend(FakePlatformBackend):
  def __init__(self):
    super(FakeAndroidPlatformBackend, self).__init__()
    self.device = 'fake_device'

  def GetOSName(self):
    return 'android'


class FakeDesktopPlatformBackend(FakePlatformBackend):
  def __init__(self):
    self.platform = 'win'

  def GetOSName(self):
    return self.platform


class FakeBattOr(object):
  def __init__(self, test_platform, android_device=None, battor_path=None,
               battor_map=None, serial_log_bucket=None):
    self._is_shell_running = False
    self._android_device = android_device
    self._battor_path = battor_path
    self._battor_map = battor_map
    self._test_platform = test_platform
    self._serial_log_bucket = serial_log_bucket
    self._stop_tracing_called = False
    self._start_shell_called = False
    self._start_tracing_called = False
    self._collect_trace_data_called = False
    self._record_clock_sync_marker_called = False

  def IsShellRunning(self):
    return self._is_shell_running

  def StartShell(self):
    self._is_shell_running = True
    self._start_shell_called = True

  def StartTracing(self):
    self.StartShell()
    self._start_tracing_called = True

  def StopTracing(self):
    self._is_shell_running = False
    self._stop_tracing_called = True

  def CollectTraceData(self, timeout=None):
    del timeout # unused
    self._collect_trace_data_called = True
    return _BATTOR_RETURN

  def RecordClockSyncMarker(self, _):
    self._record_clock_sync_marker_called = True


class BattOrTracingAgentTest(unittest.TestCase):
  def setUp(self):
    self._config = tracing_config.TracingConfig()
    self._config.enable_battor_trace = True

    # Monkey patch BattOrWrapper.
    self._battor_wrapper = battor_wrapper.BattOrWrapper
    battor_wrapper.BattOrWrapper = FakeBattOr
    battor_wrapper.IsBattOrConnected = lambda x, android_device=None: True

    self._battery_utils = battery_utils.BatteryUtils
    battery_utils.BatteryUtils = FakeBatteryUtils

    # Agents and backends.
    self.android_backend = FakeAndroidPlatformBackend()
    self.desktop_backend = FakeDesktopPlatformBackend()
    self.android_agent = (
        battor_tracing_agent.BattOrTracingAgent(self.android_backend))
    self.desktop_agent = (
        battor_tracing_agent.BattOrTracingAgent(self.desktop_backend))

  def tearDown(self):
    battor_wrapper.BattOrWrapper = self._battor_wrapper
    battery_utils.BatteryUtils = self._battery_utils

  def testInit(self):
    self.assertTrue(isinstance(self.android_agent._platform_backend,
                               FakeAndroidPlatformBackend))
    self.assertTrue(isinstance(self.desktop_agent._platform_backend,
                               FakeDesktopPlatformBackend))

  def testIsSupportedAndroid(self):
    self.assertTrue(battor_tracing_agent.BattOrTracingAgent.IsSupported(
        self.android_backend))
    battor_wrapper.IsBattOrConnected = lambda x, android_device=None: False
    self.assertFalse(battor_tracing_agent.BattOrTracingAgent.IsSupported(
        self.android_backend))

  def testIsSupportedNonAndroid(self):
    self.desktop_backend.platform = 'mac'
    battor_wrapper.IsBattOrConnected = lambda *unused: True
    self.assertTrue(battor_tracing_agent.BattOrTracingAgent.IsSupported(
        self.desktop_backend))
    battor_wrapper.IsBattOrConnected = lambda *unused: False
    self.assertFalse(battor_tracing_agent.BattOrTracingAgent.IsSupported(
        self.desktop_backend))

  def testStartAgentTracingPass(self):
    self.assertTrue(self.android_agent.StartAgentTracing(self._config, 0))
    self.assertTrue(self.android_agent._battor._is_shell_running)
    self.assertTrue(self.android_agent._battor._start_shell_called)
    self.assertTrue(self.android_agent._battor._start_tracing_called)
    self.assertFalse(self.android_agent._battor._stop_tracing_called)
    self.assertFalse(
        self.android_agent._battor._record_clock_sync_marker_called)

  def testStartAgentTracingConfigSetToFalse(self):
    self._config.enable_battor_trace = False
    self.assertFalse(self.android_agent.StartAgentTracing(self._config, 0))
    self.assertFalse(self.android_agent._battor._is_shell_running)
    self.assertFalse(self.android_agent._battor._start_shell_called)
    self.assertFalse(self.android_agent._battor._start_tracing_called)
    self.assertFalse(self.android_agent._battor._stop_tracing_called)
    self.assertFalse(
        self.android_agent._battor._record_clock_sync_marker_called)

  def testStartAgentTracingFail(self):
    def throw_battor_error():
      raise battor_error.BattOrError('Forced Exception')
    self.android_agent._battor.StartTracing = throw_battor_error
    with self.assertRaises(battor_error.BattOrError):
      self.android_agent.StartAgentTracing(self._config, 0)

  def testStopAgentTracing(self):
    self.android_agent.StopAgentTracing()
    self.assertTrue(self.android_agent._battor._stop_tracing_called)

  def testCollectAgentTraceData(self):
    builder = trace_data.TraceDataBuilder()
    self.android_agent.CollectAgentTraceData(builder)
    self.assertTrue(self.android_agent._battor._collect_trace_data_called)
    builder = builder.AsData()
    self.assertTrue(builder.HasTracesFor(trace_data.BATTOR_TRACE_PART))
    data_from_builder = builder.GetTracesFor(trace_data.BATTOR_TRACE_PART)
    self.assertEqual([_BATTOR_RETURN], data_from_builder)

  def testAndroidCharging(self):
    self.assertTrue(self.android_agent._battery.GetCharging())
    self.assertTrue(self.android_agent.StartAgentTracing(self._config, 0))
    self.assertFalse(self.android_agent._battery.GetCharging())
    self.android_agent.StopAgentTracing()
    self.assertTrue(self.android_agent._battery.GetCharging())

  def testRecordClockSyncMarker(self):
    def callback_with_exception(a, b):
      del a # unused
      del b # unused
      raise Exception
    def callback_without_exception(a, b):
      del a # unused
      del b # unused

    self.android_agent.RecordClockSyncMarker('123', callback_without_exception)
    with self.assertRaises(Exception):
      self.android_agent.RecordClockSyncMarker('abc', callback_with_exception)
