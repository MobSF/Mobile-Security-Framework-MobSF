# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import mock
import unittest

from telemetry.internal.platform import android_platform_backend
from telemetry.internal.platform.tracing_agent import display_tracing_agent
from telemetry.timeline import tracing_config

# pylint: disable=super-init-not-called, abstract-method, unused-argument
class FakeAndroidPlatformBackend(
    android_platform_backend.AndroidPlatformBackend):
  def __init__(self):
    self._device = 0
    self._raw_display_frame_rate_measurements = []
    self._surface_stats_collector = None

  @property
  def surface_stats_collector(self):
    return self._surface_stats_collector

  def IsDisplayTracingSupported(self):
    return True


class DisplayTracingAgentTest(unittest.TestCase):
  def setUp(self):
    self._config = tracing_config.TracingConfig()
    self._config.enable_platform_display_trace = True
    self._platform_backend = FakeAndroidPlatformBackend()
    self._agent = display_tracing_agent.DisplayTracingAgent(
        self._platform_backend)

  def stopAndCollect(self):
    self._agent.StopAgentTracing()
    self._agent.CollectAgentTraceData(mock.MagicMock())

  @mock.patch(
      'devil.android.perf.surface_stats_collector.SurfaceStatsCollector')
  def testStartAndStopTracing(self, MockSurfaceStatsCollector):
    self._agent.StartAgentTracing(self._config, 10)
    # Second start tracing will raise error.
    with self.assertRaises(AssertionError):
      self._agent.StartAgentTracing(self._config, 10)
    self._platform_backend.surface_stats_collector.Stop.return_value = (0, [])
    self.stopAndCollect()

    # Can start and stop tracing multiple times.
    self._agent.StartAgentTracing(self._config, 10)
    self._platform_backend.surface_stats_collector.Stop.return_value = (0, [])
    self.stopAndCollect()

  @mock.patch(
      'devil.android.perf.surface_stats_collector.SurfaceStatsCollector')
  def testExceptionRaisedInStopTracing(self, MockSurfaceStatsCollector):
    self._agent.StartAgentTracing(self._config, 10)
    self._platform_backend.surface_stats_collector.Stop.side_effect = Exception(
        'Raise error when stopping tracing.')
    with self.assertRaises(Exception):
      self.stopAndCollect()
    # Tracing is stopped even if there is exception. And the agent can start
    # tracing again.
    self._agent.StartAgentTracing(self._config, 10)
    self._platform_backend.surface_stats_collector.Stop.side_effect = None
    self._platform_backend.surface_stats_collector.Stop.return_value = (0, [])
    self.stopAndCollect()
