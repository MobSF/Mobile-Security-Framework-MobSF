# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json
import sys
import time
import unittest

from telemetry import decorators
from telemetry.internal.platform.tracing_agent import cpu_tracing_agent
from telemetry.internal.platform import tracing_agent
from telemetry.internal.platform import linux_platform_backend
from telemetry.internal.platform import mac_platform_backend
from telemetry.internal.platform import win_platform_backend
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


SNAPSHOT_KEYS = ['pid', 'ppid', 'name', 'pCpu', 'pMem']
TRACE_EVENT_KEYS = ['name', 'tid', 'pid', 'ph', 'args', 'local', 'id', 'ts']


class FakeAndroidPlatformBackend(object):
  def __init__(self):
    self.device = 'fake_device'

  def GetOSName(self):
    return 'android'


class CpuTracingAgentTest(unittest.TestCase):

  def setUp(self):
    self._config = tracing_config.TracingConfig()
    self._config.enable_cpu_trace = True
    if sys.platform.startswith('win'):
      self._desktop_backend = win_platform_backend.WinPlatformBackend()
    elif sys.platform.startswith('darwin'):
      self._desktop_backend = mac_platform_backend.MacPlatformBackend()
    else:
      self._desktop_backend = linux_platform_backend.LinuxPlatformBackend()
    self._agent = cpu_tracing_agent.CpuTracingAgent(self._desktop_backend)

  @decorators.Enabled('linux', 'mac', 'win')
  def testInit(self):
    self.assertTrue(isinstance(self._agent,
                               tracing_agent.TracingAgent))
    self.assertFalse(self._agent._snapshots)
    self.assertFalse(self._agent._snapshot_ongoing)

  @decorators.Enabled('linux', 'mac', 'win')
  def testIsSupported(self):
    self.assertTrue(cpu_tracing_agent.CpuTracingAgent.IsSupported(
      self._desktop_backend))
    self.assertFalse(cpu_tracing_agent.CpuTracingAgent.IsSupported(
      FakeAndroidPlatformBackend()))

  @decorators.Enabled('linux', 'mac', 'win')
  def testStartAgentTracing(self):
    self.assertFalse(self._agent._snapshot_ongoing)
    self.assertFalse(self._agent._snapshots)
    self.assertTrue(self._agent.StartAgentTracing(self._config, 0))
    self.assertTrue(self._agent._snapshot_ongoing)
    time.sleep(2)
    self.assertTrue(self._agent._snapshots)
    self._agent.StopAgentTracing()

  @decorators.Enabled('linux', 'mac', 'win')
  def testStartAgentTracingNotEnabled(self):
    self._config.enable_cpu_trace = False
    self.assertFalse(self._agent._snapshot_ongoing)
    self.assertFalse(self._agent.StartAgentTracing(self._config, 0))
    self.assertFalse(self._agent._snapshot_ongoing)
    self.assertFalse(self._agent._snapshots)
    time.sleep(2)
    self.assertFalse(self._agent._snapshots)

  @decorators.Enabled('linux', 'mac', 'win')
  def testStopAgentTracingBeforeStart(self):
    self.assertRaises(AssertionError, self._agent.StopAgentTracing)

  @decorators.Enabled('linux', 'mac', 'win')
  def testStopAgentTracing(self):
    self._agent.StartAgentTracing(self._config, 0)
    self._agent.StopAgentTracing()
    self.assertFalse(self._agent._snapshot_ongoing)

  @decorators.Enabled('linux', 'mac', 'win')
  def testCollectAgentTraceDataBeforeStop(self):
    self._agent.StartAgentTracing(self._config, 0)
    self.assertRaises(AssertionError, self._agent.CollectAgentTraceData,
        trace_data.TraceDataBuilder())
    self._agent.StopAgentTracing()

  @decorators.Enabled('linux', 'mac', 'win')
  def testCollectAgentTraceData(self):
    builder = trace_data.TraceDataBuilder()
    self._agent.StartAgentTracing(self._config, 0)
    self._agent.StopAgentTracing()
    self._agent.CollectAgentTraceData(builder)
    self.assertFalse(self._agent._snapshot_ongoing)
    builder = builder.AsData()
    self.assertTrue(builder.HasTracesFor(trace_data.CPU_TRACE_DATA))

  @decorators.Enabled('linux', 'mac', 'win')
  def testCollectAgentTraceDataFormat(self):
    builder = trace_data.TraceDataBuilder()
    self._agent.StartAgentTracing(self._config, 0)
    time.sleep(2)
    self._agent.StopAgentTracing()
    self._agent.CollectAgentTraceData(builder)
    builder = builder.AsData()
    data = json.loads(builder.GetTracesFor(trace_data.CPU_TRACE_DATA)[0])
    self.assertTrue(data)
    self.assertEquals(set(data[0].keys()), set(TRACE_EVENT_KEYS))
    self.assertEquals(set(data[0]['args']['snapshot'].keys()),
                      set(['processes']))
    self.assertTrue(data[0]['args']['snapshot']['processes'])
    self.assertEquals(set(data[0]['args']['snapshot']['processes'][0].keys()),
                      set(SNAPSHOT_KEYS))

  @decorators.Enabled('linux', 'mac', 'win')
  def testContainsRealProcesses(self):
    builder = trace_data.TraceDataBuilder()
    self._agent.StartAgentTracing(self._config, 0)
    time.sleep(2)
    self._agent.StopAgentTracing()
    self._agent.CollectAgentTraceData(builder)
    builder = builder.AsData()
    data = json.loads(builder.GetTracesFor(trace_data.CPU_TRACE_DATA)[0])
    self.assertTrue(data)
    for snapshot in data:
      found_unittest_process = False
      processes = snapshot['args']['snapshot']['processes']
      for process in processes:
        if 'run_tests' in process['name']:
          found_unittest_process = True

      self.assertTrue(found_unittest_process)

  @decorators.Enabled('win')
  def testWindowsCanHandleProcessesWithSpaces(self):
    proc_collector = cpu_tracing_agent.WindowsProcessCollector()
    proc_collector.Init()
    proc = proc_collector._ParseProcessString(
      '0 1 Multi Word Process 50 75')
    self.assertEquals(proc['ppid'], 0)
    self.assertEquals(proc['pid'], 1)
    self.assertEquals(proc['name'], 'Multi Word Process')
    self.assertEquals(proc['pCpu'], 50)
