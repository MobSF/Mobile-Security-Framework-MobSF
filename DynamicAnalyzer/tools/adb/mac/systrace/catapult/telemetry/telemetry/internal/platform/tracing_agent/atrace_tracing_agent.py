# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from systrace.tracing_agents import atrace_agent
from telemetry.internal.platform import tracing_agent
from tracing.trace_data import trace_data

from devil.android.sdk import version_codes


class AtraceTracingAgent(tracing_agent.TracingAgent):
  def __init__(self, platform_backend):
    super(AtraceTracingAgent, self).__init__(platform_backend)
    self._device = platform_backend.device
    self._categories = None
    self._atrace_agent = atrace_agent.AtraceAgent(
        platform_backend.device.build_version_sdk)
    self._config = None

  @classmethod
  def IsSupported(cls, platform_backend):
    return (platform_backend.GetOSName() == 'android' and
        platform_backend.device.build_version_sdk >
            version_codes.JELLY_BEAN_MR1)

  def StartAgentTracing(self, config, timeout):
    if not config.enable_atrace_trace:
      return False

    app_name = (','.join(config.atrace_config.app_name) if
        isinstance(config.atrace_config.app_name, list) else
        config.atrace_config.app_name)
    self._config = atrace_agent.AtraceConfig(
        config.atrace_config.categories,
        trace_buf_size=None, kfuncs=None, app_name=app_name,
        compress_trace_data=True, from_file=True,
        device_serial_number=str(self._device), trace_time=None,
        target='android')
    return self._atrace_agent.StartAgentTracing(self._config, timeout)

  def StopAgentTracing(self):
    self._atrace_agent.StopAgentTracing()

  def SupportsExplicitClockSync(self):
    return self._atrace_agent.SupportsExplicitClockSync()

  def RecordClockSyncMarker(self, sync_id,
                            record_controller_clock_sync_marker_callback):
    return self._atrace_agent.RecordClockSyncMarker(sync_id,
        lambda t, sid: record_controller_clock_sync_marker_callback(sid, t))

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    raw_data = self._atrace_agent.GetResults(timeout).raw_data
    trace_data_builder.AddTraceFor(trace_data.ATRACE_PART, raw_data)
