# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.platform import tracing_agent


class TracingController(tracing_agent.TracingAgent):

  def __init__(self, tracing_controller_backend):
    """Provides control of the tracing systems supported by telemetry."""
    super(TracingController, self).__init__(
        tracing_controller_backend._platform_backend)
    self._tracing_controller_backend = tracing_controller_backend

  @property
  def telemetry_info(self):
    return self._tracing_controller_backend.telemetry_info

  @telemetry_info.setter
  def telemetry_info(self, ii):
    self._tracing_controller_backend.telemetry_info = ii

  def StartTracing(self, tracing_config, timeout=10):
    """Starts tracing.

    tracing config contains both tracing options and category filters.

    trace_options specifies which tracing systems to activate. Category filter
    allows fine-tuning of the data that are collected by the selected tracing
    systems.

    Some tracers are process-specific, e.g. chrome tracing, but are not
    guaranteed to be supported. In order to support tracing of these kinds of
    tracers, Start will succeed *always*, even if the tracing systems you have
    requested are not supported.

    If you absolutely require a particular tracer to exist, then check
    for its support after you have started the process in question. Or, have
    your code fail gracefully when the data you require is not present in the
    resulting trace.
    """
    self._tracing_controller_backend.StartTracing(tracing_config, timeout)

  def StopTracing(self):
    """Stops tracing and returns a TraceValue."""
    return self._tracing_controller_backend.StopTracing()

  def FlushTracing(self):
    """Flush tracing buffer and continue tracing.

    Warning: This method is a temporary hack to enable multi-tab benchmarks
    (see https://goo.gl/8Gjstr). Please contact Telemetry owners before using
    it.
    """
    self._tracing_controller_backend.FlushTracing()

  @property
  def is_tracing_running(self):
    return self._tracing_controller_backend.is_tracing_running

  def IsChromeTracingSupported(self):
    """Returns whether chrome tracing is supported."""
    return self._tracing_controller_backend.IsChromeTracingSupported()

  def StartAgentTracing(self, config, timeout=10):
    """ Starts agent tracing for tracing controller"""
    return self._tracing_controller_backend.StartAgentTracing(config, timeout)

  def StopAgentTracing(self):
    """ Stops agent tracing for tracing controller. """
    return self._tracing_controller_backend.StopAgentTracing()

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    """ Collect tracing data. """
    return self._tracing_controller_backend.CollectTraceData(trace_data_builder,
                                                             timeout=timeout)

  def SupportsExplicitClockSync(self):
    return self._tracing_controller_backend.SupportsExplicitClockSync()

  def RecordClockSyncMarker(self, sync_id,
                            record_controller_clocksync_marker_callback):
    return self._tracing_controller_backend.RecordClockSyncMarker(
        sync_id, record_controller_clocksync_marker_callback)

  def ClearStateIfNeeded(self):
    """Clear tracing state if needed."""
    self._tracing_controller_backend.ClearStateIfNeeded()
