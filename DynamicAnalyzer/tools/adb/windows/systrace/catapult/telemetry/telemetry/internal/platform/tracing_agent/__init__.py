# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class TracingAgent(object):
  """A tracing agent provided by the platform.

  A tracing agent can gather data with Start() until Stop().
  Before constructing an TracingAgent, check whether it's supported on the
  platform with IsSupported method first.

  NOTE: All subclasses of TracingAgent must not change the constructor's
  parameters so the agents can be dynamically constructed in
  tracing_controller_backend.

  """

  def __init__(self, platform_backend):
    self._platform_backend = platform_backend

  @classmethod
  def IsSupported(cls, platform_backend):
    del platform_backend  # unused
    return False

  def StartAgentTracing(self, config, timeout):
    """ Override to add tracing agent's custom logic to start tracing.

    Depending on trace_options and category_filter, the tracing agent may choose
    to start or not start tracing.

    Args:
      config: tracing_config instance that contains trace_option and
        category_filter
        trace_options: an instance of tracing_options.TracingOptions that
          control which core tracing systems should be enabled.
        category_filter: an instance of
          chrome_trace_category_filter.ChromeTraceCategoryFilter
      timeout: number of seconds that this tracing agent should try to start
        tracing until time out.

    Returns:
      True if tracing agent started successfully.
    """
    raise NotImplementedError

  def StopAgentTracing(self):
    """ Override to add tracing agent's custom logic to stop tracing.

    StopAgentTracing() should guarantee tracing is stopped, even if there may
    be exception.
    """
    raise NotImplementedError

  def SupportsFlushingAgentTracing(self):
    """ Override to indicate support of flushing tracing. """
    return False

  def FlushAgentTracing(self, config, timeout, trace_data_builder):
    """ Override to add tracing agent's custom logic to flush tracing. """
    del config, timeout, trace_data_builder  # unused
    raise NotImplementedError

  def SupportsExplicitClockSync(self):
    """ Override to indicate support of explicit clock syncing. """
    return False

  def RecordClockSyncMarker(self, sync_id,
                            record_controller_clocksync_marker_callback):
    """ Override to record clock sync marker.

    Only override if supports explicit clock syncing.
    Args:
      sync_id: Unqiue id for sync event.
      record_controller_clocksync_marker_callback: Function that accepts two
        arguments: a sync ID and a timestamp taken immediately before the
        controller requested that the agent write a clock sync marker into its
        trace. Any tracing agent that implements this method must invoke this
        callback immediately after receiving confirmation from the agent that
        the clock sync marker was recorded.

        We use a callback here rather than just calling this function after
        RecordClockSyncMarker because it's important for clock sync accuracy
        reasons that the "issued" timestamp and "received confirmation"
        timestamp be as accurate as possible, and some agents are forced to do
        additional time-consuming cleanup work in RecordClockSyncMarker after
        receiving this confirmation.
    """
    del sync_id # unused
    del record_controller_clocksync_marker_callback # unused
    raise NotImplementedError

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    """ Override to add agent's custom logic to collect tracing data. """
    del trace_data_builder
    del timeout
    raise NotImplementedError
