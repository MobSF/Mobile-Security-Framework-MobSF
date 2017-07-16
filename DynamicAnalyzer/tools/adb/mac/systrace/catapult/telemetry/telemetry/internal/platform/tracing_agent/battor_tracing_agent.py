# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from battor import battor_error
from battor import battor_wrapper
from py_utils import cloud_storage
from devil.android import battery_utils
from py_trace_event import trace_time
from telemetry.internal.platform import tracing_agent
from telemetry.internal.util import atexit_with_log
from tracing.trace_data import trace_data


def _ReenableChargingIfNeeded(battery):
  if not battery.GetCharging():
    battery.SetCharging(True)
  logging.info('Charging status checked at exit.')


class BattOrTracingAgent(tracing_agent.TracingAgent):
  """A tracing agent for getting power data from a BattOr device.

  BattOrTracingAgent allows Telemetry to issue high-level tracing commands
  (StartTracing, StopTracing, RecordClockSyncMarker) to BattOrs, which are
  high-frequency power monitors used for battery testing.
  """

  def __init__(self, platform_backend):
    super(BattOrTracingAgent, self).__init__(platform_backend)
    self._platform_backend = platform_backend
    android_device = (
        platform_backend.device if platform_backend.GetOSName() == 'android'
        else None)
    self._battery = (
        battery_utils.BatteryUtils(platform_backend.device)
        if platform_backend.GetOSName() == 'android' else None)
    self._battor = battor_wrapper.BattOrWrapper(
        platform_backend.GetOSName(), android_device=android_device,
        serial_log_bucket=cloud_storage.TELEMETRY_OUTPUT)

  @classmethod
  def IsSupported(cls, platform_backend):
    """Returns True if BattOr tracing is available."""
    if platform_backend.GetOSName() == 'android':
      # TODO(rnephew): When we pass BattOr device map into Telemetry, change
      # this to reflect that.
      return battor_wrapper.IsBattOrConnected(
          'android', android_device=platform_backend.device)
    return battor_wrapper.IsBattOrConnected(platform_backend.GetOSName())

  def StartAgentTracing(self, config, timeout):
    """Start tracing on the BattOr.

    Args:
      config: A TracingConfig instance.
      timeout: number of seconds that this tracing agent should try to start
        tracing until timing out.

    Returns:
      True if the tracing agent started successfully.
    """
    if not config.enable_battor_trace:
      return False
    try:
      if self._battery:
        self._battery.SetCharging(False)
        atexit_with_log.Register(_ReenableChargingIfNeeded, self._battery)

      self._battor.StartShell()
      self._battor.StartTracing()
      return True
    except battor_error.BattOrError:
      if self._battery:
        self._battery.SetCharging(True)
      raise

  def StopAgentTracing(self):
    """Stops tracing on the BattOr."""
    try:
      self._battor.StopTracing()
    finally:
      if self._battery:
        self._battery.SetCharging(True)

  def SupportsExplicitClockSync(self):
    return self._battor.SupportsExplicitClockSync()

  def RecordClockSyncMarker(self, sync_id,
                            record_controller_clock_sync_marker_callback):
    """Records a clock sync marker in the BattOr trace.

    Args:
      sync_id: Unique id for sync event.
      record_controller_clock_sync_marker_callback: Function that takes a sync
        ID and a timestamp as arguments. This function typically will record the
        tracing controller clock sync marker.
    """
    timestamp = trace_time.Now()
    try:
      self._battor.RecordClockSyncMarker(sync_id)
    except battor_error.BattOrError:
      logging.critical(
          'Error while clock syncing with BattOr. Killing BattOr shell.')
      self._battor.KillBattOrShell()
      raise
    record_controller_clock_sync_marker_callback(sync_id, timestamp)

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    data = self._battor.CollectTraceData(timeout=timeout)
    trace_data_builder.AddTraceFor(trace_data.BATTOR_TRACE_PART, data)
