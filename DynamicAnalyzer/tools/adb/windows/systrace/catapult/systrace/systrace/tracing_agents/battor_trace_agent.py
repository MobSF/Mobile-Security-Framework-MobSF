# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import atexit
import logging
import optparse
import py_utils

from battor import battor_wrapper
from devil.android import battery_utils
from devil.android import device_utils
from devil.utils import battor_device_mapping
from devil.utils import find_usb_devices
from py_trace_event import trace_time
from systrace import trace_result
from systrace import tracing_agents


def try_create_agent(config):
  if config.from_file is not None:
    return None
  if config.battor:
    return BattOrTraceAgent()
  return None


class BattOrConfig(tracing_agents.TracingConfig):
  def __init__(self, battor_categories, serial_map, battor_path,
               battor, target, from_file, device_serial_number):
    tracing_agents.TracingConfig.__init__(self)
    self.battor_categories = battor_categories
    self.serial_map = serial_map
    self.battor_path = battor_path
    self.battor = battor
    self.target = target
    self.from_file = from_file
    self.device_serial_number = device_serial_number


def add_options(parser):
  options = optparse.OptionGroup(parser, 'BattOr trace options')
  options.add_option('--battor-categories', dest='battor_categories',
                     help='Select battor categories with a comma-delimited '
                     'list, e.g. --battor-categories=cat1,cat2,cat3')
  options.add_option('--serial-map', dest='serial_map',
                    default='serial_map.json',
                    help='File containing pregenerated map of phone serial '
                    'numbers to BattOr serial numbers.')
  options.add_option('--battor-path', dest='battor_path', default=None,
                    type='string', help='specify a BattOr path to use')
  options.add_option('--battor', dest='battor', default=False,
                    action='store_true', help='Use the BattOr tracing agent.')
  return options

def get_config(options):
  return BattOrConfig(
      options.battor_categories, options.serial_map, options.battor_path,
      options.battor, options.target, options.from_file,
      options.device_serial_number)

def _reenable_charging_if_needed(battery):
  if not battery.GetCharging():
    battery.SetCharging(True)
  logging.info('Charging status checked at exit.')


class BattOrTraceAgent(tracing_agents.TracingAgent):
  # Class representing tracing agent that gets data from a BattOr.
  # BattOrs are high-frequency power monitors used for battery testing.
  def __init__(self):
    super(BattOrTraceAgent, self).__init__()
    self._collection_process = None
    self._recording_error = None
    self._battor_wrapper = None
    self._battery_utils = None

  @staticmethod
  def _FindBattOrPath(config):
    device_tree = find_usb_devices.GetBusNumberToDeviceTreeMap()
    battors = battor_device_mapping.GetBattOrList(device_tree)
    battor_path = config.battor_path
    if not config.battor_path and not config.serial_map:
      assert len(battors) == 1, ('Must specify BattOr path if there is not '
                                 'exactly one')
      battor_path = battors[0]
    return battor_path

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    """Starts tracing.

    Args:
        config: Tracing config.

    Raises:
        RuntimeError: If trace already in progress.
        AssertionError: If There is no BattOr path given and more
            than one BattOr is attached.
    """
    battor_path = self._FindBattOrPath(config)
    self._battor_wrapper = battor_wrapper.BattOrWrapper(
        target_platform=config.target,
        android_device=config.device_serial_number,
        battor_path=battor_path,
        battor_map_file=config.serial_map)

    dev_utils = device_utils.DeviceUtils(config.device_serial_number)
    self._battery_utils = battery_utils.BatteryUtils(dev_utils)
    self._battery_utils.SetCharging(False)
    atexit.register(_reenable_charging_if_needed, self._battery_utils)
    self._battor_wrapper.StartShell()
    self._battor_wrapper.StartTracing()
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    """Stops tracing and collects the results asynchronously.

    Creates a new process that stops the tracing and collects the results.
    Returns immediately after the process is created (does not wait for
    trace results to be collected).
    """
    self._battor_wrapper.StopTracing()
    self._battery_utils.SetCharging(True)
    return True

  def SupportsExplicitClockSync(self):
    """Returns whether this function supports explicit clock sync."""
    return self._battor_wrapper.SupportsExplicitClockSync()

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    """Records a clock sync marker.

    Args:
        sync_id: ID string for clock sync marker.
        did_record_sync_marker_callback: Callback function to call after
        the clock sync marker is recorded.
    """
    ts = trace_time.Now()
    self._battor_wrapper.RecordClockSyncMarker(sync_id)
    did_record_sync_marker_callback(ts, sync_id)

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    """Waits until data collection is completed and get the trace data.

    The trace data is the data that comes out of the BattOr, and is in the
    format with the following lines:

    time current voltage <sync_id>

    where the sync_id is only there if a clock sync marker was recorded
    during that sample.

    time = time since start of trace (ms)
    current = current through battery (mA) - this can be negative if the
        battery is charging
    voltage = voltage of battery (mV)

    Returns:
      The trace data.
    """
    return trace_result.TraceResult(
        'powerTraceAsString', self._battor_wrapper.CollectTraceData())
