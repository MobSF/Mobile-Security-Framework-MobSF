# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import multiprocessing
import tempfile
import time

from telemetry.core import exceptions
from telemetry.internal.platform.power_monitor import android_power_monitor_base
from telemetry.internal.platform.profiler import monsoon


def _MonitorPower(device, is_collecting, output):
  """Monitoring process
     Args:
       device: A profiler.monsoon object to collect samples from.
       is_collecting: the event to synchronize on.
       output: opened file to write the samples.
  """
  with output:
    samples = []
    start_time = None
    end_time = None
    try:
      device.StartDataCollection()
      is_collecting.set()
      # First sample also calibrate the computation.
      device.CollectData()
      start_time = time.time()
      while is_collecting.is_set():
        new_data = device.CollectData()
        assert new_data, 'Unable to collect data from device'
        samples += new_data
      end_time = time.time()
    finally:
      device.StopDataCollection()
    result = {
      'duration_s': end_time - start_time,
      'samples': samples
    }
    json.dump(result, output)


class MonsoonPowerMonitor(android_power_monitor_base.AndroidPowerMonitorBase):
  def __init__(self, _, platform_backend):
    super(MonsoonPowerMonitor, self).__init__()
    self._powermonitor_process = None
    self._powermonitor_output_file = None
    self._is_collecting = None
    self._monsoon = None
    self._platform = platform_backend
    try:
      self._monsoon = monsoon.Monsoon(wait=False)
      # Nominal Li-ion voltage is 3.7V, but it puts out 4.2V at max capacity.
      # Use 4.0V to simulate a "~80%" charged battery. Google "li-ion voltage
      # curve". This is true only for a single cell. (Most smartphones, some
      # tablets.)
      self._monsoon.SetVoltage(4.0)
    except EnvironmentError:
      self._monsoon = None

  def CanMonitorPower(self):
    return self._monsoon is not None

  def StartMonitoringPower(self, browser):
    self._CheckStart()
    self._powermonitor_output_file = tempfile.TemporaryFile()
    self._is_collecting = multiprocessing.Event()
    self._powermonitor_process = multiprocessing.Process(
        target=_MonitorPower,
        args=(self._monsoon,
              self._is_collecting,
              self._powermonitor_output_file))
    # Ensure child is not left behind: parent kills daemonic children on exit.
    self._powermonitor_process.daemon = True
    self._powermonitor_process.start()
    if not self._is_collecting.wait(timeout=0.5):
      self._powermonitor_process.terminate()
      raise exceptions.ProfilingException('Failed to start data collection.')

  def StopMonitoringPower(self):
    self._CheckStop()
    try:
      # Tell powermonitor to take an immediate sample and join.
      self._is_collecting.clear()
      self._powermonitor_process.join()
      with self._powermonitor_output_file:
        self._powermonitor_output_file.seek(0)
        powermonitor_output = self._powermonitor_output_file.read()
      assert powermonitor_output, 'PowerMonitor produced no output'
      return MonsoonPowerMonitor.ParseSamplingOutput(powermonitor_output)
    finally:
      self._powermonitor_output_file = None
      self._powermonitor_process = None
      self._is_collecting = None

  @staticmethod
  def ParseSamplingOutput(powermonitor_output):
    """Parse the output of of the samples collector process.

    Returns:
        Dictionary in the format returned by StopMonitoringPower().
    """
    result = json.loads(powermonitor_output)
    if result['samples']:
      timedelta_h = (result['duration_s'] / len(result['samples'])) / 3600.0
      power_samples = [current_a * voltage_v * 10**3
                       for (current_a, voltage_v) in result['samples']]
      total_energy_consumption_mwh = sum(power_samples) * timedelta_h
    else:
      logging.warning('Sample information not available.')
      power_samples = []
      total_energy_consumption_mwh = 0

    return {'identifier':'monsoon',
            'power_samples_mw':power_samples,
            'monsoon_energy_consumption_mwh':total_energy_consumption_mwh}
