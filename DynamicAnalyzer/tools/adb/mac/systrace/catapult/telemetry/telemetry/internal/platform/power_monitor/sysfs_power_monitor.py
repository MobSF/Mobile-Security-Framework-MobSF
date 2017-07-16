# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import logging
import os
import re

from telemetry.internal.platform import power_monitor
from telemetry import decorators


CPU_PATH = '/sys/devices/system/cpu/'


class SysfsPowerMonitor(power_monitor.PowerMonitor):
  """PowerMonitor that relies on sysfs to monitor CPU statistics on several
  different platforms.
  """
  # TODO(rnephew): crbug.com/513453
  # Convert all platforms to use standalone power monitors.
  def __init__(self, linux_based_platform_backend, standalone=False):
    """Constructor.

    Args:
        linux_based_platform_backend: A LinuxBasedPlatformBackend object.
        standalone: If it is not wrapping another monitor, set to True.

    Attributes:
        _cpus: A list of the CPUs on the target device.
        _end_time: The time the test stopped monitoring power.
        _final_cstate: The c-state residency times after the test.
        _final_freq: The CPU frequency times after the test.
        _initial_cstate: The c-state residency times before the test.
        _initial_freq: The CPU frequency times before the test.
        _platform: A LinuxBasedPlatformBackend object associated with the
            target platform.
        _start_time: The time the test started monitoring power.
    """
    super(SysfsPowerMonitor, self).__init__()
    self._cpus = None
    self._final_cstate = None
    self._final_freq = None
    self._initial_cstate = None
    self._initial_freq = None
    self._platform = linux_based_platform_backend
    self._standalone = standalone

  @decorators.Cache
  def CanMonitorPower(self):
    return bool(self._platform.RunCommand(
        'if [ -e %s ]; then echo true; fi' % CPU_PATH))

  def StartMonitoringPower(self, browser):
    del browser  # unused
    self._CheckStart()
    if self.CanMonitorPower():
      self._cpus = filter(  # pylint: disable=deprecated-lambda
          lambda x: re.match(r'^cpu[0-9]+', x),
          self._platform.RunCommand('ls %s' % CPU_PATH).split())
      self._initial_freq = self.GetCpuFreq()
      self._initial_cstate = self.GetCpuState()

  def StopMonitoringPower(self):
    self._CheckStop()
    try:
      out = {}
      if SysfsPowerMonitor.CanMonitorPower(self):
        self._final_freq = self.GetCpuFreq()
        self._final_cstate = self.GetCpuState()
        frequencies = SysfsPowerMonitor.ComputeCpuStats(
            SysfsPowerMonitor.ParseFreqSample(self._initial_freq),
            SysfsPowerMonitor.ParseFreqSample(self._final_freq))
        cstates = SysfsPowerMonitor.ComputeCpuStats(
            self._platform.ParseCStateSample(self._initial_cstate),
            self._platform.ParseCStateSample(self._final_cstate))
        for cpu in frequencies:
          out[cpu] = {'frequency_percent': frequencies.get(cpu)}
          out[cpu] = {'cstate_residency_percent': cstates.get(cpu)}
      if self._standalone:
        return self.CombineResults(out, {})
      return out
    finally:
      self._initial_cstate = None
      self._initial_freq = None

  def GetCpuState(self):
    """Retrieve CPU c-state residency times from the device.

    Returns:
        Dictionary containing c-state residency times for each CPU.
    """
    stats = {}
    for cpu in self._cpus:
      cpu_idle_path = os.path.join(CPU_PATH, cpu, 'cpuidle')
      if not self._platform.PathExists(cpu_idle_path):
        logging.warning(
            'Cannot read cpu c-state residency times for %s due to %s not exist'
            % (cpu, cpu_idle_path))
        continue
      cpu_state_path = os.path.join(cpu_idle_path, 'state*')
      output = self._platform.RunCommand(
          'cat %s %s %s; date +%%s' % (
              os.path.join(cpu_state_path, 'name'),
              os.path.join(cpu_state_path, 'time'),
              os.path.join(cpu_state_path, 'latency')))
      stats[cpu] = re.sub('\n\n+', '\n', output)
    return stats

  def GetCpuFreq(self):
    """Retrieve CPU frequency times from the device.

    Returns:
        Dictionary containing frequency times for each CPU.
    """
    stats = {}
    for cpu in self._cpus:
      cpu_freq_path = os.path.join(
          CPU_PATH, cpu, 'cpufreq/stats/time_in_state')
      if not self._platform.PathExists(cpu_freq_path):
        logging.warning(
            'Cannot read cpu frequency times for %s due to %s not existing'
            % (cpu, cpu_freq_path))
        stats[cpu] = None
        continue
      try:
        stats[cpu] = self._platform.GetFileContents(cpu_freq_path)
      except Exception as e:
        logging.warning(
            'Cannot read cpu frequency times in %s due to error: %s' %
            (cpu_freq_path, e.message))
        stats[cpu] = None
    return stats

  @staticmethod
  def ParseFreqSample(sample):
    """Parse a single frequency sample.

    Args:
        sample: The single sample of frequency data to be parsed.

    Returns:
        A dictionary associating a frequency with a time.
    """
    sample_stats = {}
    for cpu in sample:
      frequencies = {}
      if sample[cpu] is None:
        sample_stats[cpu] = None
        continue
      for line in sample[cpu].splitlines():
        pair = line.split()
        freq = int(pair[0]) * 10 ** 3
        timeunits = int(pair[1])
        if freq in frequencies:
          frequencies[freq] += timeunits
        else:
          frequencies[freq] = timeunits
      sample_stats[cpu] = frequencies
    return sample_stats

  @staticmethod
  def ComputeCpuStats(initial, final):
    """Parse the CPU c-state and frequency values saved during monitoring.

    Args:
        initial: The parsed dictionary of initial statistics to be converted
        into percentages.
        final: The parsed dictionary of final statistics to be converted
        into percentages.

    Returns:
        Dictionary containing percentages for each CPU as well as an average
        across all CPUs.
    """
    cpu_stats = {}
    # Each core might have different states or frequencies, so keep track of
    # the total time in a state or frequency and how many cores report a time.
    cumulative_times = collections.defaultdict(lambda: (0, 0))
    for cpu in initial:
      current_cpu = {}
      total = 0
      if not initial[cpu] or not final[cpu]:
        cpu_stats[cpu] = collections.defaultdict(int)
        continue
      for state in initial[cpu]:
        current_cpu[state] = final[cpu][state] - initial[cpu][state]
        total += current_cpu[state]
      if total == 0:
        # Somehow it's possible for initial and final to have the same sum,
        # but a different distribution, making total == 0. crbug.com/426430
        cpu_stats[cpu] = collections.defaultdict(int)
        continue
      for state in current_cpu:
        current_cpu[state] /= (float(total) / 100.0)
        # Calculate the average c-state residency across all CPUs.
        time, count = cumulative_times[state]
        cumulative_times[state] = (time + current_cpu[state], count + 1)
      cpu_stats[cpu] = current_cpu
    average = {}
    for state in cumulative_times:
      time, count = cumulative_times[state]
      average[state] = time / float(count)
    cpu_stats['platform_info'] = average
    return cpu_stats

  @staticmethod
  def CombineResults(cpu_stats, power_stats):
    """Add frequency and c-state residency data to the power data.

    Args:
        cpu_stats: Dictionary containing CPU statistics.
        power_stats: Dictionary containing power statistics.

    Returns:
        Dictionary in the format returned by StopMonitoringPower.
    """
    if not cpu_stats:
      return power_stats
    if 'component_utilization' not in power_stats:
      power_stats['component_utilization'] = {}
    if 'platform_info' in cpu_stats:
      if 'platform_info' not in power_stats:
        power_stats['platform_info'] = {}
      power_stats['platform_info'].update(cpu_stats['platform_info'])
      del cpu_stats['platform_info']
    for cpu in cpu_stats:
      power_stats['component_utilization'][cpu] = cpu_stats[cpu]
    return power_stats
