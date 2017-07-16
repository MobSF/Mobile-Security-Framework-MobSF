# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import logging
import os
import plistlib
import shutil
import tempfile
import xml.parsers.expat

from telemetry.core import os_version
from telemetry import decorators
from telemetry.internal.platform import power_monitor

import py_utils


# TODO: rename this class (seems like this is used by mac)
class PowerMetricsPowerMonitor(power_monitor.PowerMonitor):

  def __init__(self, backend):
    super(PowerMetricsPowerMonitor, self).__init__()
    self._powermetrics_process = None
    self._backend = backend
    self._output_filename = None
    self._output_directory = None

  @property
  def binary_path(self):
    return '/usr/bin/powermetrics'

  def StartMonitoringPower(self, browser):
    self._CheckStart()
    # Empirically powermetrics creates an empty output file immediately upon
    # starting.  We detect file creation as a signal that measurement has
    # started.  In order to avoid various race conditions in tempfile creation
    # we create a temp directory and have powermetrics create it's output
    # there rather than say, creating a tempfile, deleting it and reusing its
    # name.
    self._output_directory = tempfile.mkdtemp()
    self._output_filename = os.path.join(self._output_directory,
                                         'powermetrics.output')
    args = ['-f', 'plist',
            '-u', self._output_filename,
            '-i0',
            '--show-usage-summary']
    self._powermetrics_process = self._backend.LaunchApplication(
        self.binary_path, args, elevate_privilege=True)

    # Block until output file is written to ensure this function call is
    # synchronous in respect to powermetrics starting.
    def _OutputFileExists():
      return os.path.isfile(self._output_filename)
    py_utils.WaitFor(_OutputFileExists, 1)

  @decorators.Cache
  def CanMonitorPower(self):
    mavericks_or_later = (
        self._backend.GetOSVersionName() >= os_version.MAVERICKS)
    binary_path = self.binary_path
    return mavericks_or_later and self._backend.CanLaunchApplication(
        binary_path)

  @staticmethod
  def _ParsePlistString(plist_string):
    """Wrapper to parse a plist from a string and catch any errors.

    Sometimes powermetrics will exit in the middle of writing it's output,
    empirically it seems that it always writes at least one sample in it's
    entirety so we can safely ignore any errors in it's output.

    Returns:
        Parser output on successful parse, None on parse error.
    """
    try:
      return plistlib.readPlistFromString(plist_string)
    except xml.parsers.expat.ExpatError:
      return None

  @staticmethod
  def ParsePowerMetricsOutput(powermetrics_output):
    """Parse output of powermetrics command line utility.

    Returns:
        Dictionary in the format returned by StopMonitoringPower() or None
        if |powermetrics_output| is empty - crbug.com/353250 .
    """
    if len(powermetrics_output) == 0:
      logging.warning('powermetrics produced zero length output')
      return {}

    # Container to collect samples for running averages.
    # out_path - list containing the key path in the output dictionary.
    # src_path - list containing the key path to get the data from in
    #    powermetrics' output.
    def ConstructMetric(out_path, src_path):
      RunningAverage = collections.namedtuple('RunningAverage', [
          'out_path', 'src_path', 'samples'])
      return RunningAverage(out_path, src_path, [])

    # List of RunningAverage objects specifying metrics we want to aggregate.
    metrics = [
        ConstructMetric(
            ['platform_info', 'average_frequency_hz'],
            ['processor', 'freq_hz']),
        ConstructMetric(
            ['platform_info', 'idle_percent'],
            ['processor', 'packages', 0, 'c_state_ratio'])]

    def DataWithMetricKeyPath(metric, powermetrics_output):
      """Retrieve the sample from powermetrics' output for a given metric.

      Args:
          metric: The RunningAverage object we want to collect a new sample for.
          powermetrics_output: Dictionary containing powermetrics output.

      Returns:
          The sample corresponding to |metric|'s keypath."""
      # Get actual data corresponding to key path.
      out_data = powermetrics_output
      for k in metric.src_path:
        out_data = out_data[k]

      assert type(out_data) in [int, float], (
          'Was expecting a number: %s (%s)' % (type(out_data), out_data))
      return float(out_data)

    sample_durations = []
    total_energy_consumption_mwh = 0
    # powermetrics outputs multiple plists separated by null terminators.
    raw_plists = powermetrics_output.split('\0')
    raw_plists = [x for x in raw_plists if len(x) > 0]
    assert len(raw_plists) == 1

    # -------- Examine contents of first plist for systems specs. --------
    plist = PowerMetricsPowerMonitor._ParsePlistString(raw_plists[0])
    if not plist:
      logging.warning('powermetrics produced invalid output, output length: '
                      '%d', len(powermetrics_output))
      return {}

    # Powermetrics doesn't record power usage when running on a VM.
    hw_model = plist.get('hw_model')
    if hw_model and hw_model.startswith('VMware'):
      return {}

    if 'GPU' in plist:
      metrics.extend([
          ConstructMetric(
              ['component_utilization', 'gpu', 'average_frequency_hz'],
              ['GPU', 0, 'freq_hz']),
          ConstructMetric(
              ['component_utilization', 'gpu', 'idle_percent'],
              ['GPU', 0, 'c_state_ratio'])])

    # There's no way of knowing ahead of time how many cpus and packages the
    # current system has. Iterate over cores and cpus - construct metrics for
    # each one.
    if 'processor' in plist:
      core_dict = plist['processor']['packages'][0]['cores']
      num_cores = len(core_dict)
      cpu_num = 0
      for core_idx in xrange(num_cores):
        num_cpus = len(core_dict[core_idx]['cpus'])
        base_src_path = ['processor', 'packages', 0, 'cores', core_idx]
        for cpu_idx in xrange(num_cpus):
          base_out_path = ['component_utilization', 'cpu%d' % cpu_num]
          # C State ratio is per-package, component CPUs of that package may
          # have different frequencies.
          metrics.append(ConstructMetric(
              base_out_path + ['average_frequency_hz'],
              base_src_path + ['cpus', cpu_idx, 'freq_hz']))
          metrics.append(ConstructMetric(
              base_out_path + ['idle_percent'],
              base_src_path + ['c_state_ratio']))
          cpu_num += 1

    # -------- Parse Data Out of Plists --------
    plist = PowerMetricsPowerMonitor._ParsePlistString(raw_plists[0])
    if not plist:
      logging.error('Error parsing plist.')
      return {}

    # Duration of this sample.
    sample_duration_ms = int(plist['elapsed_ns']) / 10 ** 6
    sample_durations.append(sample_duration_ms)

    if 'processor' not in plist:
      logging.error("'processor' field not found in plist.")
      return {}
    processor = plist['processor']

    total_energy_consumption_mwh = (
        (float(processor.get('package_joules', 0)) / 3600.) * 10 ** 3)

    for m in metrics:
      try:
        m.samples.append(DataWithMetricKeyPath(m, plist))
      except KeyError:
        # Old CPUs don't have c-states, so if data is missing, just ignore it.
        logging.info('Field missing from powermetrics output: %s', m.src_path)
        continue

    # -------- Collect and Process Data --------
    out_dict = {}
    out_dict['identifier'] = 'powermetrics'
    out_dict['energy_consumption_mwh'] = total_energy_consumption_mwh

    def StoreMetricAverage(metric, sample_durations, out):
      """Calculate average value of samples in a metric and store in output
         path as specified by metric.

      Args:
          metric: A RunningAverage object containing samples to average.
          sample_durations: A list which parallels the samples list containing
              the time slice for each sample.
          out: The output dicat, average is stored in the location specified by
              metric.out_path.
      """
      if len(metric.samples) == 0:
        return

      assert len(metric.samples) == len(sample_durations)
      avg = 0
      for i in xrange(len(metric.samples)):
        avg += metric.samples[i] * sample_durations[i]
      avg /= sum(sample_durations)

      # Store data in output, creating empty dictionaries as we go.
      for k in metric.out_path[:-1]:
        if not out.has_key(k):
          out[k] = {}
        out = out[k]
      out[metric.out_path[-1]] = avg

    for m in metrics:
      StoreMetricAverage(m, sample_durations, out_dict)

    if 'tasks' not in plist:
      logging.error("'tasks' field not found in plist.")
      return {}

    # The following CPU metrics are already time-normalized, and segmented by
    # process. Sum the metrics across all Chrome processes.
    cputime = 0
    energy_impact = 0
    browser_process_count = 0
    idle_wakeups = 0
    for task in plist['tasks']:
      if 'Chrome' in task['name'] or 'Chromium' in task['name']:
        if 'Helper' not in task['name']:
          browser_process_count += 1
        cputime += float(task['cputime_ms_per_s'])
        energy_impact += float(task.get('energy_impact', 0))
        idle_wakeups += float(task['idle_wakeups_per_s'])
    if browser_process_count == 0:
      logging.warning('No Chrome or Chromium browser process found with '
                      'powermetrics. Chrome CPU metrics will not be emitted.')
      return {}
    elif browser_process_count >= 2:
      logging.warning('powermetrics found more than one Chrome or Chromium '
                      'browser. Chrome CPU metrics will not be emitted.')
      # During Telemetry unit tests, there may be multiple Chrome browsers
      # present. Don't add cpu metrics, but don't return {} either.
    else:  # browser_process_count == 1:
      chrome_dict = {}
      chrome_dict['cputime_ms_per_s'] = cputime
      chrome_dict['energy_impact'] = energy_impact
      chrome_dict['idle_wakeups_per_s'] = idle_wakeups
      out_dict['component_utilization']['chrome'] = chrome_dict

    return out_dict

  def _KillPowerMetricsProcess(self):
    """Kill a running powermetrics process."""
    try:
      if self._powermetrics_process.poll() is None:
        self._powermetrics_process.terminate()
    except OSError as e:
      logging.warning(
          'Error when trying to terminate powermetric process: %s', repr(e))
      if self._powermetrics_process.poll() is None:
        # terminate() can fail when Powermetrics does not have the SetUID set.
        self._backend.LaunchApplication(
          '/usr/bin/pkill',
          ['-SIGTERM', os.path.basename(self.binary_path)],
          elevate_privilege=True)

  def StopMonitoringPower(self):
    self._CheckStop()
    # Tell powermetrics to take an immediate sample.
    try:
      self._KillPowerMetricsProcess()
      (power_stdout, power_stderr) = self._powermetrics_process.communicate()
      returncode = self._powermetrics_process.returncode
      assert returncode in [0, -15], (
          """powermetrics error
          return code=%d
          stdout=(%s)
          stderr=(%s)""" % (returncode, power_stdout, power_stderr))

      with open(self._output_filename, 'rb') as output_file:
        powermetrics_output = output_file.read()
      return PowerMetricsPowerMonitor.ParsePowerMetricsOutput(
          powermetrics_output)
    except Exception as e:
      logging.warning(
          'Error when trying to collect power monitoring data: %s', repr(e))
      return PowerMetricsPowerMonitor.ParsePowerMetricsOutput('')
    finally:
      shutil.rmtree(self._output_directory)
      self._output_directory = None
      self._output_filename = None
      self._powermetrics_process = None
