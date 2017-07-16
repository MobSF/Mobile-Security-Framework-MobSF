# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import optparse
import os
import py_utils
import signal
import subprocess
import sys
import tempfile

from devil.android import device_temp_file
from devil.android.perf import perf_control

from profile_chrome import ui
from systrace import trace_result
from systrace import tracing_agents

_CATAPULT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..')
sys.path.append(os.path.join(_CATAPULT_DIR, 'telemetry'))
try:
  # pylint: disable=F0401
  from telemetry.internal.platform.profiler import android_profiling_helper
  from telemetry.internal.util import binary_manager
except ImportError:
  android_profiling_helper = None
  binary_manager = None


_PERF_OPTIONS = [
    # Sample across all processes and CPUs to so that the current CPU gets
    # recorded to each sample.
    '--all-cpus',
    # In perf 3.13 --call-graph requires an argument, so use the -g short-hand
    # which does not.
    '-g',
    # Increase priority to avoid dropping samples. Requires root.
    '--realtime', '80',
    # Record raw samples to get CPU information.
    '--raw-samples',
    # Increase sampling frequency for better coverage.
    '--freq', '2000',
]


class _PerfProfiler(object):
  def __init__(self, device, perf_binary, categories):
    self._device = device
    self._output_file = device_temp_file.DeviceTempFile(
        self._device.adb, prefix='perf_output')
    self._log_file = tempfile.TemporaryFile()

    # TODO(jbudorick) Look at providing a way to unhandroll this once the
    #                 adb rewrite has fully landed.
    device_param = (['-s', str(self._device)] if str(self._device) else [])
    cmd = ['adb'] + device_param + \
          ['shell', perf_binary, 'record',
           '--output', self._output_file.name] + _PERF_OPTIONS
    if categories:
      cmd += ['--event', ','.join(categories)]
    self._perf_control = perf_control.PerfControl(self._device)
    self._perf_control.SetPerfProfilingMode()
    self._perf_process = subprocess.Popen(cmd,
                                          stdout=self._log_file,
                                          stderr=subprocess.STDOUT)

  def SignalAndWait(self):
    self._device.KillAll('perf', signum=signal.SIGINT)
    self._perf_process.wait()
    self._perf_control.SetDefaultPerfMode()

  def _FailWithLog(self, msg):
    self._log_file.seek(0)
    log = self._log_file.read()
    raise RuntimeError('%s. Log output:\n%s' % (msg, log))

  def PullResult(self, output_path):
    if not self._device.FileExists(self._output_file.name):
      self._FailWithLog('Perf recorded no data')

    perf_profile = os.path.join(output_path,
                                os.path.basename(self._output_file.name))
    self._device.PullFile(self._output_file.name, perf_profile)
    if not os.stat(perf_profile).st_size:
      os.remove(perf_profile)
      self._FailWithLog('Perf recorded a zero-sized file')

    self._log_file.close()
    self._output_file.close()
    return perf_profile


class PerfProfilerAgent(tracing_agents.TracingAgent):
  def __init__(self, device):
    tracing_agents.TracingAgent.__init__(self)
    self._device = device
    self._perf_binary = self._PrepareDevice(device)
    self._perf_instance = None
    self._categories = None

  def __repr__(self):
    return 'perf profile'

  @staticmethod
  def IsSupported():
    return bool(android_profiling_helper)

  @staticmethod
  def _PrepareDevice(device):
    if not 'BUILDTYPE' in os.environ:
      os.environ['BUILDTYPE'] = 'Release'
    if binary_manager.NeedsInit():
      binary_manager.InitDependencyManager(None)
    return android_profiling_helper.PrepareDeviceForPerf(device)

  @classmethod
  def GetCategories(cls, device):
    perf_binary = cls._PrepareDevice(device)
    # Perf binary returns non-zero exit status on "list" command.
    return device.RunShellCommand([perf_binary, 'list'], check_return=False)

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StartAgentTracing(self, config, timeout=None):
    self._categories = _ComputePerfCategories(config)
    self._perf_instance = _PerfProfiler(self._device,
                                        self._perf_binary,
                                        self._categories)
    return True

  @py_utils.Timeout(tracing_agents.START_STOP_TIMEOUT)
  def StopAgentTracing(self, timeout=None):
    if not self._perf_instance:
      return
    self._perf_instance.SignalAndWait()
    return True

  @py_utils.Timeout(tracing_agents.GET_RESULTS_TIMEOUT)
  def GetResults(self, timeout=None):
    with open(self._PullTrace(), 'r') as f:
      trace_data = f.read()
    return trace_result.TraceResult('perf', trace_data)

  @staticmethod
  def _GetInteractivePerfCommand(perfhost_path, perf_profile, symfs_dir,
                                 required_libs, kallsyms):
    cmd = '%s report -n -i %s --symfs %s --kallsyms %s' % (
        os.path.relpath(perfhost_path, '.'), perf_profile, symfs_dir, kallsyms)
    for lib in required_libs:
      lib = os.path.join(symfs_dir, lib[1:])
      if not os.path.exists(lib):
        continue
      objdump_path = android_profiling_helper.GetToolchainBinaryPath(
          lib, 'objdump')
      if objdump_path:
        cmd += ' --objdump %s' % os.path.relpath(objdump_path, '.')
        break
    return cmd

  def _PullTrace(self):
    symfs_dir = os.path.join(tempfile.gettempdir(),
                             os.path.expandvars('$USER-perf-symfs'))
    if not os.path.exists(symfs_dir):
      os.makedirs(symfs_dir)
    required_libs = set()

    # Download the recorded perf profile.
    perf_profile = self._perf_instance.PullResult(symfs_dir)
    required_libs = \
        android_profiling_helper.GetRequiredLibrariesForPerfProfile(
            perf_profile)
    if not required_libs:
      logging.warning('No libraries required by perf trace. Most likely there '
                      'are no samples in the trace.')

    # Build a symfs with all the necessary libraries.
    kallsyms = android_profiling_helper.CreateSymFs(self._device,
                                                    symfs_dir,
                                                    required_libs,
                                                    use_symlinks=False)
    perfhost_path = binary_manager.FetchPath(
        android_profiling_helper.GetPerfhostName(), 'x86_64', 'linux')

    ui.PrintMessage('\nNote: to view the profile in perf, run:')
    ui.PrintMessage('  ' + self._GetInteractivePerfCommand(perfhost_path,
        perf_profile, symfs_dir, required_libs, kallsyms))

    # Convert the perf profile into JSON.
    perf_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    'third_party', 'perf_to_tracing.py')
    json_file_name = os.path.basename(perf_profile)
    with open(os.devnull, 'w') as dev_null, \
        open(json_file_name, 'w') as json_file:
      cmd = [perfhost_path, 'script', '-s', perf_script_path, '-i',
             perf_profile, '--symfs', symfs_dir, '--kallsyms', kallsyms]
      if subprocess.call(cmd, stdout=json_file, stderr=dev_null):
        logging.warning('Perf data to JSON conversion failed. The result will '
                        'not contain any perf samples. You can still view the '
                        'perf data manually as shown above.')
        return None

    return json_file_name

  def SupportsExplicitClockSync(self):
    return False

  def RecordClockSyncMarker(self, sync_id, did_record_sync_marker_callback):
    # pylint: disable=unused-argument
    assert self.SupportsExplicitClockSync(), ('Clock sync marker cannot be '
        'recorded since explicit clock sync is not supported.')

def _OptionalValueCallback(default_value):
  def callback(option, _, __, parser):  # pylint: disable=unused-argument
    value = default_value
    if parser.rargs and not parser.rargs[0].startswith('-'):
      value = parser.rargs.pop(0)
    setattr(parser.values, option.dest, value)
  return callback


class PerfConfig(tracing_agents.TracingConfig):
  def __init__(self, perf_categories, device):
    tracing_agents.TracingConfig.__init__(self)
    self.perf_categories = perf_categories
    self.device = device


def try_create_agent(config):
  if config.perf_categories:
    return PerfProfilerAgent(config.device)
  return None

def add_options(parser):
  options = optparse.OptionGroup(parser, 'Perf profiling options')
  options.add_option('-p', '--perf', help='Capture a perf profile with '
                     'the chosen comma-delimited event categories. '
                     'Samples CPU cycles by default. Use "list" to see '
                     'the available sample types.', action='callback',
                     default='', callback=_OptionalValueCallback('cycles'),
                     metavar='PERF_CATEGORIES', dest='perf_categories')
  return options

def get_config(options):
  return PerfConfig(options.perf_categories, options.device)

def _ComputePerfCategories(config):
  if not PerfProfilerAgent.IsSupported():
    return []
  if not config.perf_categories:
    return []
  return config.perf_categories.split(',')
