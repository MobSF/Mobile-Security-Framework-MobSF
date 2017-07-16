# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import re
import signal
import subprocess
import sys
import tempfile

from devil.android import device_errors  # pylint: disable=import-error

from telemetry.internal.util import binary_manager
from telemetry.core import platform
from telemetry.internal.platform import profiler
from telemetry.internal.platform.profiler import android_profiling_helper

from devil.android.perf import perf_control  # pylint: disable=import-error


_PERF_OPTIONS = [
    # Sample across all processes and CPUs to so that the current CPU gets
    # recorded to each sample.
    '--all-cpus',
    # In perf 3.13 --call-graph requires an argument, so use the -g short-hand
    # which does not.
    '-g',
    # Record raw samples to get CPU information.
    '--raw-samples',
    # Increase sampling frequency for better coverage.
    '--freq', '2000',
]

_PERF_OPTIONS_ANDROID = [
    # Increase priority to avoid dropping samples. Requires root.
    '--realtime', '80',
]


def _NicePath(path):
  rel_path = os.path.relpath(path, os.curdir)
  return rel_path if len(rel_path) < len(path) else path


def _PrepareHostForPerf():
  kptr_file = '/proc/sys/kernel/kptr_restrict'
  with open(kptr_file) as f:
    if f.read().strip() != '0':
      logging.warning('Making kernel symbols unrestricted. You might have to '
          'enter your password for "sudo".')
      with tempfile.NamedTemporaryFile() as zero:
        zero.write('0')
        zero.flush()
        subprocess.call(['/usr/bin/sudo', 'cp', zero.name, kptr_file])


def _InstallPerfHost():
  perfhost_name = android_profiling_helper.GetPerfhostName()
  host = platform.GetHostPlatform()
  if not host.CanLaunchApplication(perfhost_name):
    host.InstallApplication(perfhost_name)
  return binary_manager.FetchPath(perfhost_name, 'x86_64', 'linux')


class _SingleProcessPerfProfiler(object):
  """An internal class for using perf for a given process.

  On android, this profiler uses pre-built binaries from AOSP.
  See more details in prebuilt/android/README.txt.
  """
  def __init__(self, pid, output_file, browser_backend, platform_backend,
               perf_binary, perfhost_binary):
    self._pid = pid
    self._browser_backend = browser_backend
    self._platform_backend = platform_backend
    self._output_file = output_file
    self._tmp_output_file = tempfile.NamedTemporaryFile('w', 0)
    self._is_android = platform_backend.GetOSName() == 'android'
    self._perf_binary = perf_binary
    self._perfhost_binary = perfhost_binary
    cmd_prefix = []
    perf_args = ['record', '--pid', str(pid)]
    if self._is_android:
      cmd_prefix = [
          browser_backend.device.adb.GetAdbPath(),
          '-s', browser_backend.device.adb.GetDeviceSerial(),
          'shell', perf_binary]
      perf_args += _PERF_OPTIONS_ANDROID
      output_file = os.path.join('/sdcard', 'perf_profiles',
                                 os.path.basename(output_file))
      self._device_output_file = output_file
      browser_backend.device.RunShellCommand(
          ['mkdir', '-p', os.path.dirname(self._device_output_file)],
          check_return=True)
      browser_backend.device.RemovePath(self._device_output_file, force=True)
    else:
      cmd_prefix = [perf_binary]
    perf_args += ['--output', output_file] + _PERF_OPTIONS
    self._proc = subprocess.Popen(cmd_prefix + perf_args,
        stdout=self._tmp_output_file, stderr=subprocess.STDOUT)

  def CollectProfile(self):
    if ('renderer' in self._output_file and
        not self._is_android and
        not self._platform_backend.GetCommandLine(self._pid)):
      logging.warning('Renderer was swapped out during profiling. '
                      'To collect a full profile rerun with '
                      '"--extra-browser-args=--single-process"')
    if self._is_android:
      device = self._browser_backend.device
      try:
        binary_name = os.path.basename(self._perf_binary)
        device.KillAll(binary_name, signum=signal.SIGINT, blocking=True,
                       quiet=True)
      except device_errors.CommandFailedError:
        logging.warning('The perf process could not be killed on the device.')
    self._proc.send_signal(signal.SIGINT)
    exit_code = self._proc.wait()
    try:
      if exit_code == 128:
        raise Exception(
            """perf failed with exit code 128.
Try rerunning this script under sudo or setting
/proc/sys/kernel/perf_event_paranoid to "-1".\nOutput:\n%s""" %
            self._GetStdOut())
      elif exit_code not in (0, -2):
        raise Exception(
            'perf failed with exit code %d. Output:\n%s' % (exit_code,
                                                            self._GetStdOut()))
    finally:
      self._tmp_output_file.close()
    cmd = '%s report -n -i %s' % (_NicePath(self._perfhost_binary),
                                  self._output_file)
    if self._is_android:
      device = self._browser_backend.device
      device.PullFile(self._device_output_file, self._output_file)
      required_libs = \
          android_profiling_helper.GetRequiredLibrariesForPerfProfile(
              self._output_file)
      symfs_root = os.path.join(os.path.dirname(self._output_file), 'symfs')
      if not os.path.exists(symfs_root):
        os.makedirs(symfs_root)
      kallsyms = android_profiling_helper.CreateSymFs(device,
                                                      symfs_root,
                                                      required_libs,
                                                      use_symlinks=True)
      cmd += ' --symfs %s --kallsyms %s' % (symfs_root, kallsyms)
      for lib in required_libs:
        lib = os.path.join(symfs_root, lib[1:])
        if not os.path.exists(lib):
          continue
        objdump_path = android_profiling_helper.GetToolchainBinaryPath(
            lib, 'objdump')
        if objdump_path:
          cmd += ' --objdump %s' % _NicePath(objdump_path)
          break

    print 'To view the profile, run:'
    print ' ', cmd
    return self._output_file

  def _GetStdOut(self):
    self._tmp_output_file.flush()
    try:
      with open(self._tmp_output_file.name) as f:
        return f.read()
    except IOError:
      return ''


class PerfProfiler(profiler.Profiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(PerfProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    process_output_file_map = self._GetProcessOutputFileMap()
    self._process_profilers = []
    self._perf_control = None

    perf_binary = perfhost_binary = _InstallPerfHost()
    try:
      if platform_backend.GetOSName() == 'android':
        device = browser_backend.device
        perf_binary = android_profiling_helper.PrepareDeviceForPerf(device)
        self._perf_control = perf_control.PerfControl(device)
        self._perf_control.SetPerfProfilingMode()
      else:
        _PrepareHostForPerf()

      for pid, output_file in process_output_file_map.iteritems():
        if 'zygote' in output_file:
          continue
        self._process_profilers.append(
            _SingleProcessPerfProfiler(
                pid, output_file, browser_backend, platform_backend,
                perf_binary, perfhost_binary))
    except:
      if self._perf_control:
        self._perf_control.SetDefaultPerfMode()
      raise

  @classmethod
  def name(cls):
    return 'perf'

  @classmethod
  def is_supported(cls, browser_type):
    if sys.platform != 'linux2':
      return False
    if platform.GetHostPlatform().GetOSName() == 'chromeos':
      return False
    return True

  @classmethod
  def CustomizeBrowserOptions(cls, browser_type, options):
    options.AppendExtraBrowserArgs([
        '--no-sandbox',
        '--allow-sandbox-debugging',
    ])

  def CollectProfile(self):
    if self._perf_control:
      self._perf_control.SetDefaultPerfMode()
    output_files = []
    for single_process in self._process_profilers:
      output_files.append(single_process.CollectProfile())
    return output_files

  @classmethod
  def GetTopSamples(cls, file_name, number):
    """Parses the perf generated profile in |file_name| and returns a
    {function: period} dict of the |number| hottests functions.
    """
    assert os.path.exists(file_name)
    with open(os.devnull, 'w') as devnull:
      _InstallPerfHost()
      report = subprocess.Popen(
          [android_profiling_helper.GetPerfhostName(),
           'report', '--show-total-period', '-U', '-t', '^', '-i', file_name],
          stdout=subprocess.PIPE, stderr=devnull).communicate()[0]
    period_by_function = {}
    for line in report.split('\n'):
      if not line or line.startswith('#'):
        continue
      fields = line.split('^')
      if len(fields) != 5:
        continue
      period = int(fields[1])
      function = fields[4].partition(' ')[2]
      function = re.sub('<.*>', '', function)  # Strip template params.
      function = re.sub('[(].*[)]', '', function)  # Strip function params.
      period_by_function[function] = period
      if len(period_by_function) == number:
        break
    return period_by_function
