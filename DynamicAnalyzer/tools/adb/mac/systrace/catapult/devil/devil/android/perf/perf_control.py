# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import atexit
import logging
import re

from devil.android import device_errors

logger = logging.getLogger(__name__)


class PerfControl(object):
  """Provides methods for setting the performance mode of a device."""

  _AVAILABLE_GOVERNORS_REL_PATH = 'cpufreq/scaling_available_governors'
  _CPU_FILE_PATTERN = re.compile(r'^cpu\d+$')
  _CPU_PATH = '/sys/devices/system/cpu'
  _KERNEL_MAX = '/sys/devices/system/cpu/kernel_max'

  def __init__(self, device):
    self._device = device
    self._cpu_files = [
        filename
        for filename in self._device.ListDirectory(self._CPU_PATH, as_root=True)
        if self._CPU_FILE_PATTERN.match(filename)]
    assert self._cpu_files, 'Failed to detect CPUs.'
    self._cpu_file_list = ' '.join(self._cpu_files)
    logger.info('CPUs found: %s', self._cpu_file_list)

    self._have_mpdecision = self._device.FileExists('/system/bin/mpdecision')

    raw = self._ReadEachCpuFile(self._AVAILABLE_GOVERNORS_REL_PATH)
    self._available_governors = [
        (cpu, raw_governors.strip().split() if not exit_code else None)
        for cpu, raw_governors, exit_code in raw]

  def SetHighPerfMode(self):
    """Sets the highest stable performance mode for the device."""
    try:
      self._device.EnableRoot()
    except device_errors.CommandFailedError:
      message = 'Need root for performance mode. Results may be NOISY!!'
      logger.warning(message)
      # Add an additional warning at exit, such that it's clear that any results
      # may be different/noisy (due to the lack of intended performance mode).
      atexit.register(logger.warning, message)
      return

    product_model = self._device.product_model
    # TODO(epenner): Enable on all devices (http://crbug.com/383566)
    if 'Nexus 4' == product_model:
      self._ForceAllCpusOnline(True)
      if not self._AllCpusAreOnline():
        logger.warning('Failed to force CPUs online. Results may be NOISY!')
      self.SetScalingGovernor('performance')
    elif 'Nexus 5' == product_model:
      self._ForceAllCpusOnline(True)
      if not self._AllCpusAreOnline():
        logger.warning('Failed to force CPUs online. Results may be NOISY!')
      self.SetScalingGovernor('performance')
      self._SetScalingMaxFreq(1190400)
      self._SetMaxGpuClock(200000000)
    else:
      self.SetScalingGovernor('performance')

  def SetPerfProfilingMode(self):
    """Enables all cores for reliable perf profiling."""
    self._ForceAllCpusOnline(True)
    self.SetScalingGovernor('performance')
    if not self._AllCpusAreOnline():
      if not self._device.HasRoot():
        raise RuntimeError('Need root to force CPUs online.')
      raise RuntimeError('Failed to force CPUs online.')

  def SetDefaultPerfMode(self):
    """Sets the performance mode for the device to its default mode."""
    if not self._device.HasRoot():
      return
    product_model = self._device.product_model
    if 'Nexus 5' == product_model:
      if self._AllCpusAreOnline():
        self._SetScalingMaxFreq(2265600)
        self._SetMaxGpuClock(450000000)

    governor_mode = {
        'GT-I9300': 'pegasusq',
        'Galaxy Nexus': 'interactive',
        'Nexus 4': 'ondemand',
        'Nexus 5': 'ondemand',
        'Nexus 7': 'interactive',
        'Nexus 10': 'interactive'
    }.get(product_model, 'ondemand')
    self.SetScalingGovernor(governor_mode)
    self._ForceAllCpusOnline(False)

  def GetCpuInfo(self):
    online = (output.rstrip() == '1' and status == 0
              for (_, output, status) in self._ForEachCpu('cat "$CPU/online"'))
    governor = (output.rstrip() if status == 0 else None
                for (_, output, status)
                in self._ForEachCpu('cat "$CPU/cpufreq/scaling_governor"'))
    return zip(self._cpu_files, online, governor)

  def _ForEachCpu(self, cmd):
    script = '; '.join([
        'for CPU in %s' % self._cpu_file_list,
        'do %s' % cmd,
        'echo -n "%~%$?%~%"',
        'done'
    ])
    output = self._device.RunShellCommand(
        script, cwd=self._CPU_PATH, check_return=True, as_root=True, shell=True)
    output = '\n'.join(output).split('%~%')
    return zip(self._cpu_files, output[0::2], (int(c) for c in output[1::2]))

  def _WriteEachCpuFile(self, path, value):
    self._ConditionallyWriteEachCpuFile(path, value, condition='true')

  def _ConditionallyWriteEachCpuFile(self, path, value, condition):
    template = (
        '{condition} && test -e "$CPU/{path}" && echo {value} > "$CPU/{path}"')
    results = self._ForEachCpu(
        template.format(path=path, value=value, condition=condition))
    cpus = ' '.join(cpu for (cpu, _, status) in results if status == 0)
    if cpus:
      logger.info('Successfully set %s to %r on: %s', path, value, cpus)
    else:
      logger.warning('Failed to set %s to %r on any cpus', path, value)

  def _ReadEachCpuFile(self, path):
    return self._ForEachCpu(
        'cat "$CPU/{path}"'.format(path=path))

  def SetScalingGovernor(self, value):
    """Sets the scaling governor to the given value on all possible CPUs.

    This does not attempt to set a governor to a value not reported as available
    on the corresponding CPU.

    Args:
      value: [string] The new governor value.
    """
    condition = 'test -e "{path}" && grep -q {value} {path}'.format(
        path=('${CPU}/%s' % self._AVAILABLE_GOVERNORS_REL_PATH),
        value=value)
    self._ConditionallyWriteEachCpuFile(
        'cpufreq/scaling_governor', value, condition)

  def GetScalingGovernor(self):
    """Gets the currently set governor for each CPU.

    Returns:
      An iterable of 2-tuples, each containing the cpu and the current
      governor.
    """
    raw = self._ReadEachCpuFile('cpufreq/scaling_governor')
    return [
        (cpu, raw_governor.strip() if not exit_code else None)
        for cpu, raw_governor, exit_code in raw]

  def ListAvailableGovernors(self):
    """Returns the list of available governors for each CPU.

    Returns:
      An iterable of 2-tuples, each containing the cpu and a list of available
      governors for that cpu.
    """
    return self._available_governors

  def _SetScalingMaxFreq(self, value):
    self._WriteEachCpuFile('cpufreq/scaling_max_freq', '%d' % value)

  def _SetMaxGpuClock(self, value):
    self._device.WriteFile('/sys/class/kgsl/kgsl-3d0/max_gpuclk',
                           str(value),
                           as_root=True)

  def _AllCpusAreOnline(self):
    results = self._ForEachCpu('cat "$CPU/online"')
    # TODO(epenner): Investigate why file may be missing
    # (http://crbug.com/397118)
    return all(output.rstrip() == '1' and status == 0
               for (cpu, output, status) in results
               if cpu != 'cpu0')

  def _ForceAllCpusOnline(self, force_online):
    """Enable all CPUs on a device.

    Some vendors (or only Qualcomm?) hot-plug their CPUs, which can add noise
    to measurements:
    - In perf, samples are only taken for the CPUs that are online when the
      measurement is started.
    - The scaling governor can't be set for an offline CPU and frequency scaling
      on newly enabled CPUs adds noise to both perf and tracing measurements.

    It appears Qualcomm is the only vendor that hot-plugs CPUs, and on Qualcomm
    this is done by "mpdecision".

    """
    if self._have_mpdecision:
      cmd = ['stop', 'mpdecision'] if force_online else ['start', 'mpdecision']
      self._device.RunShellCommand(cmd, check_return=True, as_root=True)

    if not self._have_mpdecision and not self._AllCpusAreOnline():
      logger.warning('Unexpected cpu hot plugging detected.')

    if force_online:
      self._ForEachCpu('echo 1 > "$CPU/online"')
