# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry import decorators
from telemetry.core import cros_interface
from telemetry.core import platform
from telemetry.core import util
from telemetry.internal.forwarders import cros_forwarder
from telemetry.internal.platform import cros_device
from telemetry.internal.platform import linux_based_platform_backend
from telemetry.internal.platform.power_monitor import cros_power_monitor
from telemetry.internal.util import ps_util


class CrosPlatformBackend(
    linux_based_platform_backend.LinuxBasedPlatformBackend):
  def __init__(self, device=None):
    super(CrosPlatformBackend, self).__init__(device)
    if device and not device.is_local:
      self._cri = cros_interface.CrOSInterface(
          device.host_name, device.ssh_port, device.ssh_identity)
      self._cri.TryLogin()
    else:
      self._cri = cros_interface.CrOSInterface()
    self._powermonitor = cros_power_monitor.CrosPowerMonitor(self)

  @classmethod
  def IsPlatformBackendForHost(cls):
    return util.IsRunningOnCrosDevice()

  @classmethod
  def SupportsDevice(cls, device):
    return isinstance(device, cros_device.CrOSDevice)

  @classmethod
  def CreatePlatformForDevice(cls, device, finder_options):
    assert cls.SupportsDevice(device)
    return platform.Platform(CrosPlatformBackend(device))

  @property
  def cri(self):
    return self._cri

  @property
  def forwarder_factory(self):
    if not self._forwarder_factory:
      self._forwarder_factory = cros_forwarder.CrOsForwarderFactory(self._cri)
    return self._forwarder_factory

  def GetRemotePort(self, port):
    if self._cri.local:
      return port
    return self._cri.GetRemotePort()

  def IsThermallyThrottled(self):
    raise NotImplementedError()

  def HasBeenThermallyThrottled(self):
    raise NotImplementedError()

  def RunCommand(self, args):
    if not isinstance(args, list):
      args = [args]
    stdout, stderr = self._cri.RunCmdOnDevice(args)
    if stderr:
      raise IOError('Failed to run: cmd = %s, stderr = %s' %
                    (str(args), stderr))
    return stdout

  def GetFileContents(self, filename):
    try:
      return self.RunCommand(['cat', filename])
    except AssertionError:
      return ''

  def GetPsOutput(self, columns, pid=None):
    return ps_util.GetPsOutputWithPlatformBackend(self, columns, pid)

  @staticmethod
  def ParseCStateSample(sample):
    sample_stats = {}
    for cpu in sample:
      values = sample[cpu].splitlines()
      # There are three values per state after excluding the single time value.
      num_states = (len(values) - 1) / 3
      names = values[:num_states]
      times = values[num_states:2 * num_states]
      latencies = values[2 * num_states:]
      # The last line in the sample contains the time.
      cstates = {'C0': int(values[-1]) * 10 ** 6}
      for i, state in enumerate(names):
        if names[i] == 'POLL' and not int(latencies[i]):
          # C0 state. Kernel stats aren't right, so calculate by
          # subtracting all other states from total time (using epoch
          # timer since we calculate differences in the end anyway).
          # NOTE: Only x86 lists C0 under cpuidle, ARM does not.
          continue
        cstates['C0'] -= int(times[i])
        if names[i] == '<null>':
          # Kernel race condition that can happen while a new C-state gets
          # added (e.g. AC->battery). Don't know the 'name' of the state
          # yet, but its 'time' would be 0 anyway.
          continue
        cstates[state] = int(times[i])
      sample_stats[cpu] = cstates
    return sample_stats

  def GetDeviceTypeName(self):
    return self._cri.GetDeviceTypeName()

  @decorators.Cache
  def GetArchName(self):
    return self._cri.GetArchName()

  def GetOSName(self):
    return 'chromeos'

  def GetOSVersionName(self):
    return ''  # TODO: Implement this.

  def GetChildPids(self, pid):
    """Returns a list of child pids of |pid|."""
    all_process_info = self._cri.ListProcesses()
    processes = [(curr_pid, curr_ppid, curr_state)
                 for curr_pid, _, curr_ppid, curr_state in all_process_info]
    return ps_util.GetChildPids(processes, pid)

  def GetCommandLine(self, pid):
    procs = self._cri.ListProcesses()
    return next((proc[1] for proc in procs if proc[0] == pid), None)

  def CanFlushIndividualFilesFromSystemCache(self):
    return True

  def FlushEntireSystemCache(self):
    raise NotImplementedError()

  def FlushSystemCacheForDirectory(self, directory):
    flush_command = (
        '/usr/local/telemetry/src/src/out/Release/clear_system_cache')
    self.RunCommand(['chmod', '+x', flush_command])
    self.RunCommand([flush_command, '--recurse', directory])

  def CanMonitorPower(self):
    return self._powermonitor.CanMonitorPower()

  def StartMonitoringPower(self, browser):
    self._powermonitor.StartMonitoringPower(browser)

  def StopMonitoringPower(self):
    return self._powermonitor.StopMonitoringPower()

  def PathExists(self, path, timeout=None, retries=None):
    if timeout or retries:
      logging.warning(
          'PathExists: params timeout and retries are not support on CrOS.')
    return self._cri.FileExistsOnDevice(path)

  def CanTakeScreenshot(self):
    # crbug.com/609001: screenshots don't work on VMs.
    return not self.cri.IsRunningOnVM()

  def TakeScreenshot(self, file_path):
    return self._cri.TakeScreenshot(file_path)
