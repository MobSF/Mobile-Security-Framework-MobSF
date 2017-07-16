# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

try:
  import resource  # pylint: disable=import-error
except ImportError:
  resource = None  # Not available on all platforms

import re

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.platform import platform_backend


class LinuxBasedPlatformBackend(platform_backend.PlatformBackend):

  """Abstract platform containing functionality shared by all Linux based OSes.

  This includes Android and ChromeOS.

  Subclasses must implement RunCommand, GetFileContents, GetPsOutput, and
  ParseCStateSample."""

  # Get the commit charge in kB.
  def GetSystemCommitCharge(self):
    meminfo_contents = self.GetFileContents('/proc/meminfo')
    meminfo = self._GetProcFileDict(meminfo_contents)
    if not meminfo:
      return None
    return (self._ConvertToKb(meminfo['MemTotal'])
            - self._ConvertToKb(meminfo['MemFree'])
            - self._ConvertToKb(meminfo['Buffers'])
            - self._ConvertToKb(meminfo['Cached']))

  @decorators.Cache
  def GetSystemTotalPhysicalMemory(self):
    meminfo_contents = self.GetFileContents('/proc/meminfo')
    meminfo = self._GetProcFileDict(meminfo_contents)
    if not meminfo:
      return None
    return self._ConvertToBytes(meminfo['MemTotal'])

  def GetCpuStats(self, pid):
    results = {}
    stats = self._GetProcFileForPid(pid, 'stat')
    if not stats:
      return results
    stats = stats.split()
    utime = float(stats[13])
    stime = float(stats[14])
    cpu_process_jiffies = utime + stime
    clock_ticks = self.GetClockTicks()
    results.update({'CpuProcessTime': cpu_process_jiffies / clock_ticks})
    return results

  def GetCpuTimestamp(self):
    total_jiffies = self._GetProcJiffies()
    clock_ticks = self.GetClockTicks()
    return {'TotalTime': total_jiffies / clock_ticks}

  @decorators.Deprecated(
      2017, 11, 4,
      'Clients should use tracing and memory-infra in new Telemetry '
      'benchmarks. See for context: https://crbug.com/632021')
  def GetMemoryStats(self, pid):
    status_contents = self._GetProcFileForPid(pid, 'status')
    stats = self._GetProcFileForPid(pid, 'stat').split()
    status = self._GetProcFileDict(status_contents)
    if not status or not stats or 'Z' in status['State']:
      return {}
    vm = int(stats[22])
    vm_peak = (self._ConvertToBytes(status['VmPeak'])
               if 'VmPeak' in status else vm)
    wss = int(stats[23]) * resource.getpagesize()
    wss_peak = (self._ConvertToBytes(status['VmHWM'])
                if 'VmHWM' in status else wss)

    private_dirty_bytes = 0
    for line in self._GetProcFileForPid(pid, 'smaps').splitlines():
      if line.startswith('Private_Dirty:'):
        private_dirty_bytes += self._ConvertToBytes(line.split(':')[1].strip())

    return {'VM': vm,
            'VMPeak': vm_peak,
            'PrivateDirty': private_dirty_bytes,
            'WorkingSetSize': wss,
            'WorkingSetSizePeak': wss_peak}

  @decorators.Cache
  def GetClockTicks(self):
    """Returns the number of clock ticks per second.

    The proper way is to call os.sysconf('SC_CLK_TCK') but that is not easy to
    do on Android/CrOS. In practice, nearly all Linux machines have a USER_HZ
    of 100, so just return that.
    """
    return 100

  def GetFileContents(self, filename):
    raise NotImplementedError()

  def GetPsOutput(self, columns, pid=None):
    raise NotImplementedError()

  def RunCommand(self, cmd):
    """Runs the specified command.

    Args:
        cmd: A list of program arguments or the path string of the program.
    Returns:
        A string whose content is the output of the command.
    """
    raise NotImplementedError()

  @staticmethod
  def ParseCStateSample(sample):
    """Parse a single c-state residency sample.

    Args:
        sample: A sample of c-state residency times to be parsed. Organized as
            a dictionary mapping CPU name to a string containing all c-state
            names, the times in each state, the latency of each state, and the
            time at which the sample was taken all separated by newlines.
            Ex: {'cpu0': 'C0\nC1\n5000\n2000\n20\n30\n1406673171'}

    Returns:
        Dictionary associating a c-state with a time.
    """
    raise NotImplementedError()

  def _IsPidAlive(self, pid):
    assert pid, 'pid is required'
    return bool(self.GetPsOutput(['pid'], pid) == str(pid))

  def _GetProcFileForPid(self, pid, filename):
    try:
      return self.GetFileContents('/proc/%s/%s' % (pid, filename))
    except IOError:
      if not self._IsPidAlive(pid):
        raise exceptions.ProcessGoneException()
      raise

  def _ConvertToKb(self, value):
    return int(value.replace('kB', ''))

  def _ConvertToBytes(self, value):
    return self._ConvertToKb(value) * 1024

  def _GetProcFileDict(self, contents):
    retval = {}
    for line in contents.splitlines():
      key, value = line.split(':')
      retval[key.strip()] = value.strip()
    return retval

  def _GetProcJiffies(self):
    """Parse '/proc/timer_list' output and returns the first jiffies attribute.

    Multi-CPU machines will have multiple 'jiffies:' lines, all of which will be
    essentially the same.  Return the first one."""
    jiffies_timer_lines = self.RunCommand(
        ['grep', 'jiffies', '/proc/timer_list'])
    if not jiffies_timer_lines:
      raise Exception('Unable to find jiffies from /proc/timer_list')
    jiffies_timer_list = jiffies_timer_lines.splitlines()
    # Each line should look something like 'jiffies: 4315883489'.
    for line in jiffies_timer_list:
      match = re.match(r'\s*jiffies\s*:\s*(\d+)', line)
      if match:
        value = match.group(1)
        return float(value)
    raise Exception('Unable to parse jiffies attribute: %s' %
                    repr(jiffies_timer_lines))
