# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import re
import subprocess
from threading import Timer

from py_trace_event import trace_time
from telemetry.internal.platform import tracing_agent
from tracing.trace_data import trace_data


def _ParsePsProcessString(line):
  """Parses a process line from the output of `ps`.

  Example of `ps` command output:
  '3.4 8.0 31887 31447 com.app.Webkit'
  """
  token_list = line.strip().split()
  if len(token_list) < 5:
    raise ValueError('Line has too few tokens: %s.' % token_list)

  return {
    'pCpu': float(token_list[0]),
    'pMem': float(token_list[1]),
    'pid': int(token_list[2]),
    'ppid': int(token_list[3]),
    'name': ' '.join(token_list[4:])
  }


class ProcessCollector(object):
  def _GetProcessesAsStrings(self):
    """Returns a list of strings, each of which contains info about a
    process.
    """
    raise NotImplementedError

  # pylint: disable=unused-argument
  def _ParseProcessString(self, proc_string):
    """Parses an individual process string returned by _GetProcessesAsStrings().

    Returns:
      A dictionary containing keys of 'pid' (an integer process ID), 'ppid' (an
      integer parent process ID), 'name' (a string for the process name), 'pCpu'
      (a float for the percent CPU load incurred by the process), and 'pMem' (a
      float for the percent memory load caused by the process).
    """
    raise NotImplementedError

  def Init(self):
    """Performs any required initialization before starting tracing."""
    pass

  def GetProcesses(self):
    """Fetches the top processes returned by top command.

    Returns:
      A list of dictionaries, each containing 'pid' (an integer process ID),
      'ppid' (an integer parent process ID), 'name (a string for the process
      name), pCpu' (a float for the percent CPU load incurred by the process),
      and 'pMem' (a float for the percent memory load caused by the process).
    """
    proc_strings = self._GetProcessesAsStrings()
    return [
        self._ParseProcessString(proc_string) for proc_string in proc_strings
    ]


class WindowsProcessCollector(ProcessCollector):
  """Class for collecting information about processes on Windows.

  Example of Windows command output:
  '3644      1724   chrome#1                 8           84497'
  '3644      832    chrome#2                 4           34872'
  """
  _GET_PERF_DATA_SHELL_COMMAND = [
    'wmic',
    'path', # Retrieve a WMI object from the following path.
    'Win32_PerfFormattedData_PerfProc_Process', # Contains process perf data.
    'get',
    'CreatingProcessID,IDProcess,Name,PercentProcessorTime,WorkingSet'
  ]

  _GET_COMMANDS_SHELL_COMMAND = [
    'wmic',
    'Process',
    'get',
    'CommandLine,ProcessID',
    # Formatting the result as a CSV means that if no CommandLine is available,
    # we can at least tell by the lack of data between commas.
    '/format:csv'
  ]

  _GET_PHYSICAL_MEMORY_BYTES_SHELL_COMMAND = [
    'wmic',
    'ComputerSystem',
    'get',
    'TotalPhysicalMemory'
  ]

  def __init__(self):
    self._physicalMemoryBytes = None

  def Init(self):
    if not self._physicalMemoryBytes:
      self._physicalMemoryBytes = self._GetPhysicalMemoryBytes()

    # The command to get the per-process perf data takes significantly longer
    # the first time that it's run (~10s, compared to ~60ms for subsequent
    # runs). In order to avoid having this affect tracing, we run it once ahead
    # of time.
    self._GetProcessesAsStrings()

  def GetProcesses(self):
    processes = super(WindowsProcessCollector, self).GetProcesses()

    # On Windows, the absolute minimal name of the process is given
    # (e.g. "python" for Telemetry). In order to make this more useful, we check
    # if a more descriptive command is available for each PID and use that
    # command if it is.
    pid_to_command_dict = self._GetPidToCommandDict()
    for process in processes:
      if process['pid'] in pid_to_command_dict:
        process['name'] = pid_to_command_dict[process['pid']]

    return processes

  def _GetPhysicalMemoryBytes(self):
    """Returns the number of bytes of physical memory on the computer."""
    raw_output = subprocess.check_output(
        self._GET_PHYSICAL_MEMORY_BYTES_SHELL_COMMAND)
    # The bytes of physical memory is on the second row (after the header row).
    return int(raw_output.strip().split('\n')[1])

  def _GetProcessesAsStrings(self):
    # Skip the header and total rows and strip the trailing newline.
    return subprocess.check_output(
        self._GET_PERF_DATA_SHELL_COMMAND).strip().split('\n')[2:]

  def _ParseProcessString(self, proc_string):
    assert self._physicalMemoryBytes, 'Must call Init() before using collector'

    token_list = proc_string.strip().split()
    if len(token_list) < 5:
      raise ValueError('Line has too few tokens: %s.' % token_list)

    # Process names are given in the form:
    #
    #   windowsUpdate
    #   Windows Explorer
    #   chrome#1
    #   chrome#2
    #
    # In order to match other platforms, where multiple processes can have the
    # same name and can be easily grouped based on that name, we strip any
    # pound sign and number.
    name = ' '.join(token_list[2:-2])
    name = re.sub(r'#[0-9]+$', '', name)
    # The working set size (roughly equivalent to the resident set size on Unix)
    # is given in bytes. In order to convert this to percent of physical memory
    # occupied by the process, we divide by the amount of total physical memory
    # on the machine.
    percent_memory = float(token_list[-1]) / self._physicalMemoryBytes * 100

    return {
      'ppid': int(token_list[0]),
      'pid': int(token_list[1]),
      'name': name,
      'pCpu': float(token_list[-2]),
      'pMem': percent_memory
    }

  def _GetPidToCommandDict(self):
    """Returns a dictionary from the PID of a process to the full command used
    to launch that process. If no full command is available for a given process,
    that process is omitted from the returned dictionary.
    """
    # Skip the header row and strip the trailing newline.
    process_strings = subprocess.check_output(
        self._GET_COMMANDS_SHELL_COMMAND).strip().split('\n')[1:]
    command_by_pid = {}
    for process_string in process_strings:
      process_string = process_string.strip()
      command = self._ParseCommandString(process_string)

      # Only return additional information about the command if it's available.
      if command['command']:
        command_by_pid[command['pid']] = command['command']

    return command_by_pid

  def _ParseCommandString(self, command_string):
    groups = re.match(r'^([^,]+),(.*),([0-9]+)$', command_string).groups()
    return {
      # Ignore groups[0]: it's the hostname.
      'pid': int(groups[2]),
      'command': groups[1]
    }


class LinuxProcessCollector(ProcessCollector):
  """Class for collecting information about processes on Linux.

  Example of Linux command output:
  '3.4 8.0 31887 31447 com.app.Webkit'
  """
  _SHELL_COMMAND = [
    'ps',
    '-a', # Include processes that aren't session leaders.
    '-x', # List all processes, even those not owned by the user.
    '-o', # Show the output in the specified format.
    'pcpu,pmem,pid,ppid,cmd'
  ]

  def _GetProcessesAsStrings(self):
    # Skip the header row and strip the trailing newline.
    return subprocess.check_output(self._SHELL_COMMAND).strip().split('\n')[1:]

  def _ParseProcessString(self, proc_string):
    return _ParsePsProcessString(proc_string)


class MacProcessCollector(ProcessCollector):
  """Class for collecting information about processes on Mac.

  Example of Mac command output:
  '3.4 8.0 31887 31447 com.app.Webkit'
  """

  _SHELL_COMMAND = [
    'ps',
    '-a', # Include all users' processes.
    '-ww', # Don't limit the length of each line.
    '-x', # Include processes that aren't associated with a terminal.
    '-o', # Show the output in the specified format.
    '%cpu %mem pid ppid command' # Put the command last to avoid truncation.
  ]

  def _GetProcessesAsStrings(self):
    # Skip the header row and strip the trailing newline.
    return subprocess.check_output(self._SHELL_COMMAND).strip().split('\n')[1:]

  def _ParseProcessString(self, proc_string):
    return _ParsePsProcessString(proc_string)


class CpuTracingAgent(tracing_agent.TracingAgent):
  _SNAPSHOT_INTERVAL_BY_OS = {
    # Sampling via wmic on Windows is about twice as expensive as sampling via
    # ps on Linux and Mac, so we halve the sampling frequency.
    'win': 2.0,
    'mac': 1.0,
    'linux': 1.0
  }

  def __init__(self, platform_backend):
    super(CpuTracingAgent, self).__init__(platform_backend)
    self._snapshot_ongoing = False
    self._snapshots = []
    self._os_name = platform_backend.GetOSName()
    if  self._os_name == 'win':
      self._collector = WindowsProcessCollector()
    elif self._os_name == 'mac':
      self._collector = MacProcessCollector()
    else:
      self._collector = LinuxProcessCollector()

  @classmethod
  def IsSupported(cls, platform_backend):
    os_name = platform_backend.GetOSName()
    return (os_name in ['mac', 'linux', 'win'])

  def StartAgentTracing(self, config, timeout):
    assert not self._snapshot_ongoing, (
           'Agent is already taking snapshots when tracing is started.')
    if not config.enable_cpu_trace:
      return False

    self._collector.Init()
    self._snapshot_ongoing = True
    self._KeepTakingSnapshots()
    return True

  def _KeepTakingSnapshots(self):
    """Take CPU snapshots every SNAPSHOT_FREQUENCY seconds."""
    if not self._snapshot_ongoing:
      return
    # Assume CpuTracingAgent shares the same clock domain as telemetry
    self._snapshots.append(
        (self._collector.GetProcesses(), trace_time.Now()))
    interval = self._SNAPSHOT_INTERVAL_BY_OS[self._os_name]
    Timer(interval, self._KeepTakingSnapshots).start()

  def StopAgentTracing(self):
    assert self._snapshot_ongoing, (
           'Agent is not taking snapshots when tracing is stopped.')
    self._snapshot_ongoing = False

  def CollectAgentTraceData(self, trace_data_builder, timeout=None):
    assert not self._snapshot_ongoing, (
           'Agent is still taking snapshots when data is collected.')
    self._snapshot_ongoing = False
    data = json.dumps(self._FormatSnapshotsData())
    trace_data_builder.AddTraceFor(trace_data.CPU_TRACE_DATA, data)

  def _FormatSnapshotsData(self):
    """Format raw data into Object Event specified in Trace Format document."""
    pid = os.getpid()
    return [{
      'name': 'CPUSnapshots',
      'ph': 'O',
      'id': '0x1000',
      'local': True,
      'ts': timestamp,
      'pid': pid,
      'tid':None,
      'args': {
        'snapshot':{
          'processes': snapshot
        }
      }
    } for snapshot, timestamp in self._snapshots]
