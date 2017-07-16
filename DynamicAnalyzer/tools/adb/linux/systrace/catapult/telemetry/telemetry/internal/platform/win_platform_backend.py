# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.util import atexit_with_log
import collections
import contextlib
import ctypes
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import zipfile

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry.core import exceptions
from telemetry.core import os_version as os_version_module
from telemetry import decorators
from telemetry.internal.platform import desktop_platform_backend
from telemetry.internal.platform.power_monitor import msr_power_monitor
from telemetry.internal.util import path

try:
  import pywintypes  # pylint: disable=import-error
  import win32api  # pylint: disable=import-error
  from win32com.shell import shell  # pylint: disable=no-name-in-module
  from win32com.shell import shellcon  # pylint: disable=no-name-in-module
  import win32con  # pylint: disable=import-error
  import win32file  # pylint: disable=import-error
  import win32gui  # pylint: disable=import-error
  import win32pipe  # pylint: disable=import-error
  import win32process  # pylint: disable=import-error
  try:
    import winreg  # pylint: disable=import-error
  except ImportError:
    import _winreg as winreg  # pylint: disable=import-error
  import win32security  # pylint: disable=import-error
except ImportError:
  pywintypes = None
  shell = None
  shellcon = None
  win32api = None
  win32con = None
  win32file = None
  win32gui = None
  win32pipe = None
  win32process = None
  win32security = None
  winreg = None


def _InstallWinRing0():
  """WinRing0 is used for reading MSRs."""
  executable_dir = os.path.dirname(sys.executable)

  python_is_64_bit = sys.maxsize > 2 ** 32
  dll_file_name = 'WinRing0x64.dll' if python_is_64_bit else 'WinRing0.dll'
  dll_path = os.path.join(executable_dir, dll_file_name)

  os_is_64_bit = platform.machine().endswith('64')
  driver_file_name = 'WinRing0x64.sys' if os_is_64_bit else 'WinRing0.sys'
  driver_path = os.path.join(executable_dir, driver_file_name)

  # Check for WinRing0 and download if needed.
  if not (os.path.exists(dll_path) and os.path.exists(driver_path)):
    win_binary_dir = os.path.join(
        path.GetTelemetryDir(), 'bin', 'win', 'AMD64')
    zip_path = os.path.join(win_binary_dir, 'winring0.zip')
    cloud_storage.GetIfChanged(zip_path, bucket=cloud_storage.PUBLIC_BUCKET)
    try:
      with zipfile.ZipFile(zip_path, 'r') as zip_file:
        error_message = (
            'Failed to extract %s into %s. If python claims that '
            'the zip file is locked, this may be a lie. The problem may be '
            'that python does not have write permissions to the destination '
            'directory.'
        )
        # Install DLL.
        if not os.path.exists(dll_path):
          try:
            zip_file.extract(dll_file_name, executable_dir)
          except:
            logging.error(error_message % (dll_file_name, executable_dir))
            raise

        # Install kernel driver.
        if not os.path.exists(driver_path):
          try:
            zip_file.extract(driver_file_name, executable_dir)
          except:
            logging.error(error_message % (driver_file_name, executable_dir))
            raise
    finally:
      os.remove(zip_path)


def TerminateProcess(process_handle):
  if not process_handle:
    return
  if win32process.GetExitCodeProcess(process_handle) == win32con.STILL_ACTIVE:
    win32process.TerminateProcess(process_handle, 0)
  process_handle.close()


class WinPlatformBackend(desktop_platform_backend.DesktopPlatformBackend):
  def __init__(self):
    super(WinPlatformBackend, self).__init__()
    self._msr_server_handle = None
    self._msr_server_port = None
    self._power_monitor = msr_power_monitor.MsrPowerMonitorWin(self)

  @classmethod
  def IsPlatformBackendForHost(cls):
    return sys.platform == 'win32'

  def __del__(self):
    self.close()

  def close(self):
    self.CloseMsrServer()

  def CloseMsrServer(self):
    if not self._msr_server_handle:
      return

    TerminateProcess(self._msr_server_handle)
    self._msr_server_handle = None
    self._msr_server_port = None

  def IsThermallyThrottled(self):
    raise NotImplementedError()

  def HasBeenThermallyThrottled(self):
    raise NotImplementedError()

  def GetSystemCommitCharge(self):
    performance_info = self._GetPerformanceInfo()
    return performance_info.CommitTotal * performance_info.PageSize / 1024

  @decorators.Cache
  def GetSystemTotalPhysicalMemory(self):
    performance_info = self._GetPerformanceInfo()
    return performance_info.PhysicalTotal * performance_info.PageSize / 1024

  def GetCpuStats(self, pid):
    cpu_info = self._GetWin32ProcessInfo(win32process.GetProcessTimes, pid)
    # Convert 100 nanosecond units to seconds
    cpu_time = (cpu_info['UserTime'] / 1e7 +
                cpu_info['KernelTime'] / 1e7)
    return {'CpuProcessTime': cpu_time}

  def GetCpuTimestamp(self):
    """Return current timestamp in seconds."""
    return {'TotalTime': time.time()}

  @decorators.Deprecated(
      2017, 11, 4,
      'Clients should use tracing and memory-infra in new Telemetry '
      'benchmarks. See for context: https://crbug.com/632021')
  def GetMemoryStats(self, pid):
    memory_info = self._GetWin32ProcessInfo(
        win32process.GetProcessMemoryInfo, pid)
    return {'VM': memory_info['PagefileUsage'],
            'VMPeak': memory_info['PeakPagefileUsage'],
            'WorkingSetSize': memory_info['WorkingSetSize'],
            'WorkingSetSizePeak': memory_info['PeakWorkingSetSize']}

  def KillProcess(self, pid, kill_process_tree=False):
    # os.kill for Windows is Python 2.7.
    cmd = ['taskkill', '/F', '/PID', str(pid)]
    if kill_process_tree:
      cmd.append('/T')
    subprocess.Popen(cmd, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT).communicate()

  def GetSystemProcessInfo(self):
    # [3:] To skip 2 blank lines and header.
    lines = subprocess.Popen(
        ['wmic', 'process', 'get',
         'CommandLine,CreationDate,Name,ParentProcessId,ProcessId',
         '/format:csv'],
        stdout=subprocess.PIPE).communicate()[0].splitlines()[3:]
    process_info = []
    for line in lines:
      if not line:
        continue
      parts = line.split(',')
      pi = {}
      pi['ProcessId'] = int(parts[-1])
      pi['ParentProcessId'] = int(parts[-2])
      pi['Name'] = parts[-3]
      creation_date = None
      if parts[-4]:
        creation_date = float(re.split('[+-]', parts[-4])[0])
      pi['CreationDate'] = creation_date
      pi['CommandLine'] = ','.join(parts[1:-4])
      process_info.append(pi)
    return process_info

  def GetChildPids(self, pid):
    """Retunds a list of child pids of |pid|."""
    ppid_map = collections.defaultdict(list)
    creation_map = {}
    for pi in self.GetSystemProcessInfo():
      ppid_map[pi['ParentProcessId']].append(pi['ProcessId'])
      if pi['CreationDate']:
        creation_map[pi['ProcessId']] = pi['CreationDate']

    def _InnerGetChildPids(pid):
      if not pid or pid not in ppid_map:
        return []
      ret = [p for p in ppid_map[pid] if creation_map[p] >= creation_map[pid]]
      for child in ret:
        if child == pid:
          continue
        ret.extend(_InnerGetChildPids(child))
      return ret

    return _InnerGetChildPids(pid)

  def GetCommandLine(self, pid):
    for pi in self.GetSystemProcessInfo():
      if pid == pi['ProcessId']:
        return pi['CommandLine']
    raise exceptions.ProcessGoneException()

  @decorators.Cache
  def GetArchName(self):
    return platform.machine()

  def GetOSName(self):
    return 'win'

  @decorators.Cache
  def GetOSVersionName(self):
    os_version = platform.uname()[3]

    if os_version.startswith('5.1.'):
      return os_version_module.XP
    if os_version.startswith('6.0.'):
      return os_version_module.VISTA
    if os_version.startswith('6.1.'):
      return os_version_module.WIN7
    # The version of python.exe we commonly use (2.7) is only manifested as
    # being compatible with Windows versions up to 8. Therefore Windows *lies*
    # to python about the version number to keep it runnable on Windows 10.
    key_name = r'Software\Microsoft\Windows NT\CurrentVersion'
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_name)
    try:
      value, _ = winreg.QueryValueEx(key, 'CurrentMajorVersionNumber')
    except OSError:
      value = None
    finally:
      key.Close()
    if value == 10:
      return os_version_module.WIN10
    elif os_version.startswith('6.2.'):
      return os_version_module.WIN8
    elif os_version.startswith('6.3.'):
      return os_version_module.WIN81
    raise NotImplementedError(
        'Unknown win version: %s, CurrentMajorVersionNumber: %s' %
        (os_version, value))

  def CanFlushIndividualFilesFromSystemCache(self):
    return True

  def _GetWin32ProcessInfo(self, func, pid):
    mask = (win32con.PROCESS_QUERY_INFORMATION |
            win32con.PROCESS_VM_READ)
    handle = None
    try:
      handle = win32api.OpenProcess(mask, False, pid)
      return func(handle)
    except pywintypes.error, e:
      errcode = e[0]
      if errcode == 87:
        raise exceptions.ProcessGoneException()
      raise
    finally:
      if handle:
        win32api.CloseHandle(handle)

  def _GetPerformanceInfo(self):
    class PerformanceInfo(ctypes.Structure):
      """Struct for GetPerformanceInfo() call
      http://msdn.microsoft.com/en-us/library/ms683210
      """
      _fields_ = [('size', ctypes.c_ulong),
                  ('CommitTotal', ctypes.c_size_t),
                  ('CommitLimit', ctypes.c_size_t),
                  ('CommitPeak', ctypes.c_size_t),
                  ('PhysicalTotal', ctypes.c_size_t),
                  ('PhysicalAvailable', ctypes.c_size_t),
                  ('SystemCache', ctypes.c_size_t),
                  ('KernelTotal', ctypes.c_size_t),
                  ('KernelPaged', ctypes.c_size_t),
                  ('KernelNonpaged', ctypes.c_size_t),
                  ('PageSize', ctypes.c_size_t),
                  ('HandleCount', ctypes.c_ulong),
                  ('ProcessCount', ctypes.c_ulong),
                  ('ThreadCount', ctypes.c_ulong)]

      def __init__(self):
        self.size = ctypes.sizeof(self)
        # pylint: disable=bad-super-call
        super(PerformanceInfo, self).__init__()

    performance_info = PerformanceInfo()
    ctypes.windll.psapi.GetPerformanceInfo(
        ctypes.byref(performance_info), performance_info.size)
    return performance_info

  def IsCurrentProcessElevated(self):
    if self.GetOSVersionName() < os_version_module.VISTA:
      # TOKEN_QUERY is not defined before Vista. All processes are elevated.
      return True

    handle = win32process.GetCurrentProcess()
    with contextlib.closing(
        win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)) as token:
      return bool(win32security.GetTokenInformation(
          token, win32security.TokenElevation))

  def LaunchApplication(
      self, application, parameters=None, elevate_privilege=False):
    """Launch an application. Returns a PyHANDLE object."""

    parameters = ' '.join(parameters) if parameters else ''
    if elevate_privilege and not self.IsCurrentProcessElevated():
      # Use ShellExecuteEx() instead of subprocess.Popen()/CreateProcess() to
      # elevate privileges. A new console will be created if the new process has
      # different permissions than this process.
      proc_info = shell.ShellExecuteEx(
          fMask=shellcon.SEE_MASK_NOCLOSEPROCESS | shellcon.SEE_MASK_NO_CONSOLE,
          lpVerb='runas' if elevate_privilege else '',
          lpFile=application,
          lpParameters=parameters,
          nShow=win32con.SW_HIDE)
      if proc_info['hInstApp'] <= 32:
        raise Exception('Unable to launch %s' % application)
      return proc_info['hProcess']
    else:
      handle, _, _, _ = win32process.CreateProcess(
          None, application + ' ' + parameters, None, None, False,
          win32process.CREATE_NO_WINDOW, None, None, win32process.STARTUPINFO())
      return handle

  def CanMonitorPower(self):
    return self._power_monitor.CanMonitorPower()

  def CanMeasurePerApplicationPower(self):
    return self._power_monitor.CanMeasurePerApplicationPower()

  def StartMonitoringPower(self, browser):
    self._power_monitor.StartMonitoringPower(browser)

  def StopMonitoringPower(self):
    return self._power_monitor.StopMonitoringPower()

  def _StartMsrServerIfNeeded(self):
    if self._msr_server_handle:
      return

    _InstallWinRing0()

    pipe_name = r"\\.\pipe\msr_server_pipe_{}".format(os.getpid())
    # Try to open a named pipe to receive a msr port number from server process.
    pipe = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_INBOUND,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 32, 32, 300, None)
    parameters = (
        os.path.join(os.path.dirname(__file__), 'msr_server_win.py'),
        pipe_name,
    )
    self._msr_server_handle = self.LaunchApplication(
        sys.executable, parameters, elevate_privilege=True)
    if pipe != win32file.INVALID_HANDLE_VALUE:
      if win32pipe.ConnectNamedPipe(pipe, None) == 0:
        self._msr_server_port = int(win32file.ReadFile(pipe, 32)[1])
      win32api.CloseHandle(pipe)
    # Wait for server to start.
    try:
      socket.create_connection(('127.0.0.1', self._msr_server_port), 5).close()
    except socket.error:
      self.CloseMsrServer()
    atexit_with_log.Register(TerminateProcess, self._msr_server_handle)

  def ReadMsr(self, msr_number, start=0, length=64):
    self._StartMsrServerIfNeeded()
    if not self._msr_server_handle:
      raise OSError('Unable to start MSR server.')

    sock = socket.create_connection(('127.0.0.1', self._msr_server_port), 5)
    try:
      sock.sendall(struct.pack('I', msr_number))
      response = sock.recv(8)
    finally:
      sock.close()
    return struct.unpack('Q', response)[0] >> start & ((1 << length) - 1)

  def IsCooperativeShutdownSupported(self):
    return True

  def CooperativelyShutdown(self, proc, app_name):
    pid = proc.pid

    # http://timgolden.me.uk/python/win32_how_do_i/
    #   find-the-window-for-my-subprocess.html
    #
    # It seems that intermittently this code manages to find windows
    # that don't belong to Chrome -- for example, the cmd.exe window
    # running slave.bat on the tryservers. Try to be careful about
    # finding only Chrome's windows. This works for both the browser
    # and content_shell.
    #
    # It seems safest to send the WM_CLOSE messages after discovering
    # all of the sub-process's windows.
    def find_chrome_windows(hwnd, hwnds):
      _, win_pid = win32process.GetWindowThreadProcessId(hwnd)
      if (pid == win_pid and
          win32gui.IsWindowVisible(hwnd) and
          win32gui.IsWindowEnabled(hwnd) and
          win32gui.GetClassName(hwnd).lower().startswith(app_name)):
        hwnds.append(hwnd)
      return True
    hwnds = []
    win32gui.EnumWindows(find_chrome_windows, hwnds)
    if hwnds:
      for hwnd in hwnds:
        win32gui.SendMessage(hwnd, win32con.WM_CLOSE, 0, 0)
      return True
    else:
      logging.info('Did not find any windows owned by target process')
    return False
