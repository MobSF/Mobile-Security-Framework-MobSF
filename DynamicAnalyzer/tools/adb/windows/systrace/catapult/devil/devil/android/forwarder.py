# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=W0212

import fcntl
import logging
import os
import psutil

from devil import base_error
from devil import devil_env
from devil.android import device_errors
from devil.android.constants import file_system
from devil.android.sdk import adb_wrapper
from devil.android.valgrind_tools import base_tool
from devil.utils import cmd_helper

logger = logging.getLogger(__name__)

# If passed as the device port, this will tell the forwarder to allocate
# a dynamic port on the device. The actual port can then be retrieved with
# Forwarder.DevicePortForHostPort.
DYNAMIC_DEVICE_PORT = 0


def _GetProcessStartTime(pid):
  return psutil.Process(pid).create_time


def _LogMapFailureDiagnostics(device):
  # The host forwarder daemon logs to /tmp/host_forwarder_log, so print the end
  # of that.
  try:
    with open('/tmp/host_forwarder_log') as host_forwarder_log:
      logger.info('Last 50 lines of the host forwarder daemon log:')
      for line in host_forwarder_log.read().splitlines()[-50:]:
        logger.info('    %s', line)
  except Exception: # pylint: disable=broad-except
    # Grabbing the host forwarder log is best-effort. Ignore all errors.
    logger.warning('Failed to get the contents of host_forwarder_log.')

  # The device forwarder daemon logs to the logcat, so print the end of that.
  try:
    logger.info('Last 50 lines of logcat:')
    for logcat_line in device.adb.Logcat(dump=True)[-50:]:
      logger.info('    %s', logcat_line)
  except device_errors.CommandFailedError:
    # Grabbing the device forwarder log is also best-effort. Ignore all errors.
    logger.warning('Failed to get the contents of the logcat.')

  # Log alive device forwarders.
  try:
    ps_out = device.RunShellCommand(['ps'], check_return=True)
    logger.info('Currently running device_forwarders:')
    for line in ps_out:
      if 'device_forwarder' in line:
        logger.info('    %s', line)
  except device_errors.CommandFailedError:
    logger.warning('Failed to list currently running device_forwarder '
                   'instances.')


class _FileLock(object):
  """With statement-aware implementation of a file lock.

  File locks are needed for cross-process synchronization when the
  multiprocessing Python module is used.
  """

  def __init__(self, path):
    self._fd = -1
    self._path = path

  def __enter__(self):
    self._fd = os.open(self._path, os.O_RDONLY | os.O_CREAT)
    if self._fd < 0:
      raise Exception('Could not open file %s for reading' % self._path)
    fcntl.flock(self._fd, fcntl.LOCK_EX)

  def __exit__(self, _exception_type, _exception_value, traceback):
    fcntl.flock(self._fd, fcntl.LOCK_UN)
    os.close(self._fd)


class HostForwarderError(base_error.BaseError):
  """Exception for failures involving host_forwarder."""

  def __init__(self, message):
    super(HostForwarderError, self).__init__(message)


class Forwarder(object):
  """Thread-safe class to manage port forwards from the device to the host."""

  _DEVICE_FORWARDER_FOLDER = (file_system.TEST_EXECUTABLE_DIR +
                              '/forwarder/')
  _DEVICE_FORWARDER_PATH = (file_system.TEST_EXECUTABLE_DIR +
                            '/forwarder/device_forwarder')
  _LOCK_PATH = '/tmp/chrome.forwarder.lock'
  # Defined in host_forwarder_main.cc
  _HOST_FORWARDER_LOG = '/tmp/host_forwarder_log'

  _TIMEOUT = 60  # seconds

  _instance = None

  @staticmethod
  def Map(port_pairs, device, tool=None):
    """Runs the forwarder.

    Args:
      port_pairs: A list of tuples (device_port, host_port) to forward. Note
                 that you can specify 0 as a device_port, in which case a
                 port will by dynamically assigned on the device. You can
                 get the number of the assigned port using the
                 DevicePortForHostPort method.
      device: A DeviceUtils instance.
      tool: Tool class to use to get wrapper, if necessary, for executing the
            forwarder (see valgrind_tools.py).

    Raises:
      Exception on failure to forward the port.
    """
    if not tool:
      tool = base_tool.BaseTool()
    with _FileLock(Forwarder._LOCK_PATH):
      instance = Forwarder._GetInstanceLocked(tool)
      instance._InitDeviceLocked(device, tool)

      device_serial = str(device)
      map_arg_lists = [
          ['--adb=' + adb_wrapper.AdbWrapper.GetAdbPath(),
           '--serial-id=' + device_serial,
           '--map', str(device_port), str(host_port)]
          for device_port, host_port in port_pairs]
      logger.info('Forwarding using commands: %s', map_arg_lists)

      for map_arg_list in map_arg_lists:
        try:
          map_cmd = [instance._host_forwarder_path] + map_arg_list
          (exit_code, output) = cmd_helper.GetCmdStatusAndOutputWithTimeout(
              map_cmd, Forwarder._TIMEOUT)
        except cmd_helper.TimeoutError as e:
          raise HostForwarderError(
              '`%s` timed out:\n%s' % (' '.join(map_cmd), e.output))
        except OSError as e:
          if e.errno == 2:
            raise HostForwarderError(
                'Unable to start host forwarder. '
                'Make sure you have built host_forwarder.')
          else: raise
        if exit_code != 0:
          try:
            instance._KillDeviceLocked(device, tool)
          except device_errors.CommandFailedError:
            # We don't want the failure to kill the device forwarder to
            # supersede the original failure to map.
            logging.warning(
                'Failed to kill the device forwarder after map failure: %s',
                str(e))
          _LogMapFailureDiagnostics(device)
          formatted_output = ('\n'.join(output) if isinstance(output, list)
                              else output)
          raise HostForwarderError(
              '`%s` exited with %d:\n%s' % (
                  ' '.join(map_cmd),
                  exit_code,
                  formatted_output))
        tokens = output.split(':')
        if len(tokens) != 2:
          raise HostForwarderError(
              'Unexpected host forwarder output "%s", '
              'expected "device_port:host_port"' % output)
        device_port = int(tokens[0])
        host_port = int(tokens[1])
        serial_with_port = (device_serial, device_port)
        instance._device_to_host_port_map[serial_with_port] = host_port
        instance._host_to_device_port_map[host_port] = serial_with_port
        logger.info('Forwarding device port: %d to host port: %d.',
                    device_port, host_port)

  @staticmethod
  def UnmapDevicePort(device_port, device):
    """Unmaps a previously forwarded device port.

    Args:
      device: A DeviceUtils instance.
      device_port: A previously forwarded port (through Map()).
    """
    with _FileLock(Forwarder._LOCK_PATH):
      Forwarder._UnmapDevicePortLocked(device_port, device)

  @staticmethod
  def UnmapAllDevicePorts(device):
    """Unmaps all the previously forwarded ports for the provided device.

    Args:
      device: A DeviceUtils instance.
      port_pairs: A list of tuples (device_port, host_port) to unmap.
    """
    with _FileLock(Forwarder._LOCK_PATH):
      instance = Forwarder._GetInstanceLocked(None)
      unmap_all_cmd = [
          instance._host_forwarder_path,
          '--adb=%s' % adb_wrapper.AdbWrapper.GetAdbPath(),
          '--serial-id=%s' % device.serial,
          '--unmap-all'
      ]
      try:
        exit_code, output = cmd_helper.GetCmdStatusAndOutputWithTimeout(
            unmap_all_cmd, Forwarder._TIMEOUT)
      except cmd_helper.TimeoutError as e:
        raise HostForwarderError(
            '`%s` timed out:\n%s' % (' '.join(unmap_all_cmd), e.output))
      if exit_code != 0:
        error_msg = [
            '`%s` exited with %d' % (' '.join(unmap_all_cmd), exit_code)]
        if isinstance(output, list):
          error_msg += output
        else:
          error_msg += [output]
        raise HostForwarderError('\n'.join(error_msg))

      # Clean out any entries from the device & host map.
      device_map = instance._device_to_host_port_map
      host_map = instance._host_to_device_port_map
      for device_serial_and_port, host_port in device_map.items():
        device_serial = device_serial_and_port[0]
        if device_serial == device.serial:
          del device_map[device_serial_and_port]
          del host_map[host_port]

      # Kill the device forwarder.
      tool = base_tool.BaseTool()
      instance._KillDeviceLocked(device, tool)

  @staticmethod
  def DevicePortForHostPort(host_port):
    """Returns the device port that corresponds to a given host port."""
    with _FileLock(Forwarder._LOCK_PATH):
      serial_and_port = Forwarder._GetInstanceLocked(
          None)._host_to_device_port_map.get(host_port)
      return serial_and_port[1] if serial_and_port else None

  @staticmethod
  def RemoveHostLog():
    if os.path.exists(Forwarder._HOST_FORWARDER_LOG):
      os.unlink(Forwarder._HOST_FORWARDER_LOG)

  @staticmethod
  def GetHostLog():
    if not os.path.exists(Forwarder._HOST_FORWARDER_LOG):
      return ''
    with file(Forwarder._HOST_FORWARDER_LOG, 'r') as f:
      return f.read()

  @staticmethod
  def _GetInstanceLocked(tool):
    """Returns the singleton instance.

    Note that the global lock must be acquired before calling this method.

    Args:
      tool: Tool class to use to get wrapper, if necessary, for executing the
            forwarder (see valgrind_tools.py).
    """
    if not Forwarder._instance:
      Forwarder._instance = Forwarder(tool)
    return Forwarder._instance

  def __init__(self, tool):
    """Constructs a new instance of Forwarder.

    Note that Forwarder is a singleton therefore this constructor should be
    called only once.

    Args:
      tool: Tool class to use to get wrapper, if necessary, for executing the
            forwarder (see valgrind_tools.py).
    """
    assert not Forwarder._instance
    self._tool = tool
    self._initialized_devices = set()
    self._device_to_host_port_map = dict()
    self._host_to_device_port_map = dict()
    self._host_forwarder_path = devil_env.config.FetchPath('forwarder_host')
    assert os.path.exists(self._host_forwarder_path), 'Please build forwarder2'
    self._InitHostLocked()

  @staticmethod
  def _UnmapDevicePortLocked(device_port, device):
    """Internal method used by UnmapDevicePort().

    Note that the global lock must be acquired before calling this method.
    """
    instance = Forwarder._GetInstanceLocked(None)
    serial = str(device)
    serial_with_port = (serial, device_port)
    if not serial_with_port in instance._device_to_host_port_map:
      logger.error('Trying to unmap non-forwarded port %d', device_port)
      return

    host_port = instance._device_to_host_port_map[serial_with_port]
    del instance._device_to_host_port_map[serial_with_port]
    del instance._host_to_device_port_map[host_port]

    unmap_cmd = [
        instance._host_forwarder_path,
        '--adb=%s' % adb_wrapper.AdbWrapper.GetAdbPath(),
        '--serial-id=%s' % serial,
        '--unmap', str(device_port)
    ]
    try:
      (exit_code, output) = cmd_helper.GetCmdStatusAndOutputWithTimeout(
          unmap_cmd, Forwarder._TIMEOUT)
    except cmd_helper.TimeoutError as e:
      raise HostForwarderError(
          '`%s` timed out:\n%s' % (' '.join(unmap_cmd), e.output))
    if exit_code != 0:
      logger.error(
          '`%s` exited with %d:\n%s',
          ' '.join(unmap_cmd),
          exit_code,
          '\n'.join(output) if isinstance(output, list) else output)

  @staticmethod
  def _GetPidForLock():
    """Returns the PID used for host_forwarder initialization.

    The PID of the "sharder" is used to handle multiprocessing. The "sharder"
    is the initial process that forks that is the parent process.
    """
    return os.getpgrp()

  def _InitHostLocked(self):
    """Initializes the host forwarder daemon.

    Note that the global lock must be acquired before calling this method. This
    method kills any existing host_forwarder process that could be stale.
    """
    # See if the host_forwarder daemon was already initialized by a concurrent
    # process or thread (in case multi-process sharding is not used).
    pid_for_lock = Forwarder._GetPidForLock()
    fd = os.open(Forwarder._LOCK_PATH, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, 'r+') as pid_file:
      pid_with_start_time = pid_file.readline()
      if pid_with_start_time:
        (pid, process_start_time) = pid_with_start_time.split(':')
        if pid == str(pid_for_lock):
          if process_start_time == str(_GetProcessStartTime(pid_for_lock)):
            return
      self._KillHostLocked()
      pid_file.seek(0)
      pid_file.write(
          '%s:%s' % (pid_for_lock, str(_GetProcessStartTime(pid_for_lock))))
      pid_file.truncate()

  def _InitDeviceLocked(self, device, tool):
    """Initializes the device_forwarder daemon for a specific device (once).

    Note that the global lock must be acquired before calling this method. This
    method kills any existing device_forwarder daemon on the device that could
    be stale, pushes the latest version of the daemon (to the device) and starts
    it.

    Args:
      device: A DeviceUtils instance.
      tool: Tool class to use to get wrapper, if necessary, for executing the
            forwarder (see valgrind_tools.py).
    """
    device_serial = str(device)
    if device_serial in self._initialized_devices:
      return
    try:
      self._KillDeviceLocked(device, tool)
    except device_errors.CommandFailedError:
      logger.warning('Failed to kill device forwarder. Rebooting.')
      device.Reboot()
    forwarder_device_path_on_host = devil_env.config.FetchPath(
        'forwarder_device', device=device)
    forwarder_device_path_on_device = (
        Forwarder._DEVICE_FORWARDER_FOLDER
        if os.path.isdir(forwarder_device_path_on_host)
        else Forwarder._DEVICE_FORWARDER_PATH)
    device.PushChangedFiles([(
        forwarder_device_path_on_host,
        forwarder_device_path_on_device)])

    cmd = [Forwarder._DEVICE_FORWARDER_PATH]
    wrapper = tool.GetUtilWrapper()
    if wrapper:
      cmd.insert(0, wrapper)
    device.RunShellCommand(
        cmd, env={'LD_LIBRARY_PATH': Forwarder._DEVICE_FORWARDER_FOLDER},
        check_return=True)
    self._initialized_devices.add(device_serial)

  @staticmethod
  def KillHost():
    """Kills the forwarder process running on the host."""
    with _FileLock(Forwarder._LOCK_PATH):
      Forwarder._GetInstanceLocked(None)._KillHostLocked()

  def _KillHostLocked(self):
    """Kills the forwarder process running on the host.

    Note that the global lock must be acquired before calling this method.
    """
    logger.info('Killing host_forwarder.')
    try:
      kill_cmd = [self._host_forwarder_path, '--kill-server']
      (exit_code, _o) = cmd_helper.GetCmdStatusAndOutputWithTimeout(
          kill_cmd, Forwarder._TIMEOUT)
      if exit_code != 0:
        kill_cmd = ['pkill', '-9', 'host_forwarder']
        (exit_code, output) = cmd_helper.GetCmdStatusAndOutputWithTimeout(
            kill_cmd, Forwarder._TIMEOUT)
        if exit_code != 0:
          raise HostForwarderError(
              '%s exited with %d:\n%s' % (
                  self._host_forwarder_path,
                  exit_code,
                  '\n'.join(output) if isinstance(output, list) else output))
    except cmd_helper.TimeoutError as e:
      raise HostForwarderError(
          '`%s` timed out:\n%s' % (' '.join(kill_cmd), e.output))

  @staticmethod
  def KillDevice(device, tool=None):
    """Kills the forwarder process running on the device.

    Args:
      device: Instance of DeviceUtils for talking to the device.
      tool: Wrapper tool (e.g. valgrind) that can be used to execute the device
            forwarder (see valgrind_tools.py).
    """
    with _FileLock(Forwarder._LOCK_PATH):
      Forwarder._GetInstanceLocked(None)._KillDeviceLocked(
          device, tool or base_tool.BaseTool())

  def _KillDeviceLocked(self, device, tool):
    """Kills the forwarder process running on the device.

    Note that the global lock must be acquired before calling this method.

    Args:
      device: Instance of DeviceUtils for talking to the device.
      tool: Wrapper tool (e.g. valgrind) that can be used to execute the device
            forwarder (see valgrind_tools.py).
    """
    logger.info('Killing device_forwarder.')
    self._initialized_devices.discard(device.serial)
    if not device.FileExists(Forwarder._DEVICE_FORWARDER_PATH):
      return

    cmd = [Forwarder._DEVICE_FORWARDER_PATH, '--kill-server']
    wrapper = tool.GetUtilWrapper()
    if wrapper:
      cmd.insert(0, wrapper)
    device.RunShellCommand(
        cmd, env={'LD_LIBRARY_PATH': Forwarder._DEVICE_FORWARDER_FOLDER},
        check_return=True)
