# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module wraps Android's adb tool.

This is a thin wrapper around the adb interface. Any additional complexity
should be delegated to a higher level (ex. DeviceUtils).
"""

import collections
import distutils.version
import errno
import logging
import os
import posixpath
import re
import subprocess

from devil import devil_env
from devil.android import decorators
from devil.android import device_errors
from devil.utils import cmd_helper
from devil.utils import lazy
from devil.utils import timeout_retry

with devil_env.SysPath(devil_env.DEPENDENCY_MANAGER_PATH):
  import dependency_manager  # pylint: disable=import-error

logger = logging.getLogger(__name__)


ADB_KEYS_FILE = '/data/misc/adb/adb_keys'

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 2

_ADB_VERSION_RE = re.compile(r'Android Debug Bridge version (\d+\.\d+\.\d+)')
_EMULATOR_RE = re.compile(r'^emulator-[0-9]+$')
_READY_STATE = 'device'
_VERITY_DISABLE_RE = re.compile(r'Verity (already )?disabled')
_VERITY_ENABLE_RE = re.compile(r'Verity (already )?enabled')


def VerifyLocalFileExists(path):
  """Verifies a local file exists.

  Args:
    path: Path to the local file.

  Raises:
    IOError: If the file doesn't exist.
  """
  if not os.path.exists(path):
    raise IOError(errno.ENOENT, os.strerror(errno.ENOENT), path)


def _FindAdb():
  try:
    return devil_env.config.LocalPath('adb')
  except dependency_manager.NoPathFoundError:
    pass

  try:
    return os.path.join(devil_env.config.LocalPath('android_sdk'),
                        'platform-tools', 'adb')
  except dependency_manager.NoPathFoundError:
    pass

  try:
    return devil_env.config.FetchPath('adb')
  except dependency_manager.NoPathFoundError:
    raise device_errors.NoAdbError()


def _GetVersion():
  # pylint: disable=protected-access
  raw_version = AdbWrapper._RunAdbCmd(['version'], timeout=2, retries=0)
  for l in raw_version.splitlines():
    m = _ADB_VERSION_RE.search(l)
    if m:
      return m.group(1)
  return None


def _ShouldRetryAdbCmd(exc):
  return not isinstance(exc, device_errors.NoAdbError)


DeviceStat = collections.namedtuple('DeviceStat',
                                    ['st_mode', 'st_size', 'st_time'])


def _IsExtraneousLine(line, send_cmd):
  """Determine if a line read from stdout in persistent shell is extraneous.

  The results output to stdout by the persistent shell process
  (in PersistentShell below) often include "extraneous" lines that are
  not part of the output of the shell command. These "extraneous" lines
  do not always appear and are of two forms: shell prompt lines and lines
  that just duplicate what the input command was. This function
  detects these extraneous lines. Since all these lines have the
  original command in them, that is what it detects ror.

  Args:
      line: Output line to check.
      send_cmd: Command that was sent to adb persistent shell.
  """
  return send_cmd.rstrip() in line


class AdbWrapper(object):
  """A wrapper around a local Android Debug Bridge executable."""

  _adb_path = lazy.WeakConstant(_FindAdb)
  _adb_version = lazy.WeakConstant(_GetVersion)

  def __init__(self, device_serial):
    """Initializes the AdbWrapper.

    Args:
      device_serial: The device serial number as a string.
    """
    if not device_serial:
      raise ValueError('A device serial must be specified')
    self._device_serial = str(device_serial)

  class PersistentShell(object):
    '''Class to use persistent shell for ADB.

    This class allows a persistent ADB shell to be created, where multiple
    commands can be passed into it. This avoids the overhead of starting
    up a new ADB shell for each command.

    Example of use:
    with PersistentShell('123456789') as pshell:
        pshell.RunCommand('which ls')
        pshell.RunCommandAndClose('echo TEST')
    '''
    def __init__(self, serial):
      """Initialization function:

      Args:
        serial: Serial number of device.
      """
      self._cmd = [AdbWrapper.GetAdbPath(), '-s', serial, 'shell']
      self._process = None

    def __enter__(self):
      self.Start()
      self.WaitForReady()
      return self

    def __exit__(self, exc_type, exc_value, tb):
      self.Stop()

    def Start(self):
      """Start the shell."""
      if self._process is not None:
        raise RuntimeError('Persistent shell already running.')
      self._process = subprocess.Popen(self._cmd,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       shell=False)

    def WaitForReady(self):
      """Wait for the shell to be ready after starting.

      Sends an echo command, then waits until it gets a response.
      """
      self._process.stdin.write('echo\n')
      output_line = self._process.stdout.readline()
      while output_line.rstrip() != '':
        output_line = self._process.stdout.readline()

    def RunCommand(self, command, close=False):
      """Runs an ADB command and returns the output.

      Note that there can be approximately 40 ms of additional latency
      between sending the command and receiving the results if close=False
      due to the use of Nagle's algorithm in the TCP socket between the
      adb server and client. To avoid this extra latency, set close=True.

      Args:
        command: Command to send.
      Returns:
        The command output, given as a list of lines, and the exit code
      """

      if close:
        def run_cmd(cmd):
          send_cmd = '( %s ); echo $?; exit;\n' % cmd.rstrip()
          (output, _) = self._process.communicate(send_cmd)
          self._process = None
          for x in output.splitlines():
            yield x

      else:
        def run_cmd(cmd):
          send_cmd = '( %s ); echo DONE:$?;\n' % cmd.rstrip()
          self._process.stdin.write(send_cmd)
          while True:
            output_line = self._process.stdout.readline().rstrip()
            if output_line[:5] == 'DONE:':
              yield output_line[5:]
              break
            yield output_line

      result = [line for line in run_cmd(command)
                if not _IsExtraneousLine(line, command)]

      return (result[:-1], int(result[-1]))

    def Stop(self):
      """Stops the ADB process if it is still running."""
      if self._process is not None:
        self._process.stdin.write('exit\n')
        self._process = None

  @classmethod
  def GetAdbPath(cls):
    return cls._adb_path.read()

  @classmethod
  def Version(cls):
    return cls._adb_version.read()

  @classmethod
  def _BuildAdbCmd(cls, args, device_serial, cpu_affinity=None):
    if cpu_affinity is not None:
      cmd = ['taskset', '-c', str(cpu_affinity)]
    else:
      cmd = []
    cmd.append(cls.GetAdbPath())
    if device_serial is not None:
      cmd.extend(['-s', device_serial])
    cmd.extend(args)
    return cmd

  # pylint: disable=unused-argument
  @classmethod
  @decorators.WithTimeoutAndConditionalRetries(_ShouldRetryAdbCmd)
  def _RunAdbCmd(cls, args, timeout=None, retries=None, device_serial=None,
                 check_error=True, cpu_affinity=None):
    # pylint: disable=no-member
    try:
      status, output = cmd_helper.GetCmdStatusAndOutputWithTimeout(
          cls._BuildAdbCmd(args, device_serial, cpu_affinity=cpu_affinity),
          timeout_retry.CurrentTimeoutThreadGroup().GetRemainingTime())
    except OSError as e:
      if e.errno in (errno.ENOENT, errno.ENOEXEC):
        raise device_errors.NoAdbError(msg=str(e))
      else:
        raise

    if status != 0:
      raise device_errors.AdbCommandFailedError(
          args, output, status, device_serial)
    # This catches some errors, including when the device drops offline;
    # unfortunately adb is very inconsistent with error reporting so many
    # command failures present differently.
    if check_error and output.startswith('error:'):
      raise device_errors.AdbCommandFailedError(args, output)
    return output
  # pylint: enable=unused-argument

  def _RunDeviceAdbCmd(self, args, timeout, retries, check_error=True):
    """Runs an adb command on the device associated with this object.

    Args:
      args: A list of arguments to adb.
      timeout: Timeout in seconds.
      retries: Number of retries.
      check_error: Check that the command doesn't return an error message. This
        does NOT check the exit status of shell commands.

    Returns:
      The output of the command.
    """
    return self._RunAdbCmd(args, timeout=timeout, retries=retries,
                           device_serial=self._device_serial,
                           check_error=check_error)

  def _IterRunDeviceAdbCmd(self, args, iter_timeout, timeout):
    """Runs an adb command and returns an iterator over its output lines.

    Args:
      args: A list of arguments to adb.
      iter_timeout: Timeout for each iteration in seconds.
      timeout: Timeout for the entire command in seconds.

    Yields:
      The output of the command line by line.
    """
    return cmd_helper.IterCmdOutputLines(
        self._BuildAdbCmd(args, self._device_serial),
        iter_timeout=iter_timeout,
        timeout=timeout)

  def __eq__(self, other):
    """Consider instances equal if they refer to the same device.

    Args:
      other: The instance to compare equality with.

    Returns:
      True if the instances are considered equal, false otherwise.
    """
    return self._device_serial == str(other)

  def __str__(self):
    """The string representation of an instance.

    Returns:
      The device serial number as a string.
    """
    return self._device_serial

  def __repr__(self):
    return '%s(\'%s\')' % (self.__class__.__name__, self)

  # pylint: disable=unused-argument
  @classmethod
  def IsServerOnline(cls):
    status, output = cmd_helper.GetCmdStatusAndOutput(['pgrep', 'adb'])
    output = [int(x) for x in output.split()]
    logger.info('PIDs for adb found: %r', output)
    return status == 0
  # pylint: enable=unused-argument

  @classmethod
  def KillServer(cls, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    cls._RunAdbCmd(['kill-server'], timeout=timeout, retries=retries)

  @classmethod
  def StartServer(cls, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    # CPU affinity is used to reduce adb instability http://crbug.com/268450
    cls._RunAdbCmd(['start-server'], timeout=timeout, retries=retries,
                   cpu_affinity=0)

  @classmethod
  def GetDevices(cls, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """DEPRECATED. Refer to Devices(...) below."""
    # TODO(jbudorick): Remove this function once no more clients are using it.
    return cls.Devices(timeout=timeout, retries=retries)

  @classmethod
  def Devices(cls, desired_state=_READY_STATE, long_list=False,
              timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Get the list of active attached devices.

    Args:
      desired_state: If not None, limit the devices returned to only those
        in the given state.
      long_list: Whether to use the long listing format.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Yields:
      AdbWrapper instances.
    """
    lines = cls._RawDevices(long_list=long_list, timeout=timeout,
                            retries=retries)
    if long_list:
      return [
        [AdbWrapper(line[0])] + line[1:]
        for line in lines
        if (len(line) >= 2 and (not desired_state or line[1] == desired_state))
      ]
    else:
      return [
        AdbWrapper(line[0])
        for line in lines
        if (len(line) == 2 and (not desired_state or line[1] == desired_state))
      ]

  @classmethod
  def _RawDevices(cls, long_list=False, timeout=DEFAULT_TIMEOUT,
                  retries=DEFAULT_RETRIES):
    cmd = ['devices']
    if long_list:
      cmd.append('-l')
    output = cls._RunAdbCmd(cmd, timeout=timeout, retries=retries)
    return [line.split() for line in output.splitlines()[1:]]

  def GetDeviceSerial(self):
    """Gets the device serial number associated with this object.

    Returns:
      Device serial number as a string.
    """
    return self._device_serial

  def Push(self, local, remote, timeout=60 * 5, retries=DEFAULT_RETRIES):
    """Pushes a file from the host to the device.

    Args:
      local: Path on the host filesystem.
      remote: Path on the device filesystem.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    VerifyLocalFileExists(local)

    if (distutils.version.LooseVersion(self.Version()) <
        distutils.version.LooseVersion('1.0.36')):

      # Different versions of adb handle pushing a directory to an existing
      # directory differently.

      # In the version packaged with the M SDK, 1.0.32, the following push:
      #   foo/bar -> /sdcard/foo/bar
      # where bar is an existing directory both on the host and the device
      # results in the contents of bar/ on the host being pushed to bar/ on
      # the device, i.e.
      #   foo/bar/A -> /sdcard/foo/bar/A
      #   foo/bar/B -> /sdcard/foo/bar/B
      #   ... etc.

      # In the version packaged with the N SDK, 1.0.36, the same push under
      # the same conditions results in a second bar/ directory being created
      # underneath the first bar/ directory on the device, i.e.
      #   foo/bar/A -> /sdcard/foo/bar/bar/A
      #   foo/bar/B -> /sdcard/foo/bar/bar/B
      #   ... etc.

      # In order to provide a consistent interface to clients, we check whether
      # the target is an existing directory on the device and, if so, modifies
      # the target passed to adb to emulate the behavior on 1.0.36 and above.

      # Note that this behavior may have started before 1.0.36; that's simply
      # the earliest version we've confirmed thus far.

      try:
        self.Shell('test -d %s' % remote, timeout=timeout, retries=retries)
        remote = posixpath.join(remote, posixpath.basename(local))
      except device_errors.AdbShellCommandFailedError:
        # The target directory doesn't exist on the device, so we can use it
        # without modification.
        pass

    self._RunDeviceAdbCmd(['push', local, remote], timeout, retries)

  def Pull(self, remote, local, timeout=60 * 5, retries=DEFAULT_RETRIES):
    """Pulls a file from the device to the host.

    Args:
      remote: Path on the device filesystem.
      local: Path on the host filesystem.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    cmd = ['pull', remote, local]
    self._RunDeviceAdbCmd(cmd, timeout, retries)
    try:
      VerifyLocalFileExists(local)
    except IOError:
      raise device_errors.AdbCommandFailedError(
          cmd,
          'File pulled from the device did not arrive on the host: %s' % local,
          device_serial=str(self))

  def Shell(self, command, expect_status=0, timeout=DEFAULT_TIMEOUT,
            retries=DEFAULT_RETRIES):
    """Runs a shell command on the device.

    Args:
      command: A string with the shell command to run.
      expect_status: (optional) Check that the command's exit status matches
        this value. Default is 0. If set to None the test is skipped.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      The output of the shell command as a string.

    Raises:
      device_errors.AdbCommandFailedError: If the exit status doesn't match
        |expect_status|.
    """
    if expect_status is None:
      args = ['shell', command]
    else:
      args = ['shell', '( %s );echo %%$?' % command.rstrip()]
    output = self._RunDeviceAdbCmd(args, timeout, retries, check_error=False)
    if expect_status is not None:
      output_end = output.rfind('%')
      if output_end < 0:
        # causes the status string to become empty and raise a ValueError
        output_end = len(output)

      try:
        status = int(output[output_end + 1:])
      except ValueError:
        logger.warning('exit status of shell command %r missing.', command)
        raise device_errors.AdbShellCommandFailedError(
            command, output, status=None, device_serial=self._device_serial)
      output = output[:output_end]
      if status != expect_status:
        raise device_errors.AdbShellCommandFailedError(
            command, output, status=status, device_serial=self._device_serial)
    return output

  def IterShell(self, command, timeout):
    """Runs a shell command and returns an iterator over its output lines.

    Args:
      command: A string with the shell command to run.
      timeout: Timeout in seconds.

    Yields:
      The output of the command line by line.
    """
    args = ['shell', command]
    return cmd_helper.IterCmdOutputLines(
      self._BuildAdbCmd(args, self._device_serial), timeout=timeout)

  def Ls(self, path, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """List the contents of a directory on the device.

    Args:
      path: Path on the device filesystem.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      A list of pairs (filename, stat) for each file found in the directory,
      where the stat object has the properties: st_mode, st_size, and st_time.

    Raises:
      AdbCommandFailedError if |path| does not specify a valid and accessible
          directory in the device, or the output of "adb ls" command is less
          than four columns
    """
    def ParseLine(line, cmd):
      cols = line.split(None, 3)
      if len(cols) < 4:
        raise device_errors.AdbCommandFailedError(
            cmd, line, "the output should be 4 columns, but is only %d columns"
            % len(cols), device_serial=self._device_serial)
      filename = cols.pop()
      stat = DeviceStat(*[int(num, base=16) for num in cols])
      return (filename, stat)

    cmd = ['ls', path]
    lines = self._RunDeviceAdbCmd(
        cmd, timeout=timeout, retries=retries).splitlines()
    if lines:
      return [ParseLine(line, cmd) for line in lines]
    else:
      raise device_errors.AdbCommandFailedError(
          cmd, 'path does not specify an accessible directory in the device',
          device_serial=self._device_serial)

  def Logcat(self, clear=False, dump=False, filter_specs=None,
             logcat_format=None, ring_buffer=None, iter_timeout=None,
             timeout=None, retries=DEFAULT_RETRIES):
    """Get an iterable over the logcat output.

    Args:
      clear: If true, clear the logcat.
      dump: If true, dump the current logcat contents.
      filter_specs: If set, a list of specs to filter the logcat.
      logcat_format: If set, the format in which the logcat should be output.
        Options include "brief", "process", "tag", "thread", "raw", "time",
        "threadtime", and "long"
      ring_buffer: If set, a list of alternate ring buffers to request.
        Options include "main", "system", "radio", "events", "crash" or "all".
        The default is equivalent to ["main", "system", "crash"].
      iter_timeout: If set and neither clear nor dump is set, the number of
        seconds to wait between iterations. If no line is found before the
        given number of seconds elapses, the iterable will yield None.
      timeout: (optional) If set, timeout per try in seconds. If clear or dump
        is set, defaults to DEFAULT_TIMEOUT.
      retries: (optional) If clear or dump is set, the number of retries to
        attempt. Otherwise, does nothing.

    Yields:
      logcat output line by line.
    """
    cmd = ['logcat']
    use_iter = True
    if clear:
      cmd.append('-c')
      use_iter = False
    if dump:
      cmd.append('-d')
      use_iter = False
    if logcat_format:
      cmd.extend(['-v', logcat_format])
    if ring_buffer:
      for buffer_name in ring_buffer:
        cmd.extend(['-b', buffer_name])
    if filter_specs:
      cmd.extend(filter_specs)

    if use_iter:
      return self._IterRunDeviceAdbCmd(cmd, iter_timeout, timeout)
    else:
      timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
      return self._RunDeviceAdbCmd(cmd, timeout, retries).splitlines()

  def Forward(self, local, remote, allow_rebind=False,
              timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Forward socket connections from the local socket to the remote socket.

    Sockets are specified by one of:
      tcp:<port>
      localabstract:<unix domain socket name>
      localreserved:<unix domain socket name>
      localfilesystem:<unix domain socket name>
      dev:<character device name>
      jdwp:<process pid> (remote only)

    Args:
      local: The host socket.
      remote: The device socket.
      allow_rebind: A boolean indicating whether adb may rebind a local socket;
        otherwise, the default, an exception is raised if the local socket is
        already being forwarded.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    cmd = ['forward']
    if not allow_rebind:
      cmd.append('--no-rebind')
    cmd.extend([str(local), str(remote)])
    self._RunDeviceAdbCmd(cmd, timeout, retries)

  def ForwardRemove(self, local, timeout=DEFAULT_TIMEOUT,
                    retries=DEFAULT_RETRIES):
    """Remove a forward socket connection.

    Args:
      local: The host socket.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    self._RunDeviceAdbCmd(['forward', '--remove', str(local)], timeout,
                          retries)

  def ForwardList(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """List all currently forwarded socket connections.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    Returns:
      The output of adb forward --list as a string.
    """
    if (distutils.version.LooseVersion(self.Version()) >=
        distutils.version.LooseVersion('1.0.36')):
      # Starting in 1.0.36, this can occasionally fail with a protocol fault.
      # As this interrupts all connections with all devices, we instead just
      # return an empty list. This may give clients an inaccurate result, but
      # that's usually better than crashing the adb server.

      # TODO(jbudorick): Determine an appropriate upper version bound for this
      # once b/31811775 is fixed.
      return ''

    return self._RunDeviceAdbCmd(['forward', '--list'], timeout, retries)

  def JDWP(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """List of PIDs of processes hosting a JDWP transport.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      A list of PIDs as strings.
    """
    return [a.strip() for a in
            self._RunDeviceAdbCmd(['jdwp'], timeout, retries).split('\n')]

  def Install(self, apk_path, forward_lock=False, allow_downgrade=False,
              reinstall=False, sd_card=False, timeout=60 * 2,
              retries=DEFAULT_RETRIES):
    """Install an apk on the device.

    Args:
      apk_path: Host path to the APK file.
      forward_lock: (optional) If set forward-locks the app.
      allow_downgrade: (optional) If set, allows for downgrades.
      reinstall: (optional) If set reinstalls the app, keeping its data.
      sd_card: (optional) If set installs on the SD card.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    VerifyLocalFileExists(apk_path)
    cmd = ['install']
    if forward_lock:
      cmd.append('-l')
    if reinstall:
      cmd.append('-r')
    if sd_card:
      cmd.append('-s')
    if allow_downgrade:
      cmd.append('-d')
    cmd.append(apk_path)
    output = self._RunDeviceAdbCmd(cmd, timeout, retries)
    if 'Success' not in output:
      raise device_errors.AdbCommandFailedError(
          cmd, output, device_serial=self._device_serial)

  def InstallMultiple(self, apk_paths, forward_lock=False, reinstall=False,
                      sd_card=False, allow_downgrade=False, partial=False,
                      timeout=60 * 2, retries=DEFAULT_RETRIES):
    """Install an apk with splits on the device.

    Args:
      apk_paths: Host path to the APK file.
      forward_lock: (optional) If set forward-locks the app.
      reinstall: (optional) If set reinstalls the app, keeping its data.
      sd_card: (optional) If set installs on the SD card.
      allow_downgrade: (optional) Allow versionCode downgrade.
      partial: (optional) Package ID if apk_paths doesn't include all .apks.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    for path in apk_paths:
      VerifyLocalFileExists(path)
    cmd = ['install-multiple']
    if forward_lock:
      cmd.append('-l')
    if reinstall:
      cmd.append('-r')
    if sd_card:
      cmd.append('-s')
    if allow_downgrade:
      cmd.append('-d')
    if partial:
      cmd.extend(('-p', partial))
    cmd.extend(apk_paths)
    output = self._RunDeviceAdbCmd(cmd, timeout, retries)
    if 'Success' not in output:
      raise device_errors.AdbCommandFailedError(
          cmd, output, device_serial=self._device_serial)

  def Uninstall(self, package, keep_data=False, timeout=DEFAULT_TIMEOUT,
                retries=DEFAULT_RETRIES):
    """Remove the app |package| from the device.

    Args:
      package: The package to uninstall.
      keep_data: (optional) If set keep the data and cache directories.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    cmd = ['uninstall']
    if keep_data:
      cmd.append('-k')
    cmd.append(package)
    output = self._RunDeviceAdbCmd(cmd, timeout, retries)
    if 'Failure' in output or 'Exception' in output:
      raise device_errors.AdbCommandFailedError(
          cmd, output, device_serial=self._device_serial)

  def Backup(self, path, packages=None, apk=False, shared=False,
             nosystem=True, include_all=False, timeout=DEFAULT_TIMEOUT,
             retries=DEFAULT_RETRIES):
    """Write an archive of the device's data to |path|.

    Args:
      path: Local path to store the backup file.
      packages: List of to packages to be backed up.
      apk: (optional) If set include the .apk files in the archive.
      shared: (optional) If set buckup the device's SD card.
      nosystem: (optional) If set exclude system applications.
      include_all: (optional) If set back up all installed applications and
        |packages| is optional.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    cmd = ['backup', '-f', path]
    if apk:
      cmd.append('-apk')
    if shared:
      cmd.append('-shared')
    if nosystem:
      cmd.append('-nosystem')
    if include_all:
      cmd.append('-all')
    if packages:
      cmd.extend(packages)
    assert bool(packages) ^ bool(include_all), (
        'Provide \'packages\' or set \'include_all\' but not both.')
    ret = self._RunDeviceAdbCmd(cmd, timeout, retries)
    VerifyLocalFileExists(path)
    return ret

  def Restore(self, path, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Restore device contents from the backup archive.

    Args:
      path: Host path to the backup archive.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    VerifyLocalFileExists(path)
    self._RunDeviceAdbCmd(['restore'] + [path], timeout, retries)

  def WaitForDevice(self, timeout=60 * 5, retries=DEFAULT_RETRIES):
    """Block until the device is online.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    self._RunDeviceAdbCmd(['wait-for-device'], timeout, retries)

  def GetState(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Get device state.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      One of 'offline', 'bootloader', or 'device'.
    """
    # TODO(jbudorick): Revert to using get-state once it doesn't cause a
    # a protocol fault.
    # return self._RunDeviceAdbCmd(['get-state'], timeout, retries).strip()

    lines = self._RawDevices(timeout=timeout, retries=retries)
    for line in lines:
      if len(line) >= 2 and line[0] == self._device_serial:
        return line[1]
    return 'offline'

  def GetDevPath(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Gets the device path.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      The device path (e.g. usb:3-4)
    """
    return self._RunDeviceAdbCmd(['get-devpath'], timeout, retries)

  def Remount(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Remounts the /system partition on the device read-write."""
    self._RunDeviceAdbCmd(['remount'], timeout, retries)

  def Reboot(self, to_bootloader=False, timeout=60 * 5,
             retries=DEFAULT_RETRIES):
    """Reboots the device.

    Args:
      to_bootloader: (optional) If set reboots to the bootloader.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    if to_bootloader:
      cmd = ['reboot-bootloader']
    else:
      cmd = ['reboot']
    self._RunDeviceAdbCmd(cmd, timeout, retries)

  def Root(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Restarts the adbd daemon with root permissions, if possible.

    Args:
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.
    """
    output = self._RunDeviceAdbCmd(['root'], timeout, retries)
    if 'cannot' in output:
      raise device_errors.AdbCommandFailedError(
          ['root'], output, device_serial=self._device_serial)

  def Emu(self, cmd, timeout=DEFAULT_TIMEOUT,
               retries=DEFAULT_RETRIES):
    """Runs an emulator console command.

    See http://developer.android.com/tools/devices/emulator.html#console

    Args:
      cmd: The command to run on the emulator console.
      timeout: (optional) Timeout per try in seconds.
      retries: (optional) Number of retries to attempt.

    Returns:
      The output of the emulator console command.
    """
    if isinstance(cmd, basestring):
      cmd = [cmd]
    return self._RunDeviceAdbCmd(['emu'] + cmd, timeout, retries)

  def DisableVerity(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Disable Marshmallow's Verity security feature"""
    output = self._RunDeviceAdbCmd(['disable-verity'], timeout, retries)
    if output and not _VERITY_DISABLE_RE.search(output):
      raise device_errors.AdbCommandFailedError(
          ['disable-verity'], output, device_serial=self._device_serial)

  def EnableVerity(self, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    """Enable Marshmallow's Verity security feature"""
    output = self._RunDeviceAdbCmd(['enable-verity'], timeout, retries)
    if output and not _VERITY_ENABLE_RE.search(output):
      raise device_errors.AdbCommandFailedError(
          ['enable-verity'], output, device_serial=self._device_serial)

  @property
  def is_emulator(self):
    return _EMULATOR_RE.match(self._device_serial)

  @property
  def is_ready(self):
    try:
      return self.GetState() == _READY_STATE
    except device_errors.CommandFailedError:
      return False
