# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Exception classes raised by AdbWrapper and DeviceUtils.
"""

from devil import base_error
from devil.utils import cmd_helper
from devil.utils import parallelizer


class CommandFailedError(base_error.BaseError):
  """Exception for command failures."""

  def __init__(self, message, device_serial=None):
    device_leader = '(device: %s)' % device_serial
    if device_serial is not None and not message.startswith(device_leader):
      message = '%s %s' % (device_leader, message)
    self.device_serial = device_serial
    super(CommandFailedError, self).__init__(message)

  def __eq__(self, other):
    return (super(CommandFailedError, self).__eq__(other)
            and self.device_serial == other.device_serial)

  def __ne__(self, other):
    return not self == other


class _BaseCommandFailedError(CommandFailedError):
  """Base Exception for adb and fastboot command failures."""

  def __init__(self, args, output, status=None, device_serial=None,
               message=None):
    self.args = args
    self.output = output
    self.status = status
    if not message:
      adb_cmd = ' '.join(cmd_helper.SingleQuote(arg) for arg in self.args)
      message = ['adb %s: failed ' % adb_cmd]
      if status:
        message.append('with exit status %s ' % self.status)
      if output:
        message.append('and output:\n')
        message.extend('- %s\n' % line for line in output.splitlines())
      else:
        message.append('and no output.')
      message = ''.join(message)
    super(_BaseCommandFailedError, self).__init__(message, device_serial)

  def __eq__(self, other):
    return (super(_BaseCommandFailedError, self).__eq__(other)
            and self.args == other.args
            and self.output == other.output
            and self.status == other.status)

  def __ne__(self, other):
    return not self == other

  def __reduce__(self):
    """Support pickling."""
    result = [None, None, None, None, None]
    super_result = super(_BaseCommandFailedError, self).__reduce__()
    for i in range(len(super_result)):
      result[i] = super_result[i]

    # Update the args used to reconstruct this exception.
    result[1] = (
        self.args, self.output, self.status, self.device_serial, self.message)
    return tuple(result)


class AdbCommandFailedError(_BaseCommandFailedError):
  """Exception for adb command failures."""

  def __init__(self, args, output, status=None, device_serial=None,
               message=None):
    super(AdbCommandFailedError, self).__init__(
        args, output, status=status, message=message,
        device_serial=device_serial)


class FastbootCommandFailedError(_BaseCommandFailedError):
  """Exception for fastboot command failures."""

  def __init__(self, args, output, status=None, device_serial=None,
               message=None):
    super(FastbootCommandFailedError, self).__init__(
        args, output, status=status, message=message,
        device_serial=device_serial)


class DeviceVersionError(CommandFailedError):
  """Exception for device version failures."""

  def __init__(self, message, device_serial=None):
    super(DeviceVersionError, self).__init__(message, device_serial)


class AdbShellCommandFailedError(AdbCommandFailedError):
  """Exception for shell command failures run via adb."""

  def __init__(self, command, output, status, device_serial=None):
    self.command = command
    message = ['shell command run via adb failed on the device:\n',
               '  command: %s\n' % command]
    message.append('  exit status: %s\n' % status)
    if output:
      message.append('  output:\n')
      if isinstance(output, basestring):
        output_lines = output.splitlines()
      else:
        output_lines = output
      message.extend('  - %s\n' % line for line in output_lines)
    else:
      message.append("  output: ''\n")
    message = ''.join(message)
    super(AdbShellCommandFailedError, self).__init__(
      ['shell', command], output, status, device_serial, message)

  def __reduce__(self):
    """Support pickling."""
    result = [None, None, None, None, None]
    super_result = super(AdbShellCommandFailedError, self).__reduce__()
    for i in range(len(super_result)):
      result[i] = super_result[i]

    # Update the args used to reconstruct this exception.
    result[1] = (self.command, self.output, self.status, self.device_serial)
    return tuple(result)


class CommandTimeoutError(base_error.BaseError):
  """Exception for command timeouts."""
  pass


class DeviceUnreachableError(base_error.BaseError):
  """Exception for device unreachable failures."""
  pass


class NoDevicesError(base_error.BaseError):
  """Exception for having no devices attached."""

  def __init__(self, msg=None):
    super(NoDevicesError, self).__init__(
        msg or 'No devices attached.', is_infra_error=True)


class MultipleDevicesError(base_error.BaseError):
  """Exception for having multiple attached devices without selecting one."""

  def __init__(self, devices):
    parallel_devices = parallelizer.Parallelizer(devices)
    descriptions = parallel_devices.pMap(
        lambda d: d.build_description).pGet(None)
    msg = ('More than one device available. Use -d/--device to select a device '
           'by serial.\n\nAvailable devices:\n')
    for d, desc in zip(devices, descriptions):
      msg += '  %s (%s)\n' % (d, desc)

    super(MultipleDevicesError, self).__init__(msg, is_infra_error=True)


class NoAdbError(base_error.BaseError):
  """Exception for being unable to find ADB."""

  def __init__(self, msg=None):
    super(NoAdbError, self).__init__(
        msg or 'Unable to find adb.', is_infra_error=True)


class DeviceChargingError(CommandFailedError):
  """Exception for device charging errors."""

  def __init__(self, message, device_serial=None):
    super(DeviceChargingError, self).__init__(message, device_serial)
