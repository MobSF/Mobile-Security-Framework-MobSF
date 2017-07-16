# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import posixpath

from devil import devil_env
from devil.android import device_errors
from devil.android.constants import file_system

BIN_DIR = '%s/bin' % file_system.TEST_EXECUTABLE_DIR
_FRAMEWORK_DIR = '%s/framework' % file_system.TEST_EXECUTABLE_DIR

_COMMANDS = {
  'unzip': 'org.chromium.android.commands.unzip.Unzip',
}

_SHELL_COMMAND_FORMAT = (
"""#!/system/bin/sh
base=%s
export CLASSPATH=$base/framework/chromium_commands.jar
exec app_process $base/bin %s $@
""")


def Installed(device):
  paths = [posixpath.join(BIN_DIR, c) for c in _COMMANDS]
  paths.append(posixpath.join(_FRAMEWORK_DIR, 'chromium_commands.jar'))
  return device.PathExists(paths)


def InstallCommands(device):
  if device.IsUserBuild():
    raise device_errors.CommandFailedError(
        'chromium_commands currently requires a userdebug build.',
        device_serial=device.adb.GetDeviceSerial())

  chromium_commands_jar_path = devil_env.config.FetchPath('chromium_commands')
  if not os.path.exists(chromium_commands_jar_path):
    raise device_errors.CommandFailedError(
        '%s not found. Please build chromium_commands.'
        % chromium_commands_jar_path)

  device.RunShellCommand(
      ['mkdir', '-p', BIN_DIR, _FRAMEWORK_DIR], check_return=True)
  for command, main_class in _COMMANDS.iteritems():
    shell_command = _SHELL_COMMAND_FORMAT % (
        file_system.TEST_EXECUTABLE_DIR, main_class)
    shell_file = '%s/%s' % (BIN_DIR, command)
    device.WriteFile(shell_file, shell_command)
    device.RunShellCommand(
        ['chmod', '755', shell_file], check_return=True)

  device.adb.Push(
      chromium_commands_jar_path,
      '%s/chromium_commands.jar' % _FRAMEWORK_DIR)
