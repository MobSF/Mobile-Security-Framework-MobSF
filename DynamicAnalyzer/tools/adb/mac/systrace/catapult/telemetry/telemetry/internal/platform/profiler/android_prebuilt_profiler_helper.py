# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Android-specific, installs pre-built profilers."""

import logging
import os

from telemetry.internal.util import binary_manager
from telemetry import decorators

_DEVICE_PROFILER_DIR = '/data/local/tmp/profilers/'


def GetDevicePath(profiler_binary):
  return os.path.join(_DEVICE_PROFILER_DIR, os.path.basename(profiler_binary))


@decorators.Cache
def InstallOnDevice(device, profiler_binary):
  arch_name = device.GetABI()
  host_path = binary_manager.FetchPath(profiler_binary, arch_name, 'android')
  if not host_path:
    logging.error('Profiler binary "%s" not found. Could not be installed',
                  host_path)
    return False

  device_binary_path = GetDevicePath(profiler_binary)
  device.PushChangedFiles([(host_path, device_binary_path)])
  device.RunShellCommand(
      ['chmod', '777', device_binary_path], check_return=True)
  return True
