# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import logging
import re
import subprocess

from telemetry.core import platform
from telemetry.internal.platform import device


IOSSIM_BUILD_DIRECTORIES = [
    'Debug-iphonesimulator',
    'Profile-iphonesimulator',
    'Release-iphonesimulator'
]

class IOSDevice(device.Device):
  def __init__(self):
    super(IOSDevice, self).__init__(name='ios', guid='ios')

  @classmethod
  def GetAllConnectedDevices(cls, blacklist):
    return []


def _IsIosDeviceAttached():
  devices = subprocess.check_output('system_profiler SPUSBDataType', shell=True)
  for line in devices.split('\n'):
    if line and re.match(r'\s*(iPod|iPhone|iPad):', line):
      return True
  return False

def _IsIosSimulatorAvailable(chrome_root):
  """Determines whether an iOS simulator is present in the local checkout.

  Assumes the iOS simulator (iossim) and Chromium have already been built.

  Returns:
    True if at least one simulator is found, otherwise False.
  """
  for build_dir in IOSSIM_BUILD_DIRECTORIES:
    iossim_path = os.path.join(
        chrome_root, 'out', build_dir, 'iossim')
    chromium_path = os.path.join(
        chrome_root, 'out', build_dir, 'Chromium.app')

    # If the iOS simulator and Chromium app are present, return True
    if os.path.exists(iossim_path) and os.path.exists(chromium_path):
      return True

  return False

def FindAllAvailableDevices(options):
  """Returns a list of available devices.
  """
  # TODO(baxley): Add support for all platforms possible. Probably Linux,
  # probably not Windows.
  if platform.GetHostPlatform().GetOSName() != 'mac':
    return []

  if options.chrome_root is None:
    logging.warning('--chrome-root is not specified, skip iOS simulator tests.')
    return []

  if (not _IsIosDeviceAttached() and not
      _IsIosSimulatorAvailable(options.chrome_root)):
    return []

  return [IOSDevice()]
