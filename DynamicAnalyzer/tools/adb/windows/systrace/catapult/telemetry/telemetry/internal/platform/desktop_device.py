# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import platform
from telemetry.internal.platform import device


class DesktopDevice(device.Device):
  def __init__(self):
    super(DesktopDevice, self).__init__(name='desktop', guid='desktop')

  @classmethod
  def GetAllConnectedDevices(cls, blacklist):
    return []


def FindAllAvailableDevices(_):
  """Returns a list of available devices.
  """
  # If the host platform is Chrome OS, the device is also considered as cros.
  if platform.GetHostPlatform().GetOSName() == 'chromeos':
    return []
  return [DesktopDevice()]
