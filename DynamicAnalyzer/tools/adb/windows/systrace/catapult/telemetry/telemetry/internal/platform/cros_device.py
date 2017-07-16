# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging

from telemetry.core import cros_interface
from telemetry.core import platform
from telemetry.internal.platform import device


class CrOSDevice(device.Device):
  def __init__(self, host_name, ssh_port, ssh_identity, is_local):
    super(CrOSDevice, self).__init__(
        name='ChromeOs with host %s' % host_name or 'localhost',
        guid='cros:%s' % host_name or 'localhost')
    self._host_name = host_name
    self._ssh_port = ssh_port
    self._ssh_identity = ssh_identity
    self._is_local = is_local

  @classmethod
  def GetAllConnectedDevices(cls, blacklist):
    return []

  @property
  def host_name(self):
    return self._host_name

  @property
  def ssh_port(self):
    return self._ssh_port

  @property
  def ssh_identity(self):
    return self._ssh_identity

  @property
  def is_local(self):
    return self._is_local


def IsRunningOnCrOS():
  return platform.GetHostPlatform().GetOSName() == 'chromeos'


def FindAllAvailableDevices(options):
  """Returns a list of available device types."""
  use_ssh = options.cros_remote and cros_interface.HasSSH()
  if not use_ssh and not IsRunningOnCrOS():
    logging.debug('No --remote specified, and not running on ChromeOs.')
    return []

  return [CrOSDevice(options.cros_remote, options.cros_remote_ssh_port,
                     options.cros_ssh_identity, not use_ssh)]
