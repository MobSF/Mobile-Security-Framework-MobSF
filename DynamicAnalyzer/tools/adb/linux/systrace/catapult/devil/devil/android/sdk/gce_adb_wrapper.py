# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides a work around for various adb commands on android gce instances.

Some adb commands don't work well when the device is a cloud vm, namely
'push' and 'pull'. With gce instances, moving files through adb can be
painfully slow and hit timeouts, so the methods here just use scp instead.
"""
# pylint: disable=unused-argument

import logging
import os
import subprocess

from devil.android import device_errors
from devil.android.sdk import adb_wrapper
from devil.utils import cmd_helper

logger = logging.getLogger(__name__)


class GceAdbWrapper(adb_wrapper.AdbWrapper):

  def __init__(self, device_serial):
    super(GceAdbWrapper, self).__init__(device_serial)
    self._Connect()
    self.Root()
    self._instance_ip = self.Shell('getprop net.gce.ip').strip()

  def _Connect(self, timeout=adb_wrapper.DEFAULT_TIMEOUT,
               retries=adb_wrapper.DEFAULT_RETRIES):
    """Connects ADB to the android gce instance."""
    cmd = ['connect', self._device_serial]
    output = self._RunAdbCmd(cmd, timeout=timeout, retries=retries)
    if 'unable to connect' in output:
      raise device_errors.AdbCommandFailedError(cmd, output)
    self.WaitForDevice()

  # override
  def Root(self, **kwargs):
    super(GceAdbWrapper, self).Root()
    self._Connect()

  # override
  def Push(self, local, remote, **kwargs):
    """Pushes an object from the host to the gce instance.

    Args:
      local: Path on the host filesystem.
      remote: Path on the instance filesystem.
    """
    adb_wrapper.VerifyLocalFileExists(local)
    if os.path.isdir(local):
      self.Shell('mkdir -p %s' % cmd_helper.SingleQuote(remote))

      # When the object to be pushed is a directory, adb merges the source dir
      # with the destination dir. So if local is a dir, just scp its contents.
      for f in os.listdir(local):
        self._PushObject(os.path.join(local, f), os.path.join(remote, f))
        self.Shell('chmod 777 %s' %
                   cmd_helper.SingleQuote(os.path.join(remote, f)))
    else:
      parent_dir = remote[0:remote.rfind('/')]
      if parent_dir:
        self.Shell('mkdir -p %s' % cmd_helper.SingleQuote(parent_dir))
      self._PushObject(local, remote)
      self.Shell('chmod 777 %s' % cmd_helper.SingleQuote(remote))

  def _PushObject(self, local, remote):
    """Copies an object from the host to the gce instance using scp.

    Args:
      local: Path on the host filesystem.
      remote: Path on the instance filesystem.
    """
    cmd = [
        'scp',
        '-r',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        local,
        'root@%s:%s' % (self._instance_ip, remote)
    ]
    status, _ = cmd_helper.GetCmdStatusAndOutput(cmd)
    if status:
      raise device_errors.AdbCommandFailedError(
          cmd, 'File not reachable on host: %s' % local,
          device_serial=str(self))

  # override
  def Pull(self, remote, local, **kwargs):
    """Pulls a file from the gce instance to the host.

    Args:
      remote: Path on the instance filesystem.
      local: Path on the host filesystem.
    """
    cmd = [
        'scp',
        '-p',
        '-r',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        'root@%s:%s' % (self._instance_ip, remote),
        local,
    ]
    status, _ = cmd_helper.GetCmdStatusAndOutput(cmd)
    if status:
      raise device_errors.AdbCommandFailedError(
          cmd, 'File not reachable on host: %s' % local,
          device_serial=str(self))

    try:
      adb_wrapper.VerifyLocalFileExists(local)
    except (subprocess.CalledProcessError, IOError):
      logger.exception('Error when pulling files from android instance.')
      raise device_errors.AdbCommandFailedError(
          cmd, 'File not reachable on host: %s' % local,
          device_serial=str(self))

  # override
  def Install(self, apk_path, forward_lock=False, reinstall=False,
              sd_card=False, **kwargs):
    """Installs an apk on the gce instance

    Args:
      apk_path: Host path to the APK file.
      forward_lock: (optional) If set forward-locks the app.
      reinstall: (optional) If set reinstalls the app, keeping its data.
      sd_card: (optional) If set installs on the SD card.
    """
    adb_wrapper.VerifyLocalFileExists(apk_path)
    cmd = ['install']
    if forward_lock:
      cmd.append('-l')
    if reinstall:
      cmd.append('-r')
    if sd_card:
      cmd.append('-s')
    self.Push(apk_path, '/data/local/tmp/tmp.apk')
    cmd = ['pm'] + cmd
    cmd.append('/data/local/tmp/tmp.apk')
    output = self.Shell(' '.join(cmd))
    self.Shell('rm /data/local/tmp/tmp.apk')
    if 'Success' not in output:
      raise device_errors.AdbCommandFailedError(
          cmd, output, device_serial=self._device_serial)

  # override
  @property
  def is_emulator(self):
    return True
