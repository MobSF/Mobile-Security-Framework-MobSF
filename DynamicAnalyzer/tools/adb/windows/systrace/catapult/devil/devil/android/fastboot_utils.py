# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides a variety of device interactions based on fastboot."""
# pylint: disable=unused-argument

import collections
import contextlib
import fnmatch
import logging
import os
import re

from devil.android import decorators
from devil.android import device_errors
from devil.android.sdk import fastboot
from devil.utils import timeout_retry

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30
_DEFAULT_RETRIES = 3
_FASTBOOT_REBOOT_TIMEOUT = 10 * _DEFAULT_TIMEOUT
_KNOWN_PARTITIONS = collections.OrderedDict([
      ('bootloader', {'image': 'bootloader*.img', 'restart': True}),
      ('radio', {'image': 'radio*.img', 'restart': True}),
      ('boot', {'image': 'boot.img'}),
      ('recovery', {'image': 'recovery.img'}),
      ('system', {'image': 'system.img'}),
      ('userdata', {'image': 'userdata.img', 'wipe_only': True}),
      ('cache', {'image': 'cache.img', 'wipe_only': True}),
      ('vendor', {'image': 'vendor*.img', 'optional': True}),
  ])
ALL_PARTITIONS = _KNOWN_PARTITIONS.keys()


def _FindAndVerifyPartitionsAndImages(partitions, directory):
  """Validate partitions and images.

  Validate all partition names and partition directories. Cannot stop mid
  flash so its important to validate everything first.

  Args:
    Partitions: partitions to be tested.
    directory: directory containing the images.

  Returns:
    Dictionary with exact partition, image name mapping.
  """

  files = os.listdir(directory)
  return_dict = collections.OrderedDict()

  def find_file(pattern):
    for filename in files:
      if fnmatch.fnmatch(filename, pattern):
        return os.path.join(directory, filename)
    return None
  for partition in partitions:
    partition_info = _KNOWN_PARTITIONS[partition]
    image_file = find_file(partition_info['image'])
    if image_file:
      return_dict[partition] = image_file
    elif not partition_info.get('optional'):
      raise device_errors.FastbootCommandFailedError(
          'Failed to flash device. Could not find image for %s.',
          partition_info['image'])
  return return_dict


class FastbootUtils(object):

  _FASTBOOT_WAIT_TIME = 1
  _BOARD_VERIFICATION_FILE = 'android-info.txt'

  def __init__(self, device, fastbooter=None, default_timeout=_DEFAULT_TIMEOUT,
               default_retries=_DEFAULT_RETRIES):
    """FastbootUtils constructor.

    Example Usage to flash a device:
      fastboot = fastboot_utils.FastbootUtils(device)
      fastboot.FlashDevice('/path/to/build/directory')

    Args:
      device: A DeviceUtils instance.
      fastbooter: Optional fastboot object. If none is passed, one will
        be created.
      default_timeout: An integer containing the default number of seconds to
        wait for an operation to complete if no explicit value is provided.
      default_retries: An integer containing the default number or times an
        operation should be retried on failure if no explicit value is provided.
    """
    self._device = device
    self._board = device.product_board
    self._serial = str(device)
    self._default_timeout = default_timeout
    self._default_retries = default_retries
    if fastbooter:
      self.fastboot = fastbooter
    else:
      self.fastboot = fastboot.Fastboot(self._serial)

  @decorators.WithTimeoutAndRetriesFromInstance()
  def WaitForFastbootMode(self, timeout=None, retries=None):
    """Wait for device to boot into fastboot mode.

    This waits for the device serial to show up in fastboot devices output.
    """
    def fastboot_mode():
      return self._serial in self.fastboot.Devices()

    timeout_retry.WaitFor(fastboot_mode, wait_period=self._FASTBOOT_WAIT_TIME)

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=_FASTBOOT_REBOOT_TIMEOUT)
  def EnableFastbootMode(self, timeout=None, retries=None):
    """Reboots phone into fastboot mode.

    Roots phone if needed, then reboots phone into fastboot mode and waits.
    """
    self._device.EnableRoot()
    self._device.adb.Reboot(to_bootloader=True)
    self.WaitForFastbootMode()

  @decorators.WithTimeoutAndRetriesFromInstance(
      min_default_timeout=_FASTBOOT_REBOOT_TIMEOUT)
  def Reboot(
      self, bootloader=False, wait_for_reboot=True, timeout=None, retries=None):
    """Reboots out of fastboot mode.

    It reboots the phone either back into fastboot, or to a regular boot. It
    then blocks until the device is ready.

    Args:
      bootloader: If set to True, reboots back into bootloader.
    """
    if bootloader:
      self.fastboot.RebootBootloader()
      self.WaitForFastbootMode()
    else:
      self.fastboot.Reboot()
      if wait_for_reboot:
        self._device.WaitUntilFullyBooted(timeout=_FASTBOOT_REBOOT_TIMEOUT)

  def _VerifyBoard(self, directory):
    """Validate as best as possible that the android build matches the device.

    Goes through build files and checks if the board name is mentioned in the
    |self._BOARD_VERIFICATION_FILE| or in the build archive.

    Args:
      directory: directory where build files are located.
    """
    files = os.listdir(directory)
    board_regex = re.compile(r'require board=(\w+)')
    if self._BOARD_VERIFICATION_FILE in files:
      with open(os.path.join(directory, self._BOARD_VERIFICATION_FILE)) as f:
        for line in f:
          m = board_regex.match(line)
          if m:
            board_name = m.group(1)
            if board_name == self._board:
              return True
            elif board_name:
              return False
            else:
              logger.warning('No board type found in %s.',
                             self._BOARD_VERIFICATION_FILE)
    else:
      logger.warning('%s not found. Unable to use it to verify device.',
                     self._BOARD_VERIFICATION_FILE)

    zip_regex = re.compile(r'.*%s.*\.zip' % re.escape(self._board))
    for f in files:
      if zip_regex.match(f):
        return True

    return False

  def _FlashPartitions(self, partitions, directory, wipe=False, force=False):
    """Flashes all given partiitons with all given images.

    Args:
      partitions: List of partitions to flash.
      directory: Directory where all partitions can be found.
      wipe: If set to true, will automatically detect if cache and userdata
          partitions are sent, and if so ignore them.
      force: boolean to decide to ignore board name safety checks.

    Raises:
      device_errors.CommandFailedError(): If image cannot be found or if bad
          partition name is give.
    """
    if not self._VerifyBoard(directory):
      if force:
        logger.warning('Could not verify build is meant to be installed on '
                       'the current device type, but force flag is set. '
                       'Flashing device. Possibly dangerous operation.')
      else:
        raise device_errors.CommandFailedError(
            'Could not verify build is meant to be installed on the current '
            'device type. Run again with force=True to force flashing with an '
            'unverified board.')

    flash_image_files = _FindAndVerifyPartitionsAndImages(partitions, directory)
    partitions = flash_image_files.keys()
    for partition in partitions:
      if _KNOWN_PARTITIONS[partition].get('wipe_only') and not wipe:
        logger.info(
            'Not flashing in wipe mode. Skipping partition %s.', partition)
      else:
        logger.info(
            'Flashing %s with %s', partition, flash_image_files[partition])
        self.fastboot.Flash(partition, flash_image_files[partition])
        if _KNOWN_PARTITIONS[partition].get('restart', False):
          self.Reboot(bootloader=True)

  @contextlib.contextmanager
  def FastbootMode(self, wait_for_reboot=True, timeout=None, retries=None):
    """Context manager that enables fastboot mode, and reboots after.

    Example usage:
      with FastbootMode():
        Flash Device
      # Anything that runs after flashing.
    """
    self.EnableFastbootMode()
    self.fastboot.SetOemOffModeCharge(False)
    try:
      yield self
    finally:
      self.fastboot.SetOemOffModeCharge(True)
      self.Reboot(wait_for_reboot=wait_for_reboot)

  def FlashDevice(self, directory, partitions=None, wipe=False):
    """Flash device with build in |directory|.

    Directory must contain bootloader, radio, boot, recovery, system, userdata,
    and cache .img files from an android build. This is a dangerous operation so
    use with care.

    Args:
      fastboot: A FastbootUtils instance.
      directory: Directory with build files.
      wipe: Wipes cache and userdata if set to true.
      partitions: List of partitions to flash. Defaults to all.
    """
    if partitions is None:
      partitions = ALL_PARTITIONS
    # If a device is wiped, then it will no longer have adb keys so it cannot be
    # communicated with to verify that it is rebooted. It is up to the user of
    # this script to ensure that the adb keys are set on the device after using
    # this to wipe a device.
    with self.FastbootMode(wait_for_reboot=not wipe):
      self._FlashPartitions(partitions, directory, wipe=wipe)
