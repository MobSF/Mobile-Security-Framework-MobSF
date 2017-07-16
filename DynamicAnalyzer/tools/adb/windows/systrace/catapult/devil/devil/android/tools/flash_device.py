#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import logging
import os
import sys

if __name__ == '__main__':
  sys.path.append(os.path.abspath(os.path.join(
      os.path.dirname(__file__), '..', '..', '..')))
from devil.android import device_blacklist
from devil.android import device_utils
from devil.android import fastboot_utils
from devil.android.tools import script_common
from devil.constants import exit_codes
from devil.utils import run_tests_helper

logger = logging.getLogger(__name__)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('build_path', help='Path to android build.')
  parser.add_argument('-d', '--device', dest='devices', action='append',
                      help='Device(s) to flash.')
  parser.add_argument('-v', '--verbose', default=0, action='count',
                      help='Verbose level (multiple times for more)')
  parser.add_argument('-w', '--wipe', action='store_true',
                       help='If set, wipes user data')
  parser.add_argument('--blacklist-file', help='Device blacklist file.')
  args = parser.parse_args()
  run_tests_helper.SetLogLevel(args.verbose)

  if args.blacklist_file:
    blacklist = device_blacklist.Blacklist(args.blacklist_file).Read()
    if blacklist:
      logger.critical('Device(s) in blacklist, not flashing devices:')
      for key in blacklist:
        logger.critical('  %s', key)
      return exit_codes.INFRA

  flashed_devices = []
  failed_devices = []

  def flash(device):
    fastboot = fastboot_utils.FastbootUtils(device)
    try:
      fastboot.FlashDevice(args.build_path, wipe=args.wipe)
      flashed_devices.append(device)
    except Exception:  # pylint: disable=broad-except
      logger.exception('Device %s failed to flash.', str(device))
      failed_devices.append(device)

  devices = script_common.GetDevices(args.devices, args.blacklist_file)
  device_utils.DeviceUtils.parallel(devices).pMap(flash)

  if flashed_devices:
    logger.info('The following devices were flashed:')
    logger.info('  %s', ' '.join(str(d) for d in flashed_devices))
  if failed_devices:
    logger.critical('The following devices failed to flash:')
    logger.critical('  %s', ' '.join(str(d) for d in failed_devices))
    return exit_codes.INFRA
  return 0

if __name__ == '__main__':
  sys.exit(main())
