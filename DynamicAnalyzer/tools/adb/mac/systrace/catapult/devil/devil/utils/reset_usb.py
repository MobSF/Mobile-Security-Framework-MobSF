#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import fcntl
import logging
import os
import re
import sys

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   '..', '..')))

from devil.android import device_errors
from devil.utils import lsusb
from devil.utils import run_tests_helper

logger = logging.getLogger(__name__)

_INDENTATION_RE = re.compile(r'^( *)')
_LSUSB_BUS_DEVICE_RE = re.compile(r'^Bus (\d{3}) Device (\d{3}):')
_LSUSB_ENTRY_RE = re.compile(r'^ *([^ ]+) +([^ ]+) *([^ ].*)?$')
_LSUSB_GROUP_RE = re.compile(r'^ *([^ ]+.*):$')

_USBDEVFS_RESET = ord('U') << 8 | 20


def reset_usb(bus, device):
  """Reset the USB device with the given bus and device."""
  usb_file_path = '/dev/bus/usb/%03d/%03d' % (bus, device)
  with open(usb_file_path, 'w') as usb_file:
    logger.debug('fcntl.ioctl(%s, %d)', usb_file_path, _USBDEVFS_RESET)
    fcntl.ioctl(usb_file, _USBDEVFS_RESET)


def reset_android_usb(serial):
  """Reset the USB device for the given Android device."""
  lsusb_info = lsusb.lsusb()

  bus = None
  device = None
  for device_info in lsusb_info:
    device_serial = lsusb.get_lsusb_serial(device_info)
    if device_serial == serial:
      bus = int(device_info.get('bus'))
      device = int(device_info.get('device'))

  if bus and device:
    reset_usb(bus, device)
  else:
    raise device_errors.DeviceUnreachableError(
        'Unable to determine bus(%s) or device(%s) for device %s'
         % (bus, device, serial))


def reset_all_android_devices():
  """Reset all USB devices that look like an Android device."""
  _reset_all_matching(lambda i: bool(lsusb.get_lsusb_serial(i)))


def _reset_all_matching(condition):
  lsusb_info = lsusb.lsusb()
  for device_info in lsusb_info:
    if int(device_info.get('device')) != 1 and condition(device_info):
      bus = int(device_info.get('bus'))
      device = int(device_info.get('device'))
      try:
        reset_usb(bus, device)
        serial = lsusb.get_lsusb_serial(device_info)
        if serial:
          logger.info(
              'Reset USB device (bus: %03d, device: %03d, serial: %s)',
              bus, device, serial)
        else:
          logger.info(
              'Reset USB device (bus: %03d, device: %03d)',
              bus, device)
      except IOError:
        logger.error(
            'Failed to reset USB device (bus: %03d, device: %03d)',
            bus, device)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-v', '--verbose', action='count')
  parser.add_argument('-s', '--serial')
  parser.add_argument('--bus', type=int)
  parser.add_argument('--device', type=int)
  args = parser.parse_args()

  run_tests_helper.SetLogLevel(args.verbose)

  if args.serial:
    reset_android_usb(args.serial)
  elif args.bus and args.device:
    reset_usb(args.bus, args.device)
  else:
    parser.error('Unable to determine target. '
                 'Specify --serial or BOTH --bus and --device.')

  return 0


if __name__ == '__main__':
  sys.exit(main())

