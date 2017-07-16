#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Takes a screenshot from an Android device."""

import argparse
import logging
import os
import sys

if __name__ == '__main__':
  sys.path.append(os.path.abspath(os.path.join(
      os.path.dirname(__file__), '..', '..', '..')))
from devil.android import device_utils
from devil.android.tools import script_common

logger = logging.getLogger(__name__)


def main():
  # Parse options.
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('-d', '--device', dest='devices', action='append',
                      help='Serial number of Android device to use.')
  parser.add_argument('--blacklist-file', help='Device blacklist JSON file.')
  parser.add_argument('-f', '--file', metavar='FILE',
                      help='Save result to file instead of generating a '
                           'timestamped file name.')
  parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose logging.')
  parser.add_argument('host_file', nargs='?',
                      help='File to which the screenshot will be saved.')

  args = parser.parse_args()

  host_file = args.host_file or args.file

  if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

  devices = script_common.GetDevices(args.devices, args.blacklist_file)

  def screenshot(device):
    f = None
    if host_file:
      root, ext = os.path.splitext(host_file)
      f = '%s_%s%s' % (root, str(device), ext)
    f = device.TakeScreenshot(f)
    print 'Screenshot for device %s written to %s' % (
        str(device), os.path.abspath(f))

  device_utils.DeviceUtils.parallel(devices).pMap(screenshot)
  return 0


if __name__ == '__main__':
  sys.exit(main())
