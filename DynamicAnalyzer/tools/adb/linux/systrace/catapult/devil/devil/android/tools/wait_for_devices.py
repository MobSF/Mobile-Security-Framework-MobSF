#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Waits for the given devices to be available."""

import argparse
import os
import sys

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   '..', '..', '..')))

from devil import devil_env
from devil.android import device_utils
from devil.utils import run_tests_helper


def main(raw_args):
  parser = argparse.ArgumentParser()
  parser.add_argument('-v', '--verbose', action='count', help='Log more.')
  parser.add_argument('-t', '--timeout', default=30, type=int,
                      help='Seconds to wait for the devices.')
  parser.add_argument('--adb-path', help='ADB binary to use.')
  parser.add_argument('device_serials', nargs='*', metavar='SERIAL',
                      help='Serials of the devices to wait for.')

  args = parser.parse_args(raw_args)

  run_tests_helper.SetLogLevel(args.verbose)

  devil_dynamic_config = devil_env.EmptyConfig()
  if args.adb_path:
    devil_dynamic_config['dependencies'].update(
        devil_env.LocalConfigItem(
            'adb', devil_env.GetPlatform(), args.adb_path))
  devil_env.config.Initialize(configs=[devil_dynamic_config])

  devices = device_utils.DeviceUtils.HealthyDevices(
      device_arg=args.device_serials)
  parallel_devices = device_utils.DeviceUtils.parallel(devices)
  parallel_devices.WaitUntilFullyBooted(timeout=args.timeout)
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
