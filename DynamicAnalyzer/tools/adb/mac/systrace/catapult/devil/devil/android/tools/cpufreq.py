#! /usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A script to manipulate device CPU frequency."""

import argparse
import os
import pprint
import sys

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   '..', '..', '..')))

from devil import devil_env
from devil.android import device_utils
from devil.android.perf import perf_control
from devil.utils import run_tests_helper


def SetScalingGovernor(device, args):
  p = perf_control.PerfControl(device)
  p.SetScalingGovernor(args.governor)


def GetScalingGovernor(device, _args):
  p = perf_control.PerfControl(device)
  for cpu, governor in p.GetScalingGovernor():
    print '%s %s: %s' % (str(device), cpu, governor)


def ListAvailableGovernors(device, _args):
  p = perf_control.PerfControl(device)
  for cpu, governors in p.ListAvailableGovernors():
    print '%s %s: %s' % (str(device), cpu, pprint.pformat(governors))


def main(raw_args):
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--adb-path',
      help='ADB binary path.')
  parser.add_argument(
      '--device', dest='devices', action='append', default=[],
      help='Devices for which the governor should be set. Defaults to all.')
  parser.add_argument(
      '-v', '--verbose', action='count',
      help='Log more.')

  subparsers = parser.add_subparsers()

  set_governor = subparsers.add_parser('set-governor')
  set_governor.add_argument(
      'governor',
      help='Desired CPU governor.')
  set_governor.set_defaults(func=SetScalingGovernor)

  get_governor = subparsers.add_parser('get-governor')
  get_governor.set_defaults(func=GetScalingGovernor)

  list_governors = subparsers.add_parser('list-governors')
  list_governors.set_defaults(func=ListAvailableGovernors)

  args = parser.parse_args(raw_args)

  run_tests_helper.SetLogLevel(args.verbose)

  devil_dynamic_config = devil_env.EmptyConfig()
  if args.adb_path:
    devil_dynamic_config['dependencies'].update(
        devil_env.LocalConfigItem(
            'adb', devil_env.GetPlatform(), args.adb_path))
  devil_env.config.Initialize(configs=[devil_dynamic_config])

  devices = device_utils.DeviceUtils.HealthyDevices(device_arg=args.devices)

  parallel_devices = device_utils.DeviceUtils.parallel(devices)
  parallel_devices.pMap(args.func, args)

  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
