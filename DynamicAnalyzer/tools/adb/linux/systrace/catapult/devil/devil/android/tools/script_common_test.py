#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import sys
import unittest

from devil import devil_env
from devil.android import device_errors
from devil.android import device_utils
from devil.android.tools import script_common

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


class ScriptCommonTest(unittest.TestCase):

  def testGetDevices_noSpecs(self):
    devices = [
        device_utils.DeviceUtils('123'),
        device_utils.DeviceUtils('456'),
    ]
    with mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices',
                    return_value=devices):
      self.assertEquals(
          devices,
          script_common.GetDevices(None, None))

  def testGetDevices_withDevices(self):
    devices = [
        device_utils.DeviceUtils('123'),
        device_utils.DeviceUtils('456'),
    ]
    with mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices',
                    return_value=devices):
      self.assertEquals(
          [device_utils.DeviceUtils('456')],
          script_common.GetDevices(['456'], None))

  def testGetDevices_missingDevice(self):
    with mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices',
                    return_value=[device_utils.DeviceUtils('123')]):
      with self.assertRaises(device_errors.DeviceUnreachableError):
        script_common.GetDevices(['456'], None)

  def testGetDevices_noDevices(self):
    with mock.patch('devil.android.device_utils.DeviceUtils.HealthyDevices',
                    return_value=[]):
      with self.assertRaises(device_errors.NoDevicesError):
        script_common.GetDevices(None, None)


if __name__ == '__main__':
  sys.exit(unittest.main())

