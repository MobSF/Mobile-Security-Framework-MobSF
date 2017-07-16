#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Unit tests for some APIs with conditional logic in adb_wrapper.py
"""

import unittest

from devil import devil_env
from devil.android import device_errors
from devil.android.sdk import adb_wrapper

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


class AdbWrapperTest(unittest.TestCase):
  def setUp(self):
    self.adb = adb_wrapper.AdbWrapper('ABC12345678')

  def _MockRunDeviceAdbCmd(self, return_value):
    return mock.patch.object(
        self.adb,
        '_RunDeviceAdbCmd',
        mock.Mock(side_effect=None, return_value=return_value))

  def testDisableVerityWhenDisabled(self):
    with self._MockRunDeviceAdbCmd('Verity already disabled on /system'):
      self.adb.DisableVerity()

  def testDisableVerityWhenEnabled(self):
    with self._MockRunDeviceAdbCmd(
        'Verity disabled on /system\nNow reboot your device for settings to '
        'take effect'):
      self.adb.DisableVerity()

  def testEnableVerityWhenEnabled(self):
    with self._MockRunDeviceAdbCmd('Verity already enabled on /system'):
      self.adb.EnableVerity()

  def testEnableVerityWhenDisabled(self):
    with self._MockRunDeviceAdbCmd(
        'Verity enabled on /system\nNow reboot your device for settings to '
        'take effect'):
      self.adb.EnableVerity()

  def testFailEnableVerity(self):
    with self._MockRunDeviceAdbCmd('error: closed'):
      self.assertRaises(
          device_errors.AdbCommandFailedError, self.adb.EnableVerity)

  def testFailDisableVerity(self):
    with self._MockRunDeviceAdbCmd('error: closed'):
      self.assertRaises(
          device_errors.AdbCommandFailedError, self.adb.DisableVerity)

