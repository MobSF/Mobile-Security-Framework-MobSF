#! /usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import pickle
import sys
import unittest

from devil.android import device_errors


class DeviceErrorsTest(unittest.TestCase):

  def assertIsPicklable(self, original):
    pickled = pickle.dumps(original)
    reconstructed = pickle.loads(pickled)
    self.assertEquals(original, reconstructed)

  def testPicklable_AdbCommandFailedError(self):
    original = device_errors.AdbCommandFailedError(
        ['these', 'are', 'adb', 'args'], 'adb failure output', status=':(',
        device_serial='0123456789abcdef')
    self.assertIsPicklable(original)

  def testPicklable_AdbShellCommandFailedError(self):
    original = device_errors.AdbShellCommandFailedError(
        'foo', 'erroneous foo output', '1', device_serial='0123456789abcdef')
    self.assertIsPicklable(original)

  def testPicklable_CommandFailedError(self):
    original = device_errors.CommandFailedError(
        'sample command failed')
    self.assertIsPicklable(original)

  def testPicklable_CommandTimeoutError(self):
    original = device_errors.CommandTimeoutError(
        'My fake command timed out :(')
    self.assertIsPicklable(original)

  def testPicklable_DeviceChargingError(self):
    original = device_errors.DeviceChargingError(
        'Fake device failed to charge')
    self.assertIsPicklable(original)

  def testPicklable_DeviceUnreachableError(self):
    original = device_errors.DeviceUnreachableError
    self.assertIsPicklable(original)

  def testPicklable_FastbootCommandFailedError(self):
    original = device_errors.FastbootCommandFailedError(
        ['these', 'are', 'fastboot', 'args'], 'fastboot failure output',
        status=':(', device_serial='0123456789abcdef')
    self.assertIsPicklable(original)

  def testPicklable_MultipleDevicesError(self):
    # TODO(jbudorick): Implement this after implementing a stable DeviceUtils
    # fake. https://github.com/catapult-project/catapult/issues/3145
    pass

  def testPicklable_NoAdbError(self):
    original = device_errors.NoAdbError()
    self.assertIsPicklable(original)

  def testPicklable_NoDevicesError(self):
    original = device_errors.NoDevicesError()
    self.assertIsPicklable(original)



if __name__ == '__main__':
  sys.exit(unittest.main())
