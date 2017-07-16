# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.internal.platform import gpu_device


class TestGPUDevice(unittest.TestCase):

  def testConstruction(self):
    device = gpu_device.GPUDevice(1000, 2000, 'test_vendor', 'test_device')
    self.assertEquals(device.vendor_id, 1000)
    self.assertEquals(device.device_id, 2000)
    self.assertEquals(device.vendor_string, 'test_vendor')
    self.assertEquals(device.device_string, 'test_device')

  def testFromDict(self):
    dictionary = {'vendor_id': 3000,
                  'device_id': 4000,
                  'vendor_string': 'test_vendor_2',
                  'device_string': 'test_device_2'}
    device = gpu_device.GPUDevice.FromDict(dictionary)
    self.assertEquals(device.vendor_id, 3000)
    self.assertEquals(device.device_id, 4000)
    self.assertEquals(device.vendor_string, 'test_vendor_2')
    self.assertEquals(device.device_string, 'test_device_2')

  def testMissingAttrsFromDict(self):
    data = {
        'vendor_id': 1,
        'device_id': 2,
        'vendor_string': 'a',
        'device_string': 'b'
    }

    for k in data:
      data_copy = data.copy()
      del data_copy[k]
      try:
        gpu_device.GPUDevice.FromDict(data_copy)
        self.fail('Should raise exception if attribute "%s" is missing' % k)
      except AssertionError:
        raise
      except KeyError:
        pass
