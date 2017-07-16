# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.internal.platform import gpu_device
from telemetry.internal.platform import gpu_info
from telemetry.internal.platform import system_info


class TestSystemInfo(unittest.TestCase):

  def testConstruction(self):
    data = {
        'model_name': 'MacBookPro 10.1',
        'gpu': {
            'devices': [
                {'vendor_id': 1000, 'device_id': 2000,
                 'vendor_string': 'a', 'device_string': 'b'},
            ]
        }
    }
    info = system_info.SystemInfo.FromDict(data)
    self.assertTrue(isinstance(info, system_info.SystemInfo))
    self.assertTrue(isinstance(info.gpu, gpu_info.GPUInfo))
    self.assertEquals(info.model_name, 'MacBookPro 10.1')
    self.assertTrue(len(info.gpu.devices) == 1)
    self.assertTrue(isinstance(info.gpu.devices[0], gpu_device.GPUDevice))
    self.assertEquals(info.gpu.devices[0].vendor_id, 1000)
    self.assertEquals(info.gpu.devices[0].device_id, 2000)
    self.assertEquals(info.gpu.devices[0].vendor_string, 'a')
    self.assertEquals(info.gpu.devices[0].device_string, 'b')

  def testEmptyModelName(self):
    data = {
        'model_name': '',
        'gpu': {
            'devices': [
                {'vendor_id': 1000, 'device_id': 2000,
                 'vendor_string': 'a', 'device_string': 'b'},
            ]
        }
    }
    try:
      info = system_info.SystemInfo.FromDict(data)
      self.assertEquals(info.model_name, '')
    except AssertionError:
      raise
    except Exception:
      self.fail('Should not raise exception for empty model_name string')

  def testMissingAttrsFromDict(self):
    data = {
        'model_name': 'MacBookPro 10.1',
        'devices': [{'vendor_id': 1000, 'device_id': 2000,
                     'vendor_string': 'a', 'device_string': 'b'}]
    }

    for k in data:
      data_copy = data.copy()
      del data_copy[k]
      try:
        system_info.SystemInfo.FromDict(data_copy)
        self.fail('Should raise exception if attribute "%s" is missing' % k)
      except AssertionError:
        raise
      except KeyError:
        pass
