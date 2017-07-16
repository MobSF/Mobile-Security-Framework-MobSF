# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.internal.platform import gpu_device
from telemetry.internal.platform import gpu_info


class TestGPUInfo(unittest.TestCase):

  def testConstruction(self):
    data = {
        'devices': [
            {'vendor_id': 1000, 'device_id': 2000,
             'vendor_string': 'a', 'device_string': 'b'},
            {'vendor_id': 3000, 'device_id': 4000,
             'vendor_string': 'k', 'device_string': 'l'}
        ],
        'aux_attributes': {
            'optimus': False,
            'amd_switchable': False,
            'driver_vendor': 'c',
            'driver_version': 'd',
            'driver_date': 'e',
            'gl_version_string': 'g',
            'gl_vendor': 'h',
            'gl_renderer': 'i',
            'gl_extensions': 'j',
        }
    }
    info = gpu_info.GPUInfo.FromDict(data)
    self.assertTrue(len(info.devices) == 2)
    self.assertTrue(isinstance(info.devices[0], gpu_device.GPUDevice))
    self.assertEquals(info.devices[0].vendor_id, 1000)
    self.assertEquals(info.devices[0].device_id, 2000)
    self.assertEquals(info.devices[0].vendor_string, 'a')
    self.assertEquals(info.devices[0].device_string, 'b')
    self.assertTrue(isinstance(info.devices[1], gpu_device.GPUDevice))
    self.assertEquals(info.devices[1].vendor_id, 3000)
    self.assertEquals(info.devices[1].device_id, 4000)
    self.assertEquals(info.devices[1].vendor_string, 'k')
    self.assertEquals(info.devices[1].device_string, 'l')
    self.assertEquals(info.aux_attributes['optimus'], False)
    self.assertEquals(info.aux_attributes['amd_switchable'], False)
    self.assertEquals(info.aux_attributes['driver_vendor'], 'c')
    self.assertEquals(info.aux_attributes['driver_version'], 'd')
    self.assertEquals(info.aux_attributes['driver_date'], 'e')
    self.assertEquals(info.aux_attributes['gl_version_string'], 'g')
    self.assertEquals(info.aux_attributes['gl_vendor'], 'h')
    self.assertEquals(info.aux_attributes['gl_renderer'], 'i')
    self.assertEquals(info.aux_attributes['gl_extensions'], 'j')

  def testMissingAttrsFromDict(self):
    data = {
        'devices': [{'vendor_id': 1000, 'device_id': 2000,
                     'vendor_string': 'a', 'device_string': 'b'}]
    }

    for k in data:
      data_copy = data.copy()
      del data_copy[k]
      try:
        gpu_info.GPUInfo.FromDict(data_copy)
        self.fail('Should raise exception if attribute "%s" is missing' % k)
      except AssertionError:
        raise
      except KeyError:
        pass

  def testMissingDevices(self):
    data = {
        'devices': []
    }

    try:
      gpu_info.GPUInfo.FromDict(data)
      self.fail('Should raise exception if devices array is empty')
    except AssertionError:
      raise
    except Exception:
      pass
