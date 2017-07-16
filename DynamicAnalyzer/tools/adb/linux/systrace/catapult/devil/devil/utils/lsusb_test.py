#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for the cmd_helper module."""

import unittest

from devil import devil_env
from devil.utils import lsusb
from devil.utils import mock_calls

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock # pylint: disable=import-error

RAW_OUTPUT = """
Bus 003 Device 007: ID 18d1:4ee2 Google Inc. Nexus 4 (debug)
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.00
  bDeviceClass            0 (Defined at Interface level)
  bDeviceSubClass         0
  bDeviceProtocol         0
  bMaxPacketSize0        64
  idVendor           0x18d1 Google Inc.
  idProduct          0x4ee2 Nexus 4 (debug)
  bcdDevice            2.28
  iManufacturer           1 LGE
  iProduct                2 Nexus 4
  iSerial                 3 01d2450ea194a93b
  bNumConfigurations      1
  Configuration Descriptor:
    bLength                 9
    bDescriptorType         2
    wTotalLength           62
    bNumInterfaces          2
    bConfigurationValue     1
    iConfiguration          0
    bmAttributes         0x80
      (Bus Powered)
    MaxPower              500mA
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        0
      bAlternateSetting       0
      bNumEndpoints           3
      bInterfaceClass       255 Vendor Specific Class
      bInterfaceSubClass    255 Vendor Specific Subclass
      bInterfaceProtocol      0
      iInterface              4 MTP
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x81  EP 1 IN
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x01  EP 1 OUT
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x82  EP 2 IN
        bmAttributes            3
          Transfer Type            Interrupt
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x001c  1x 28 bytes
        bInterval               6
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        1
      bAlternateSetting       0
      bNumEndpoints           2
      bInterfaceClass       255 Vendor Specific Class
      bInterfaceSubClass     66
      bInterfaceProtocol      1
      iInterface              0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x83  EP 3 IN
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x02  EP 2 OUT
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
Device Qualifier (for other device speed):
  bLength                10
  bDescriptorType         6
  bcdUSB               2.00
  bDeviceClass            0 (Defined at Interface level)
  bDeviceSubClass         0
  bDeviceProtocol         0
  bMaxPacketSize0        64
  bNumConfigurations      1
Device Status:     0x0000
  (Bus Powered)
"""
DEVICE_LIST = 'Bus 003 Device 007: ID 18d1:4ee2 Google Inc. Nexus 4 (debug)'

EXPECTED_RESULT = {
    'device': '007',
    'bus': '003',
    'desc': 'ID 18d1:4ee2 Google Inc. Nexus 4 (debug)',
    'Device': {
        '_value': 'Status:',
        '_desc': '0x0000',
        '(Bus': {
            '_value': 'Powered)',
            '_desc': None
        }
    },
    'Device Descriptor': {
        'bLength': {'_value': '18', '_desc': None},
        'bcdDevice': {'_value': '2.28', '_desc': None},
        'bDeviceSubClass': {'_value': '0', '_desc': None},
        'idVendor': {'_value': '0x18d1', '_desc': 'Google Inc.'},
        'bcdUSB': {'_value': '2.00', '_desc': None},
        'bDeviceProtocol': {'_value': '0', '_desc': None},
        'bDescriptorType': {'_value': '1', '_desc': None},
        'Configuration Descriptor': {
            'bLength': {'_value': '9', '_desc': None},
            'wTotalLength': {'_value': '62', '_desc': None},
            'bConfigurationValue': {'_value': '1', '_desc': None},
            'Interface Descriptor': {
                'bLength': {'_value': '9', '_desc': None},
                'bAlternateSetting': {'_value': '0', '_desc': None},
                'bInterfaceNumber': {'_value': '1', '_desc': None},
                'bNumEndpoints': {'_value': '2', '_desc': None},
                'bDescriptorType': {'_value': '4', '_desc': None},
                'bInterfaceSubClass': {'_value': '66', '_desc': None},
                'bInterfaceClass': {
                    '_value': '255',
                    '_desc': 'Vendor Specific Class'
                },
                'bInterfaceProtocol': {'_value': '1', '_desc': None},
                'Endpoint Descriptor': {
                    'bLength': {'_value': '7', '_desc': None},
                    'bEndpointAddress': {'_value': '0x02', '_desc': 'EP 2 OUT'},
                    'bInterval': {'_value': '0', '_desc': None},
                    'bDescriptorType': {'_value': '5', '_desc': None},
                    'bmAttributes': {
                        '_value': '2',
                        'Transfer': {'_value': 'Type', '_desc': 'Bulk'},
                        'Usage': {'_value': 'Type', '_desc': 'Data'},
                        '_desc': None,
                        'Synch': {'_value': 'Type', '_desc': 'None'}
                    },
                    'wMaxPacketSize': {
                        '_value': '0x0040',
                        '_desc': '1x 64 bytes'
                    }
                },
                'iInterface': {'_value': '0', '_desc': None}
            },
            'bDescriptorType': {'_value': '2', '_desc': None},
            'iConfiguration': {'_value': '0', '_desc': None},
            'bmAttributes': {
                '_value': '0x80',
                '_desc': None,
                '(Bus': {'_value': 'Powered)', '_desc': None}
            },
            'bNumInterfaces': {'_value': '2', '_desc': None},
            'MaxPower': {'_value': '500mA', '_desc': None}
        },
        'iSerial': {'_value': '3', '_desc': '01d2450ea194a93b'},
        'idProduct': {'_value': '0x4ee2', '_desc': 'Nexus 4 (debug)'},
        'iManufacturer': {'_value': '1', '_desc': 'LGE'},
        'bDeviceClass': {
            '_value': '0',
            '_desc': '(Defined at Interface level)'
        },
        'iProduct': {'_value': '2', '_desc': 'Nexus 4'},
        'bMaxPacketSize0': {'_value': '64', '_desc': None},
        'bNumConfigurations': {'_value': '1', '_desc': None}
    },
    'Device Qualifier (for other device speed)': {
        'bLength': {'_value': '10', '_desc': None},
        'bNumConfigurations': {'_value': '1', '_desc': None},
        'bDeviceSubClass': {'_value': '0', '_desc': None},
        'bcdUSB': {'_value': '2.00', '_desc': None},
        'bDeviceProtocol': {'_value': '0', '_desc': None},
        'bDescriptorType': {'_value': '6', '_desc': None},
        'bDeviceClass': {
            '_value': '0',
            '_desc': '(Defined at Interface level)'
        },
        'bMaxPacketSize0': {'_value': '64', '_desc': None}
    }
}


class LsusbTest(mock_calls.TestCase):
  """Test Lsusb parsing."""

  def testLsusb(self):
    with self.assertCalls(
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
            ['lsusb'], timeout=10), (None, DEVICE_LIST)),
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
          ['lsusb', '-v', '-s', '003:007'], timeout=10), (None, RAW_OUTPUT))):
      self.assertDictEqual(lsusb.lsusb().pop(), EXPECTED_RESULT)

  def testGetSerial(self):
    with self.assertCalls(
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
            ['lsusb'], timeout=10), (None, DEVICE_LIST)),
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
          ['lsusb', '-v', '-s', '003:007'], timeout=10), (None, RAW_OUTPUT))):
      self.assertEqual(lsusb.get_android_devices(), ['01d2450ea194a93b'])

  def testGetLsusbSerial(self):
    with self.assertCalls(
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
            ['lsusb'], timeout=10), (None, DEVICE_LIST)),
        (mock.call.devil.utils.cmd_helper.GetCmdStatusAndOutputWithTimeout(
          ['lsusb', '-v', '-s', '003:007'], timeout=10), (None, RAW_OUTPUT))):
      out = lsusb.lsusb().pop()
      self.assertEqual(lsusb.get_lsusb_serial(out), '01d2450ea194a93b')


if __name__ == '__main__':
  unittest.main()
