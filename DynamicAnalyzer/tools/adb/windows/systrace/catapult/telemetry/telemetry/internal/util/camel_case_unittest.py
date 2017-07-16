# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.util import camel_case


class CamelCaseTest(unittest.TestCase):

  def testString(self):
    self.assertEqual(camel_case.ToUnderscore('camelCase'), 'camel_case')
    self.assertEqual(camel_case.ToUnderscore('CamelCase'), 'camel_case')
    self.assertEqual(camel_case.ToUnderscore('Camel2Case'), 'camel2_case')
    self.assertEqual(camel_case.ToUnderscore('Camel2Case2'), 'camel2_case2')
    self.assertEqual(camel_case.ToUnderscore('2012Q3'), '2012_q3')

  def testList(self):
    camel_case_list = ['CamelCase', ['NestedList']]
    underscore_list = ['camel_case', ['nested_list']]
    self.assertEqual(camel_case.ToUnderscore(camel_case_list), underscore_list)

  def testDict(self):
    camel_case_dict = {
        'gpu': {
            'vendorId': 1000,
            'deviceId': 2000,
            'vendorString': 'aString',
            'deviceString': 'bString'},
        'secondaryGpus': [
            {'vendorId': 3000, 'deviceId': 4000,
             'vendorString': 'k', 'deviceString': 'l'}
        ]
    }
    underscore_dict = {
        'gpu': {
            'vendor_id': 1000,
            'device_id': 2000,
            'vendor_string': 'aString',
            'device_string': 'bString'},
        'secondary_gpus': [
            {'vendor_id': 3000, 'device_id': 4000,
             'vendor_string': 'k', 'device_string': 'l'}
        ]
    }
    self.assertEqual(camel_case.ToUnderscore(camel_case_dict), underscore_dict)

  def testOther(self):
    self.assertEqual(camel_case.ToUnderscore(self), self)
