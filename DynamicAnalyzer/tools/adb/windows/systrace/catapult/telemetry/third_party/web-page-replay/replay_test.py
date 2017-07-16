#!/usr/bin/env python
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for replay.

Usage:
$ ./replay_test.py
"""

import replay
import unittest


class MockOptions(dict):
  """A dict with items that can be accessed as attributes."""
  def __getattr__(self, name):
    return self[name]


class OptionsWrapperTest(unittest.TestCase):

  def testNoTrafficShapingByDefault(self):
    parser = replay.GetParser()
    options = parser.parse_args([])
    options = replay.OptionsWrapper(options, parser)
    self.assertEqual({}, options.shaping_dns)
    self.assertEqual({}, options.shaping_http)
    self.assertEqual({}, options.shaping_dummynet)

  def testShapingProxyWithoutOptionsGivesEmptySettings(self):
    parser = replay.GetParser()
    options = parser.parse_args(['--shaping=proxy'])
    options = replay.OptionsWrapper(options, parser)
    self.assertEqual({}, options.shaping_dns)
    self.assertEqual({}, options.shaping_http)
    self.assertEqual({}, options.shaping_dummynet)

  def testShapingProxyWithNetOption(self):
    parser = replay.GetParser()
    options = parser.parse_args(['--shaping=proxy', '--net=cable'])
    options = replay.OptionsWrapper(options, parser)
    expected_http = {
        'down_bandwidth': '5Mbit/s', 'delay_ms': '28', 'up_bandwidth': '1Mbit/s'
        }
    self.assertEqual({'delay_ms': '28'}, options.shaping_dns)
    self.assertEqual(expected_http, options.shaping_http)
    self.assertEqual({}, options.shaping_dummynet)

  def testNetOptionUsesDummynetByDefault(self):
    parser = replay.GetParser()
    options = parser.parse_args(['--net=cable'])
    options = replay.OptionsWrapper(options, parser)
    expected_dummynet = {
        'down_bandwidth': '5Mbit/s', 'delay_ms': '28', 'up_bandwidth': '1Mbit/s'
        }
    self.assertEqual({}, options.shaping_dns)
    self.assertEqual({}, options.shaping_http)
    self.assertEqual(expected_dummynet, options.shaping_dummynet)

  def testPacketLossForDummynet(self):
    parser = replay.GetParser()
    options = parser.parse_args(['--packet_loss_rate=12'])
    options = replay.OptionsWrapper(options, parser)
    self.assertEqual({'packet_loss_rate': '12'}, options.shaping_dummynet)

  def testIgnoredProxyShapingOptions(self):
    parser = replay.GetParser()
    options = parser.parse_args(
        ['--packet_loss_rate=12', '--init_cwnd=10', '--shaping=proxy'])
    options = replay.OptionsWrapper(options, parser)
    self.assertEqual({}, options.shaping_dns)
    self.assertEqual({}, options.shaping_http)
    self.assertEqual({}, options.shaping_dummynet)


if __name__ == '__main__':
  unittest.main()
