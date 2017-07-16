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

"""Unit tests for proxyshaper.

Usage:
$ ./proxyshaper_test.py
"""

import proxyshaper
import StringIO
import unittest


# pylint: disable=bad-whitespace
VALID_RATES = (
    # input,       expected_bps
    ( '384Kbit/s',   384000),
    ('1536Kbit/s',  1536000),
    (   '1Mbit/s',  1000000),
    (   '5Mbit/s',  5000000),
    (  '2MByte/s', 16000000),
    (         '0',        0),
    (         '5',        5),
    (      384000,   384000),
    )

ERROR_RATES = (
    '1536KBit/s',  # Older versions of dummynet used capital 'B' for bytes.
    '1Mbyte/s',    # Require capital 'B' for bytes.
    '5bps',
    )


class TimedTestCase(unittest.TestCase):
  def assertValuesAlmostEqual(self, expected, actual, tolerance=0.05):
    """Like the following with nicer default message:
           assertTrue(expected <= actual + tolerance &&
                      expected >= actual - tolerance)
    """
    delta = tolerance * expected
    if actual > expected + delta or actual < expected - delta:
      self.fail('%s is not equal to expected %s +/- %s%%' % (
              actual, expected, 100 * tolerance))


class RateLimitedFileTest(TimedTestCase):
  def testReadLimitedBasic(self):
    num_bytes = 1024
    bps = 384000
    request_counter = lambda: 1
    f = StringIO.StringIO(' ' * num_bytes)
    limited_f = proxyshaper.RateLimitedFile(request_counter, f, bps)
    start = proxyshaper.TIMER()
    self.assertEqual(num_bytes, len(limited_f.read()))
    expected_ms = 8.0 * num_bytes / bps * 1000.0
    actual_ms = (proxyshaper.TIMER() - start) * 1000.0
    self.assertValuesAlmostEqual(expected_ms, actual_ms)

  def testReadlineLimitedBasic(self):
    num_bytes = 1024 * 8 + 512
    bps = 384000
    request_counter = lambda: 1
    f = StringIO.StringIO(' ' * num_bytes)
    limited_f = proxyshaper.RateLimitedFile(request_counter, f, bps)
    start = proxyshaper.TIMER()
    self.assertEqual(num_bytes, len(limited_f.readline()))
    expected_ms = 8.0 * num_bytes / bps * 1000.0
    actual_ms = (proxyshaper.TIMER() - start) * 1000.0
    self.assertValuesAlmostEqual(expected_ms, actual_ms)

  def testReadLimitedSlowedByMultipleRequests(self):
    num_bytes = 1024
    bps = 384000
    request_count = 2
    request_counter = lambda: request_count
    f = StringIO.StringIO(' ' * num_bytes)
    limited_f = proxyshaper.RateLimitedFile(request_counter, f, bps)
    start = proxyshaper.TIMER()
    num_read_bytes = limited_f.read()
    self.assertEqual(num_bytes, len(num_read_bytes))
    expected_ms = 8.0 * num_bytes / (bps / float(request_count)) * 1000.0
    actual_ms = (proxyshaper.TIMER() - start) * 1000.0
    self.assertValuesAlmostEqual(expected_ms, actual_ms)

  def testWriteLimitedBasic(self):
    num_bytes = 1024 * 10 + 350
    bps = 384000
    request_counter = lambda: 1
    f = StringIO.StringIO()
    limited_f = proxyshaper.RateLimitedFile(request_counter, f, bps)
    start = proxyshaper.TIMER()
    limited_f.write(' ' * num_bytes)
    self.assertEqual(num_bytes, len(limited_f.getvalue()))
    expected_ms = 8.0 * num_bytes / bps * 1000.0
    actual_ms = (proxyshaper.TIMER() - start) * 1000.0
    self.assertValuesAlmostEqual(expected_ms, actual_ms)

  def testWriteLimitedSlowedByMultipleRequests(self):
    num_bytes = 1024 * 10
    bps = 384000
    request_count = 2
    request_counter = lambda: request_count
    f = StringIO.StringIO(' ' * num_bytes)
    limited_f = proxyshaper.RateLimitedFile(request_counter, f, bps)
    start = proxyshaper.TIMER()
    limited_f.write(' ' * num_bytes)
    self.assertEqual(num_bytes, len(limited_f.getvalue()))
    expected_ms = 8.0 * num_bytes / (bps / float(request_count)) * 1000.0
    actual_ms = (proxyshaper.TIMER() - start) * 1000.0
    self.assertValuesAlmostEqual(expected_ms, actual_ms)


class GetBitsPerSecondTest(unittest.TestCase):
  def testConvertsValidValues(self):
    for dummynet_option, expected_bps in VALID_RATES:
      bps = proxyshaper.GetBitsPerSecond(dummynet_option)
      self.assertEqual(
          expected_bps, bps, 'Unexpected result for %s: %s != %s' % (
              dummynet_option, expected_bps, bps))

  def testRaisesOnUnexpectedValues(self):
    for dummynet_option in ERROR_RATES:
      self.assertRaises(proxyshaper.BandwidthValueError,
                        proxyshaper.GetBitsPerSecond, dummynet_option)


if __name__ == '__main__':
  unittest.main()
