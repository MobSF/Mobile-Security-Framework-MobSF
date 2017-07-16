# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import unittest

from telemetry.value import histogram_util

class TestHistogram(unittest.TestCase):
  def testSubtractHistogram(self):
    baseline_histogram = """{"count": 3, "buckets": [
        {"low": 1, "high": 2, "count": 1},
        {"low": 2, "high": 3, "count": 2}]}"""

    later_histogram = """{"count": 14, "buckets": [
        {"low": 1, "high": 2, "count": 1},
        {"low": 2, "high": 3, "count": 3},
        {"low": 3, "high": 4, "count": 10}]}"""

    new_histogram = json.loads(
        histogram_util.SubtractHistogram(later_histogram, baseline_histogram))
    new_buckets = dict()
    for b in new_histogram['buckets']:
      new_buckets[b['low']] = b['count']
    self.assertFalse(1 in new_buckets)
    self.assertEquals(1, new_buckets[2])
    self.assertEquals(10, new_buckets[3])


  def testAddHistograms(self):
    histograms = []
    histograms.append("""{"count": 3, "buckets": [
        {"low": 1, "high": 2, "count": 1},
        {"low": 2, "high": 3, "count": 2}]}""")

    histograms.append("""{"count": 20, "buckets": [
        {"low": 2, "high": 3, "count": 10},
        {"low": 3, "high": 4, "count": 10}]}""")

    histograms.append("""{"count": 15, "buckets": [
        {"low": 1, "high": 2, "count": 4},
        {"low": 3, "high": 4, "count": 11}]}""")

    new_histogram = json.loads(
        histogram_util.AddHistograms(histograms))
    new_buckets = dict()
    for b in new_histogram['buckets']:
      new_buckets[b['low']] = b['count']
    self.assertEquals(5, new_buckets[1])
    self.assertEquals(12, new_buckets[2])
    self.assertEquals(21, new_buckets[3])


  def testGetHistogramBucketsFromRawValue_Max(self):
    raw_value = {'buckets': [
      {'count': 4, 'low': 10, 'high': 15,},
      {'count': 6, 'low': 16, 'high': 18,},
      {'count': 8, 'low': 19},
    ]}
    buckets = histogram_util.GetHistogramBucketsFromRawValue(raw_value)
    self.assertEquals([
      {'count': 4, 'low': 10, 'high': 15,},
      {'count': 6, 'low': 16, 'high': 18,},
      {'count': 8, 'low': 19, 'high': 19},],
      buckets)


  def testGetHistogramBucketsFromJson(self):
    json_value = json.dumps({'buckets': [
      {'count': 4, 'low': 10, 'high': 15,},
      {'count': 6, 'low': 16, 'high': 18,},
      {'count': 8, 'low': 19, 'high': 25},
    ]})
    buckets = histogram_util.GetHistogramBucketsFromJson(json_value)
    self.assertEquals([
      {'count': 4, 'low': 10, 'high': 15,},
      {'count': 6, 'low': 16, 'high': 18,},
      {'count': 8, 'low': 19, 'high': 25},],
      buckets)
