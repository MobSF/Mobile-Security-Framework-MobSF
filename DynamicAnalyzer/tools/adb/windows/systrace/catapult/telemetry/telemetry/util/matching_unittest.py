# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.util import matching


class BenchmarkFoo(object):
  """ Benchmark Foo for testing."""
  @classmethod
  def Name(cls):
    return 'FooBenchmark'


class BenchmarkBar(object):
  """ Benchmark Bar for testing long description line."""
  @classmethod
  def Name(cls):
    return 'BarBenchmarkkkkk'


class UnusualBenchmark(object):
  @classmethod
  def Name(cls):
    return 'I have a very unusual name'


class CommandLineUnittest(unittest.TestCase):
  def testGetMostLikelyMatchedObject(self):
    # Test moved from telemetry/benchmark_runner_unittest.py
    all_benchmarks = [BenchmarkFoo, BenchmarkBar, UnusualBenchmark]
    self.assertEquals(
        [BenchmarkFoo, BenchmarkBar],
        matching.GetMostLikelyMatchedObject(
            all_benchmarks, 'BenchmarkFooz', name_func=lambda x: x.Name()))

    self.assertEquals(
        [BenchmarkBar, BenchmarkFoo],
        matching.GetMostLikelyMatchedObject(
            all_benchmarks, 'BarBenchmark', name_func=lambda x: x.Name()))

    self.assertEquals(
        [UnusualBenchmark],
        matching.GetMostLikelyMatchedObject(
            all_benchmarks, 'unusual', name_func=lambda x: x.Name()))
