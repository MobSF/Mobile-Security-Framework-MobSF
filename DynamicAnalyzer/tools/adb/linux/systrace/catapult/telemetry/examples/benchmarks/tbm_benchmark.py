# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry import benchmark
from telemetry.web_perf import timeline_based_measurement

from benchmarks import simple_story_set

class TBMSample(benchmark.Benchmark):

  def CreateStorySet(self, options):
    return simple_story_set.SimpleStorySet()

  def CreateTimelineBasedMeasurementOptions(self):
    options = timeline_based_measurement.Options()
    options.SetTimelineBasedMetrics(['sample_metric.html'])
    return options

  @classmethod
  def Name(cls):
    return 'tbm_sample.tbm_sample'
