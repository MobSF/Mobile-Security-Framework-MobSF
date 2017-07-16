# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from telemetry.internal.platform import profiler
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data as trace_data_module


class TraceProfiler(profiler.Profiler):

  def __init__(self, browser_backend, platform_backend, output_path, state,
               categories=None):
    super(TraceProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    assert self._browser_backend.supports_tracing
    # We always want flow events when tracing via telemetry.
    categories_with_flow = 'disabled-by-default-toplevel.flow'
    if categories:
      categories_with_flow += ',%s' % categories
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    config.chrome_trace_config.SetCategoryFilter(
        chrome_trace_category_filter.ChromeTraceCategoryFilter(
            categories_with_flow))
    self._browser_backend.StartTracing(config, timeout=10)

  @classmethod
  def name(cls):
    return 'trace'

  @classmethod
  def is_supported(cls, browser_type):
    return True

  def CollectProfile(self):
    print 'Processing trace...'

    trace_result_builder = trace_data_module.TraceDataBuilder()
    self._browser_backend.StopTracing()
    self._browser_backend.CollectTracingData(trace_result_builder)
    trace_result = trace_result_builder.AsData()
    try:
      trace_file = '%s.html' % self._output_path
      title = os.path.basename(self._output_path)
      trace_result.Serialize(trace_file, trace_title=title)
    finally:
      trace_result.CleanUpAllTraces()

    print 'Trace saved as file:///%s' % os.path.abspath(trace_file)

    return [trace_file]


class TraceDetailedProfiler(TraceProfiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(TraceDetailedProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state,
        categories='disabled-by-default-cc.debug*')

  @classmethod
  def name(cls):
    return 'trace-detailed'


class TraceAllProfiler(TraceProfiler):

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(TraceAllProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state,
        categories='disabled-by-default-*')

  @classmethod
  def name(cls):
    return 'trace-all'
