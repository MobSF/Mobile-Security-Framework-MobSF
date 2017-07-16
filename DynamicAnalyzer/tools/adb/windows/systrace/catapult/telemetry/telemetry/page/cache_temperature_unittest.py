# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib

from telemetry import decorators
from telemetry import page as page_module
from telemetry import story
from telemetry.page import cache_temperature
from telemetry.testing import browser_test_case
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


class CacheTempeartureTests(browser_test_case.BrowserTestCase):
  def __init__(self, *args, **kwargs):
    super(CacheTempeartureTests, self).__init__(*args, **kwargs)
    self._full_trace = None

  @contextlib.contextmanager
  def captureTrace(self):
    tracing_controller = self._browser.platform.tracing_controller
    options = tracing_config.TracingConfig()
    options.enable_chrome_trace = True
    tracing_controller.StartTracing(options)
    try:
      yield
    finally:
      self._full_trace = tracing_controller.StopTracing()

  def traceMarkers(self):
    if not self._full_trace:
      return set()

    chrome_trace = self._full_trace.GetTraceFor(trace_data.CHROME_TRACE_PART)
    return set(
        event['name']
        for event in chrome_trace['traceEvents']
        if event['cat'] == 'blink.console')

  @decorators.Enabled('has tabs')
  def testEnsureAny(self):
    with self.captureTrace():
      story_set = story.StorySet()
      page = page_module.Page('http://google.com', page_set=story_set,
          cache_temperature=cache_temperature.ANY)
      cache_temperature.EnsurePageCacheTemperature(page, self._browser)

    markers = self.traceMarkers()
    self.assertNotIn('telemetry.internal.ensure_diskcache.start', markers)
    self.assertNotIn('telemetry.internal.warmCache.start', markers)

  @decorators.Enabled('has tabs')
  @decorators.Disabled('chromeos')
  def testEnsurePCv1Cold(self):
    with self.captureTrace():
      story_set = story.StorySet()
      page = page_module.Page('http://google.com', page_set=story_set,
          cache_temperature=cache_temperature.PCV1_COLD)
      cache_temperature.EnsurePageCacheTemperature(page, self._browser)

    markers = self.traceMarkers()
    self.assertIn('telemetry.internal.ensure_diskcache.start', markers)
    self.assertIn('telemetry.internal.ensure_diskcache.end', markers)

  @decorators.Enabled('has tabs')
  def testEnsurePCv1WarmAfterPCv1ColdRun(self):
    with self.captureTrace():
      story_set = story.StorySet()
      page = page_module.Page('http://google.com', page_set=story_set,
          cache_temperature=cache_temperature.PCV1_COLD)
      cache_temperature.EnsurePageCacheTemperature(page, self._browser)

      previous_page = page
      page = page_module.Page('http://google.com', page_set=story_set,
          cache_temperature=cache_temperature.PCV1_WARM)
      cache_temperature.EnsurePageCacheTemperature(page, self._browser,
          previous_page)

    markers = self.traceMarkers()
    self.assertNotIn('telemetry.internal.warmCache.start', markers)

  @decorators.Enabled('has tabs')
  @decorators.Disabled('chromeos')
  def testEnsurePCv1WarmFromScratch(self):
    with self.captureTrace():
      story_set = story.StorySet()
      page = page_module.Page('http://google.com', page_set=story_set,
          cache_temperature=cache_temperature.PCV1_WARM)
      cache_temperature.EnsurePageCacheTemperature(page, self._browser)

    markers = self.traceMarkers()
    self.assertIn('telemetry.internal.warmCache.start', markers)
    self.assertIn('telemetry.internal.warmCache.end', markers)
