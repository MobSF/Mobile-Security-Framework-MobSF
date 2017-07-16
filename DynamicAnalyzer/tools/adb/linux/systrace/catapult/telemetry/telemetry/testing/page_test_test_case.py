# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provide a TestCase base class for PageTest subclasses' unittests."""

import unittest

from telemetry import benchmark
from telemetry import story
from telemetry.core import exceptions
from telemetry.core import util
from telemetry.internal.results import results_options
from telemetry.internal import story_runner
from telemetry.page import page as page_module
from telemetry.page import legacy_page_test
from telemetry.testing import options_for_unittests


class BasicTestPage(page_module.Page):
  def __init__(self, url, story_set, base_dir):
    super(BasicTestPage, self).__init__(url, story_set, base_dir)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class EmptyMetadataForTest(benchmark.BenchmarkMetadata):
  def __init__(self):
    super(EmptyMetadataForTest, self).__init__('')


class PageTestTestCase(unittest.TestCase):
  """A base class to simplify writing unit tests for PageTest subclasses."""

  def CreateStorySetFromFileInUnittestDataDir(self, test_filename):
    ps = self.CreateEmptyPageSet()
    page = BasicTestPage('file://' + test_filename, ps, base_dir=ps.base_dir)
    ps.AddStory(page)
    return ps

  def CreateEmptyPageSet(self):
    base_dir = util.GetUnittestDataDir()
    ps = story.StorySet(base_dir=base_dir)
    return ps

  def RunMeasurement(self, measurement, ps,
      options=None):
    """Runs a measurement against a pageset, returning the rows its outputs."""
    if options is None:
      options = options_for_unittests.GetCopy()
    assert options
    temp_parser = options.CreateParser()
    story_runner.AddCommandLineArgs(temp_parser)
    defaults = temp_parser.get_default_values()
    for k, v in defaults.__dict__.items():
      if hasattr(options, k):
        continue
      setattr(options, k, v)

    if isinstance(measurement, legacy_page_test.LegacyPageTest):
      measurement.CustomizeBrowserOptions(options.browser_options)
    options.output_file = None
    options.output_formats = ['none']
    options.suppress_gtest_report = True
    options.output_trace_tag = None
    story_runner.ProcessCommandLineArgs(temp_parser, options)
    results = results_options.CreateResults(EmptyMetadataForTest(), options)
    story_runner.Run(measurement, ps, options, results)
    return results

  def TestTracingCleanedUp(self, measurement_class, options=None):
    ps = self.CreateStorySetFromFileInUnittestDataDir('blank.html')
    start_tracing_called = [False]
    stop_tracing_called = [False]

    class BuggyMeasurement(measurement_class):
      def __init__(self, *args, **kwargs):
        measurement_class.__init__(self, *args, **kwargs)

      # Inject fake tracing methods to tracing_controller
      def TabForPage(self, page, browser):
        ActualStartTracing = browser.platform.tracing_controller.StartTracing
        def FakeStartTracing(*args, **kwargs):
          ActualStartTracing(*args, **kwargs)
          start_tracing_called[0] = True
          raise exceptions.IntentionalException
        browser.StartTracing = FakeStartTracing

        ActualStopTracing = browser.platform.tracing_controller.StopTracing
        def FakeStopTracing(*args, **kwargs):
          result = ActualStopTracing(*args, **kwargs)
          stop_tracing_called[0] = True
          return result
        browser.platform.tracing_controller.StopTracing = FakeStopTracing

        return measurement_class.TabForPage(self, page, browser)

    measurement = BuggyMeasurement()
    try:
      self.RunMeasurement(measurement, ps, options=options)
    except legacy_page_test.TestNotSupportedOnPlatformError:
      pass
    if start_tracing_called[0]:
      self.assertTrue(stop_tracing_called[0])
