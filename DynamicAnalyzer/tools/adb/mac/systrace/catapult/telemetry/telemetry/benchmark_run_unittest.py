# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import benchmark as benchmark_module
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry import story as story_module
from telemetry.testing import fakes
import mock


# pylint: disable=abstract-method
class DummyPageTest(legacy_page_test.LegacyPageTest):
  def __init__(self):
    super(DummyPageTest, self).__init__()
    # Without disabling the above warning, this complains that
    # ValidateAndMeasurePage is abstract; but defining it complains
    # that its definition is overridden here.
    self.ValidateAndMeasurePage = mock.Mock()


# More end-to-end tests of Benchmark, shared_page_state and associated
# classes using telemetry.testing.fakes, to avoid needing to construct
# a real browser instance.

class FakePage(page_module.Page):
  def __init__(self, page_set):
    super(FakePage, self).__init__(
      url='http://nonexistentserver.com/nonexistentpage.html',
      page_set=page_set,
      shared_page_state_class=fakes.FakeSharedPageState)
    self.RunNavigateSteps = mock.Mock()
    self.RunPageInteractions = mock.Mock()

class FakeBenchmark(benchmark_module.Benchmark):
  def __init__(self, max_failures=None):
    super(FakeBenchmark, self).__init__(max_failures)
    self._fake_pages = []
    self._fake_story_set = story_module.StorySet()
    self._created_story_set = False
    self.validator = DummyPageTest()

  def CreatePageTest(self, options):
    return self.validator

  def GetFakeStorySet(self):
    return self._fake_story_set

  def AddFakePage(self, page):
    if self._created_story_set:
      raise Exception('Can not add any more fake pages')
    self._fake_pages.append(page)

  def CreateStorySet(self, options):
    if self._created_story_set:
      raise Exception('Can only create the story set once per FakeBenchmark')
    for page in self._fake_pages:
      self._fake_story_set.AddStory(page)
    self._created_story_set = True
    return self._fake_story_set


class FailingPage(FakePage):
  def __init__(self, page_set):
    super(FailingPage, self).__init__(page_set)
    self.RunNavigateSteps.side_effect = Exception('Deliberate exception')


class BenchmarkRunTest(unittest.TestCase):
  def setupBenchmark(self):
    finder_options = fakes.CreateBrowserFinderOptions()
    finder_options.browser_options.platform = fakes.FakeLinuxPlatform()
    finder_options.output_formats = ['none']
    finder_options.suppress_gtest_report = True
    finder_options.output_dir = None
    finder_options.upload_bucket = 'public'
    finder_options.upload_results = False
    benchmarkclass = FakeBenchmark
    parser = finder_options.CreateParser()
    benchmark_module.AddCommandLineArgs(parser)
    benchmarkclass.AddCommandLineArgs(parser)
    options, _ = parser.parse_args([])
    benchmark_module.ProcessCommandLineArgs(parser, options)
    benchmarkclass.ProcessCommandLineArgs(parser, options)
    benchmark = benchmarkclass()
    return benchmark, finder_options

  def testPassingPage(self):
    benchmark, finder_options = self.setupBenchmark()
    manager = mock.Mock()
    page = FakePage(benchmark.GetFakeStorySet())
    page.RunNavigateSteps = manager.page.RunNavigateSteps
    page.RunPageInteractions = manager.page.RunPageInteractions
    benchmark.validator.ValidateAndMeasurePage = (
      manager.validator.ValidateAndMeasurePage)
    benchmark.AddFakePage(page)
    self.assertEqual(benchmark.Run(finder_options), 0,
                     'Test should run with no errors')
    expected = [mock.call.page.RunNavigateSteps(mock.ANY),
                mock.call.page.RunPageInteractions(mock.ANY),
                mock.call.validator.ValidateAndMeasurePage(
                  page, mock.ANY, mock.ANY)]
    self.assertTrue(manager.mock_calls == expected)


  def testFailingPage(self):
    benchmark, finder_options = self.setupBenchmark()
    page = FailingPage(benchmark.GetFakeStorySet())
    benchmark.AddFakePage(page)
    self.assertNotEqual(benchmark.Run(finder_options), 0, 'Test should fail')
    self.assertFalse(page.RunPageInteractions.called)
