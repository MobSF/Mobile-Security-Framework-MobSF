# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

from telemetry import benchmark
from telemetry import story
from telemetry.core import util
from telemetry import decorators
from telemetry.page import page as page_module
from telemetry.page import legacy_page_test
from telemetry import record_wpr
from telemetry.testing import options_for_unittests
from telemetry.testing import tab_test_case
from telemetry.util import wpr_modes


class MockPage(page_module.Page):
  def __init__(self, story_set, url):
    super(MockPage, self).__init__(url=url,
                                   page_set=story_set,
                                   base_dir=util.GetUnittestDataDir())
    self.func_calls = []

  def RunNavigateSteps(self, action_runner):
    self.func_calls.append('RunNavigateSteps')
    super(MockPage, self).RunNavigateSteps(action_runner)

  def RunPageInteractions(self, _):
    self.func_calls.append('RunPageInteractions')

  def RunSmoothness(self, _):
    self.func_calls.append('RunSmoothness')

class MockStorySet(story.StorySet):
  def __init__(self, url=''):
    super(MockStorySet, self).__init__(
        archive_data_file='data/archive_files/test.json')
    self.AddStory(MockPage(self, url))


class MockPageTest(legacy_page_test.LegacyPageTest):
  def __init__(self):
    super(MockPageTest, self).__init__()
    self._action_name_to_run = "RunPageInteractions"
    self.func_calls = []

  def CustomizeBrowserOptions(self, options):
    self.func_calls.append('CustomizeBrowserOptions')

  def WillNavigateToPage(self, page, tab):
    self.func_calls.append('WillNavigateToPage')

  def DidNavigateToPage(self, page, tab):
    self.func_calls.append('DidNavigateToPage')

  def ValidateAndMeasurePage(self, page, tab, results):
    self.func_calls.append('ValidateAndMeasurePage')

  def WillStartBrowser(self, platform):
    self.func_calls.append('WillStartBrowser')

  def DidStartBrowser(self, browser):
    self.func_calls.append('DidStartBrowser')

class MockBenchmark(benchmark.Benchmark):
  test = MockPageTest

  def __init__(self):
    super(MockBenchmark, self).__init__()
    self.mock_story_set = None

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, group):
    group.add_option('', '--mock-benchmark-url', action='store', type='string')

  def CreateStorySet(self, options):
    kwargs = {}
    if options.mock_benchmark_url:
      kwargs['url'] = options.mock_benchmark_url
    self.mock_story_set = MockStorySet(**kwargs)
    return self.mock_story_set


class MockTimelineBasedMeasurementBenchmark(benchmark.Benchmark):

  def __init__(self):
    super(MockTimelineBasedMeasurementBenchmark, self).__init__()
    self.mock_story_set = None

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, group):
    group.add_option('', '--mock-benchmark-url', action='store', type='string')

  def CreateStorySet(self, options):
    kwargs = {}
    if options.mock_benchmark_url:
      kwargs['url'] = options.mock_benchmark_url
    self.mock_story_set = MockStorySet(**kwargs)
    return self.mock_story_set


class RecordWprUnitTests(tab_test_case.TabTestCase):

  _base_dir = util.GetUnittestDataDir()
  _test_data_dir = os.path.join(util.GetUnittestDataDir(), 'page_tests')

  @classmethod
  def setUpClass(cls):
    sys.path.extend([cls._base_dir, cls._test_data_dir])
    super(RecordWprUnitTests, cls).setUpClass()
    cls._url = cls.UrlOfUnittestFile('blank.html')
    cls._test_options = options_for_unittests.GetCopy()

  # When the RecorderPageTest is created from a PageSet, we do not have a
  # PageTest to use. In this case, we will record every available action.
  def testRunPage_AllActions(self):
    record_page_test = record_wpr.RecorderPageTest()
    page = MockPage(story_set=MockStorySet(url=self._url), url=self._url)

    record_page_test.RunNavigateSteps(page, self._tab)
    self.assertTrue('RunNavigateSteps' in page.func_calls)

  # When the RecorderPageTest is created from a Benchmark, the benchmark will
  # have a PageTest, specified by its test attribute.
  def testRunPage_OnlyRunBenchmarkAction(self):
    record_page_test = record_wpr.RecorderPageTest()
    record_page_test.page_test = MockBenchmark().test()
    page = MockPage(story_set=MockStorySet(url=self._url), url=self._url)
    record_page_test.ValidateAndMeasurePage(page, self._tab, results=None)

  def testRunPage_CallBenchmarksPageTestsFunctions(self):
    record_page_test = record_wpr.RecorderPageTest()
    record_page_test.page_test = MockBenchmark().test()
    page = MockPage(story_set=MockStorySet(url=self._url), url=self._url)
    record_page_test.ValidateAndMeasurePage(page, self._tab, results=None)
    self.assertEqual(1, len(record_page_test.page_test.func_calls))
    self.assertEqual('ValidateAndMeasurePage',
                     record_page_test.page_test.func_calls[0])

  def GetBrowserDeviceFlags(self):
    flags = ['--browser', self._browser.browser_type,
             '--remote', self._test_options.cros_remote,
             '--device', self._device]
    if self._test_options.chrome_root:
      flags += ['--chrome-root', self._test_options.chrome_root]
    return flags

  @decorators.Disabled('chromeos') # crbug.com/404868.
  def testWprRecorderWithPageSet(self):
    flags = self.GetBrowserDeviceFlags()
    mock_story_set = MockStorySet(url=self._url)
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir,
                                          mock_story_set, flags)
    results = wpr_recorder.CreateResults()
    wpr_recorder.Record(results)
    self.assertEqual(set(mock_story_set.stories), results.pages_that_succeeded)

  def testWprRecorderWithBenchmark(self):
    flags = self.GetBrowserDeviceFlags()
    flags.extend(['--mock-benchmark-url', self._url])
    mock_benchmark = MockBenchmark()
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir, mock_benchmark,
                                          flags)
    results = wpr_recorder.CreateResults()
    wpr_recorder.Record(results)
    self.assertEqual(set(mock_benchmark.mock_story_set.stories),
                     results.pages_that_succeeded)

  def testWprRecorderWithTimelineBasedMeasurementBenchmark(self):
    flags = self.GetBrowserDeviceFlags()
    flags.extend(['--mock-benchmark-url', self._url])
    mock_benchmark = MockTimelineBasedMeasurementBenchmark()
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir, mock_benchmark,
                                          flags)
    results = wpr_recorder.CreateResults()
    wpr_recorder.Record(results)
    self.assertEqual(set(mock_benchmark.mock_story_set.stories),
                     results.pages_that_succeeded)

  def testPageSetBaseDirFlag(self):
    flags = self.GetBrowserDeviceFlags()
    flags.extend(['--page-set-base-dir', self._test_data_dir,
                  '--mock-benchmark-url', self._url])
    mock_benchmark = MockBenchmark()
    wpr_recorder = record_wpr.WprRecorder(
        'non-existent-dummy-dir', mock_benchmark, flags)
    results = wpr_recorder.CreateResults()
    wpr_recorder.Record(results)
    self.assertEqual(set(mock_benchmark.mock_story_set.stories),
                     results.pages_that_succeeded)

  def testCommandLineFlags(self):
    flags = [
        '--pageset-repeat', '2',
        '--mock-benchmark-url', self._url,
        '--upload',
    ]
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir, MockBenchmark(),
                                          flags)
    # page_runner command-line args
    self.assertEquals(2, wpr_recorder.options.pageset_repeat)
    # benchmark command-line args
    self.assertEquals(self._url, wpr_recorder.options.mock_benchmark_url)
    # record_wpr command-line arg to upload to cloud-storage.
    self.assertTrue(wpr_recorder.options.upload)
    # invalid command-line args
    self.assertFalse(hasattr(wpr_recorder.options, 'not_a_real_option'))

  def testRecordingEnabled(self):
    flags = ['--mock-benchmark-url', self._url]
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir, MockBenchmark(),
                                          flags)
    self.assertEqual(wpr_modes.WPR_RECORD,
                     wpr_recorder.options.browser_options.wpr_mode)

  # When the RecorderPageTest CustomizeBrowserOptions/WillStartBrowser/
  # DidStartBrowser function is called, it forwards the call to the PageTest
  def testRecorderPageTest_BrowserMethods(self):
    flags = ['--mock-benchmark-url', self._url]
    record_page_test = record_wpr.RecorderPageTest()
    record_page_test.page_test = MockBenchmark().test()
    wpr_recorder = record_wpr.WprRecorder(self._test_data_dir, MockBenchmark(),
                                          flags)
    record_page_test.CustomizeBrowserOptions(wpr_recorder.options)
    record_page_test.WillStartBrowser(self._tab.browser.platform)
    record_page_test.DidStartBrowser(self._tab.browser)
    self.assertTrue(
        'CustomizeBrowserOptions' in record_page_test.page_test.func_calls)
    self.assertTrue('WillStartBrowser' in record_page_test.page_test.func_calls)
    self.assertTrue('DidStartBrowser' in record_page_test.page_test.func_calls)

  def testUseLiveSitesUnsupported(self):
    flags = ['--use-live-sites']
    with self.assertRaises(SystemExit):
      record_wpr.WprRecorder(self._test_data_dir, MockBenchmark(), flags)
