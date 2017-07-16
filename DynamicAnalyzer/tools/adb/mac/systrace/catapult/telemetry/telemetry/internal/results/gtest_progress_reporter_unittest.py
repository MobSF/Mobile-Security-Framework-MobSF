# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import traceback

from telemetry import story
from telemetry.internal.results import base_test_results_unittest
from telemetry.internal.results import gtest_progress_reporter
from telemetry.internal.results import page_test_results
from telemetry import page as page_module
from telemetry.testing import fakes
from telemetry.testing import stream
from telemetry.value import failure
from telemetry.value import skip


_GROUPING_KEY_DEFAULT = {'1': '2'}


def _MakeStorySet():
  story_set = story.StorySet(base_dir=os.path.dirname(__file__))
  story_set.AddStory(
      page_module.Page('http://www.foo.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.baz.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.roz.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.fus.com/', story_set, story_set.base_dir,
                       grouping_keys=_GROUPING_KEY_DEFAULT))
  story_set.AddStory(
      page_module.Page('http://www.ro.com/', story_set, story_set.base_dir,
                       grouping_keys=_GROUPING_KEY_DEFAULT))
  return story_set


class GTestProgressReporterTest(
    base_test_results_unittest.BaseTestResultsUnittest):

  def setUp(self):
    super(GTestProgressReporterTest, self).setUp()
    self._fake_timer = fakes.FakeTimer(gtest_progress_reporter)

    self._output_stream = stream.TestOutputStream()
    self._reporter = gtest_progress_reporter.GTestProgressReporter(
        self._output_stream)

  def tearDown(self):
    self._fake_timer.Restore()

  def testSingleSuccessPage(self):
    test_story_set = _MakeStorySet()

    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[0])
    self._fake_timer.SetTime(0.007)
    results.DidRunPage(test_story_set.stories[0])

    results.PrintSummary()
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '[       OK ] http://www.foo.com/ (7 ms)\n'
                '[  PASSED  ] 1 test.\n\n')
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testSingleSuccessPageWithGroupingKeys(self):
    test_story_set = _MakeStorySet()

    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[4])
    self._fake_timer.SetTime(0.007)
    results.DidRunPage(test_story_set.stories[4])

    results.PrintSummary()
    expected = ("[ RUN      ] http://www.fus.com/@{'1': '2'}\n"
                "[       OK ] http://www.fus.com/@{'1': '2'} (7 ms)\n"
                "[  PASSED  ] 1 test.\n\n")
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testSingleFailedPage(self):
    test_story_set = _MakeStorySet()

    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[0])
    exc_info = self.CreateException()
    results.AddValue(failure.FailureValue(test_story_set.stories[0], exc_info))
    results.DidRunPage(test_story_set.stories[0])

    results.PrintSummary()
    exception_trace = ''.join(traceback.format_exception(*exc_info))
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '%s\n'
                '[  FAILED  ] http://www.foo.com/ (0 ms)\n'
                '[  PASSED  ] 0 tests.\n'
                '[  FAILED  ] 1 test, listed below:\n'
                '[  FAILED  ]  http://www.foo.com/\n\n'
                '1 FAILED TEST\n\n' % exception_trace)
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testSingleFailedPageWithGroupingKeys(self):
    test_story_set = _MakeStorySet()

    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[4])
    exc_info = self.CreateException()
    results.AddValue(failure.FailureValue(test_story_set.stories[4], exc_info))
    results.DidRunPage(test_story_set.stories[4])

    results.PrintSummary()
    exception_trace = ''.join(traceback.format_exception(*exc_info))
    expected = ("[ RUN      ] http://www.fus.com/@{'1': '2'}\n"
                "%s\n"
                "[  FAILED  ] http://www.fus.com/@{'1': '2'} (0 ms)\n"
                "[  PASSED  ] 0 tests.\n"
                "[  FAILED  ] 1 test, listed below:\n"
                "[  FAILED  ]  http://www.fus.com/@{'1': '2'}\n\n"
                "1 FAILED TEST\n\n" % exception_trace)
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testSingleSkippedPage(self):
    test_story_set = _MakeStorySet()
    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[0])
    self._fake_timer.SetTime(0.007)
    results.AddValue(skip.SkipValue(test_story_set.stories[0],
        'Page skipped for testing reason'))
    results.DidRunPage(test_story_set.stories[0])

    results.PrintSummary()
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '===== SKIPPING TEST http://www.foo.com/:'
                ' Page skipped for testing reason =====\n'
                '[       OK ] http://www.foo.com/ (7 ms)\n'
                '[  PASSED  ] 1 test.\n\n')
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testPassAndFailedPages(self):
    test_story_set = _MakeStorySet()
    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    exc_info = self.CreateException()

    results.WillRunPage(test_story_set.stories[0])
    self._fake_timer.SetTime(0.007)
    results.DidRunPage(test_story_set.stories[0])

    results.WillRunPage(test_story_set.stories[1])
    self._fake_timer.SetTime(0.009)
    results.AddValue(failure.FailureValue(test_story_set.stories[1], exc_info))
    results.DidRunPage(test_story_set.stories[1])

    results.WillRunPage(test_story_set.stories[2])
    self._fake_timer.SetTime(0.015)
    results.AddValue(failure.FailureValue(test_story_set.stories[2], exc_info))
    results.DidRunPage(test_story_set.stories[2])

    results.WillRunPage(test_story_set.stories[3])
    self._fake_timer.SetTime(0.020)
    results.DidRunPage(test_story_set.stories[3])

    results.WillRunPage(test_story_set.stories[4])
    self._fake_timer.SetTime(0.025)
    results.DidRunPage(test_story_set.stories[4])

    results.WillRunPage(test_story_set.stories[5])
    self._fake_timer.SetTime(0.030)
    results.AddValue(failure.FailureValue(test_story_set.stories[5], exc_info))
    results.DidRunPage(test_story_set.stories[5])

    results.PrintSummary()
    exception_trace = ''.join(traceback.format_exception(*exc_info))
    expected = ("[ RUN      ] http://www.foo.com/\n"
                "[       OK ] http://www.foo.com/ (7 ms)\n"
                "[ RUN      ] http://www.bar.com/\n"
                "%s\n"
                "[  FAILED  ] http://www.bar.com/ (2 ms)\n"
                "[ RUN      ] http://www.baz.com/\n"
                "%s\n"
                "[  FAILED  ] http://www.baz.com/ (6 ms)\n"
                "[ RUN      ] http://www.roz.com/\n"
                "[       OK ] http://www.roz.com/ (5 ms)\n"
                "[ RUN      ] http://www.fus.com/@{'1': '2'}\n"
                "[       OK ] http://www.fus.com/@{'1': '2'} (5 ms)\n"
                "[ RUN      ] http://www.ro.com/@{'1': '2'}\n"
                "%s\n"
                "[  FAILED  ] http://www.ro.com/@{'1': '2'} (5 ms)\n"
                "[  PASSED  ] 3 tests.\n"
                "[  FAILED  ] 3 tests, listed below:\n"
                "[  FAILED  ]  http://www.bar.com/\n"
                "[  FAILED  ]  http://www.baz.com/\n"
                "[  FAILED  ]  http://www.ro.com/@{'1': '2'}\n\n"
                "3 FAILED TESTS\n\n"
                % (exception_trace, exception_trace, exception_trace))
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

  def testStreamingResults(self):
    test_story_set = _MakeStorySet()
    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    exc_info = self.CreateException()

    results.WillRunPage(test_story_set.stories[0])
    self._fake_timer.SetTime(0.007)
    results.DidRunPage(test_story_set.stories[0])
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '[       OK ] http://www.foo.com/ (7 ms)\n')
    self.assertEquals(expected, ''.join(self._output_stream.output_data))

    results.WillRunPage(test_story_set.stories[1])
    self._fake_timer.SetTime(0.009)
    exception_trace = ''.join(traceback.format_exception(*exc_info))
    results.AddValue(failure.FailureValue(test_story_set.stories[1], exc_info))
    results.DidRunPage(test_story_set.stories[1])
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '[       OK ] http://www.foo.com/ (7 ms)\n'
                '[ RUN      ] http://www.bar.com/\n'
                '%s\n'
                '[  FAILED  ] http://www.bar.com/ (2 ms)\n' % exception_trace)

  def testOutputSkipInformation(self):
    test_story_set = _MakeStorySet()
    self._reporter = gtest_progress_reporter.GTestProgressReporter(
        self._output_stream, output_skipped_tests_summary=True)
    results = page_test_results.PageTestResults(
        progress_reporter=self._reporter)
    results.WillRunPage(test_story_set.stories[0])
    self._fake_timer.SetTime(0.007)
    results.AddValue(skip.SkipValue(test_story_set.stories[0],
        'Page skipped for testing reason'))
    results.DidRunPage(test_story_set.stories[0])

    results.PrintSummary()
    expected = ('[ RUN      ] http://www.foo.com/\n'
                '===== SKIPPING TEST http://www.foo.com/:'
                ' Page skipped for testing reason =====\n'
                '[       OK ] http://www.foo.com/ (7 ms)\n'
                '[  PASSED  ] 1 test.\n'
                '\n'
                'Skipped pages:\n'
                'http://www.foo.com/\n'
                '\n')
    self.assertEquals(expected, ''.join(self._output_stream.output_data))
