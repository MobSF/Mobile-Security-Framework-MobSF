# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import unittest

from telemetry import android
from telemetry import benchmark
from telemetry.testing import options_for_unittests
from telemetry.internal import story_runner
from telemetry import page
from telemetry.page import legacy_page_test
from telemetry.page import shared_page_state
from telemetry import story as story_module
from telemetry.web_perf import timeline_based_measurement


class DummyPageTest(legacy_page_test.LegacyPageTest):
  def ValidateAndMeasurePage(self, *_):
    pass


class TestBenchmark(benchmark.Benchmark):
  def __init__(self, story):
    super(TestBenchmark, self).__init__()
    self._story_set = story_module.StorySet()
    self._story_set.AddStory(story)

  def CreatePageTest(self, _):
    return DummyPageTest()

  def CreateStorySet(self, _):
    return self._story_set


class BenchmarkTest(unittest.TestCase):

  def testPageTestWithIncompatibleStory(self):
    b = TestBenchmark(story_module.Story(
        shared_state_class=shared_page_state.SharedPageState))
    with self.assertRaisesRegexp(
        Exception, 'containing only telemetry.page.Page stories'):
      b.Run(options_for_unittests.GetCopy())

    state_class = story_module.SharedState
    b = TestBenchmark(story_module.Story(
        shared_state_class=state_class))
    with self.assertRaisesRegexp(
        Exception, 'containing only telemetry.page.Page stories'):
      b.Run(options_for_unittests.GetCopy())

    b = TestBenchmark(android.AndroidStory(start_intent=None))
    with self.assertRaisesRegexp(
        Exception, 'containing only telemetry.page.Page stories'):
      b.Run(options_for_unittests.GetCopy())

  def testPageTestWithCompatibleStory(self):
    original_run_fn = story_runner.Run
    was_run = [False]
    def RunStub(*arg, **kwargs):
      del arg, kwargs
      was_run[0] = True
    story_runner.Run = RunStub

    try:
      options = options_for_unittests.GetCopy()
      options.output_formats = ['none']
      options.suppress_gtest_report = True
      parser = optparse.OptionParser()
      benchmark.AddCommandLineArgs(parser)
      options.MergeDefaultValues(parser.get_default_values())

      b = TestBenchmark(page.Page(url='about:blank'))
      b.Run(options)
    finally:
      story_runner.Run = original_run_fn

    self.assertTrue(was_run[0])

  def testOverriddenTbmOptionsAndPageTestRaises(self):
    class FakeTimelineBasedMeasurementOptions(object):
      pass

    class OverrideBothBenchmark(benchmark.Benchmark):
      def CreatePageTest(self, _):
        return DummyPageTest()
      def CreateTimelineBasedMeasurementOptions(self):
        return FakeTimelineBasedMeasurementOptions()

    assertion_regex = (
        'Cannot override both CreatePageTest and '
        'CreateTimelineBasedMeasurementOptions')
    with self.assertRaisesRegexp(AssertionError, assertion_regex):
      OverrideBothBenchmark()

  def testBenchmarkMakesTbmTestByDefault(self):
    class DefaultTbmBenchmark(benchmark.Benchmark):
      pass

    self.assertIsInstance(
        DefaultTbmBenchmark().CreatePageTest(options=None),
        timeline_based_measurement.TimelineBasedMeasurement)

  def testUnknownTestTypeRaises(self):
    class UnknownTestType(object):
      pass
    class UnknownTestTypeBenchmark(benchmark.Benchmark):
      test = UnknownTestType

    type_error_regex = (
        '"UnknownTestType" is not a PageTest or a TimelineBasedMeasurement')
    with self.assertRaisesRegexp(TypeError, type_error_regex):
      UnknownTestTypeBenchmark().CreatePageTest(options=None)

  def testOverriddenTbmOptionsAndPageTestTestAttributeRaises(self):
    class FakeTimelineBasedMeasurementOptions(object):
      pass

    class OverrideOptionsOnPageTestBenchmark(benchmark.Benchmark):
      test = DummyPageTest
      def CreateTimelineBasedMeasurementOptions(self):
        return FakeTimelineBasedMeasurementOptions()

    assertion_regex = (
        'Cannot override CreateTimelineBasedMeasurementOptions '
        'with a PageTest')
    with self.assertRaisesRegexp(AssertionError, assertion_regex):
      OverrideOptionsOnPageTestBenchmark().CreatePageTest(options=None)

  def testBenchmarkPredicate(self):
    class PredicateBenchmark(TestBenchmark):
      @classmethod
      def ValueCanBeAddedPredicate(cls, value, is_first_result):
        return False

    original_run_fn = story_runner.Run
    validPredicate = [False]

    def RunStub(test, story_set_module, finder_options, results,
                *args, **kwargs): # pylint: disable=unused-argument
      predicate = results._value_can_be_added_predicate
      valid = predicate == PredicateBenchmark.ValueCanBeAddedPredicate
      validPredicate[0] = valid

    story_runner.Run = RunStub

    try:
      options = options_for_unittests.GetCopy()
      options.output_formats = ['none']
      options.suppress_gtest_report = True
      parser = optparse.OptionParser()
      benchmark.AddCommandLineArgs(parser)
      options.MergeDefaultValues(parser.get_default_values())

      b = PredicateBenchmark(page.Page(url='about:blank'))
      b.Run(options)
    finally:
      story_runner.Run = original_run_fn

    self.assertTrue(validPredicate[0])
