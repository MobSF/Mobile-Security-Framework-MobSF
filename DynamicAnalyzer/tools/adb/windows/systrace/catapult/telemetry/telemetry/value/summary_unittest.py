# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import math
import os
import unittest

from telemetry import story
from telemetry.internal.results import page_test_results
from telemetry import page as page_module
from telemetry.value import failure
from telemetry.value import histogram
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.value import summary as summary_module


class TestBase(unittest.TestCase):
  def setUp(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page('http://www.baz.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page('http://www.foo.com/', story_set, story_set.base_dir))
    self.story_set = story_set

  @property
  def pages(self):
    return self.story_set.stories


class SummaryTest(TestBase):
  def testBasicSummary(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()

    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v1 = scalar.ScalarValue(page1, 'a', 'seconds', 7,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    v0_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)
    v1_list = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [7],
        improvement_direction=improvement_direction.UP)
    # Std is 0 because we only have one measurement per page.
    merged_value = list_of_scalar_values.ListOfScalarValues(
        None, 'a', 'seconds', [3, 7], std=0.0,
        improvement_direction=improvement_direction.UP)

    self.assertEquals(3, len(values))
    self.assertIn(v0_list, values)
    self.assertIn(v1_list, values)
    self.assertIn(merged_value, values)

  def testBasicSummaryWithOnlyOnePage(self):
    page0 = self.pages[0]

    results = page_test_results.PageTestResults()

    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    v0_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)
    merged_list = list_of_scalar_values.ListOfScalarValues(
        None, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)

    self.assertEquals(2, len(values))
    self.assertIn(v0_list, values)
    self.assertIn(merged_list, values)

  def testBasicSummaryNonuniformResults(self):
    page0 = self.pages[0]
    page1 = self.pages[1]
    page2 = self.pages[2]

    results = page_test_results.PageTestResults()
    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    v1 = scalar.ScalarValue(page0, 'b', 'seconds', 10,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v2 = scalar.ScalarValue(page1, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v2)
    v3 = scalar.ScalarValue(page1, 'b', 'seconds', 10,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v3)
    results.DidRunPage(page1)

    results.WillRunPage(page2)
    v4 = scalar.ScalarValue(page2, 'a', 'seconds', 7,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v4)
    # Note, page[2] does not report a 'b' metric.
    results.DidRunPage(page2)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    v0_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)
    v1_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'b', 'seconds', [10],
        improvement_direction=improvement_direction.UP)
    v2_list = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)
    v3_list = list_of_scalar_values.ListOfScalarValues(
        page1, 'b', 'seconds', [10],
        improvement_direction=improvement_direction.UP)
    v4_list = list_of_scalar_values.ListOfScalarValues(
        page2, 'a', 'seconds', [7],
        improvement_direction=improvement_direction.UP)
    # Std is 0 because we only have one measurement per page.
    a_summary = list_of_scalar_values.ListOfScalarValues(
        None, 'a', 'seconds', [3, 3, 7], std=0.0,
        improvement_direction=improvement_direction.UP)
    b_summary = list_of_scalar_values.ListOfScalarValues(
        None, 'b', 'seconds', [10, 10], std=0.0,
        improvement_direction=improvement_direction.UP)

    self.assertEquals(7, len(values))
    self.assertIn(v0_list, values)
    self.assertIn(v1_list, values)
    self.assertIn(v2_list, values)
    self.assertIn(v3_list, values)
    self.assertIn(v4_list, values)
    self.assertIn(a_summary, values)
    self.assertIn(b_summary, values)

  def testBasicSummaryPassAndFailPage(self):
    """If a page failed, only print summary for individual pages."""
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()
    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    v1 = failure.FailureValue.FromMessage(page0, 'message')
    results.AddValue(v1)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v2 = scalar.ScalarValue(page1, 'a', 'seconds', 7,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v2)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    v0_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3],
        improvement_direction=improvement_direction.UP)
    v2_list = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [7],
        improvement_direction=improvement_direction.UP)

    self.assertEquals(2, len(values))
    self.assertIn(v0_list, values)
    self.assertIn(v2_list, values)

  def testRepeatedPagesetOneIterationOnePageFails(self):
    """Page fails on one iteration, no averaged results should print."""
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()
    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v1 = scalar.ScalarValue(page1, 'a', 'seconds', 7,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    v2 = failure.FailureValue.FromMessage(page1, 'message')
    results.AddValue(v2)
    results.DidRunPage(page1)

    results.WillRunPage(page0)
    v3 = scalar.ScalarValue(page0, 'a', 'seconds', 4,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v3)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v4 = scalar.ScalarValue(page1, 'a', 'seconds', 8,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v4)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    page0_aggregated = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3, 4],
        improvement_direction=improvement_direction.UP)
    page1_aggregated = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [7, 8],
        improvement_direction=improvement_direction.UP)

    self.assertEquals(2, len(values))
    self.assertIn(page0_aggregated, values)
    self.assertIn(page1_aggregated, values)

  def testRepeatedPages(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()
    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page0)
    v2 = scalar.ScalarValue(page0, 'a', 'seconds', 4,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v2)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v1 = scalar.ScalarValue(page1, 'a', 'seconds', 7,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page1)

    results.WillRunPage(page1)
    v3 = scalar.ScalarValue(page1, 'a', 'seconds', 8,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v3)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    page0_aggregated = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [3, 4],
        improvement_direction=improvement_direction.UP)
    page1_aggregated = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [7, 8],
        improvement_direction=improvement_direction.UP)
    # Std is computed using pooled standard deviation.
    a_summary = list_of_scalar_values.ListOfScalarValues(
        None, 'a', 'seconds', [3, 4, 7, 8], std=math.sqrt(0.5),
        improvement_direction=improvement_direction.UP)

    self.assertEquals(3, len(values))
    self.assertIn(page0_aggregated, values)
    self.assertIn(page1_aggregated, values)
    self.assertIn(a_summary, values)

  def testPageRunsTwice(self):
    page0 = self.pages[0]

    results = page_test_results.PageTestResults()

    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'b', 'seconds', 2,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page0)
    v1 = scalar.ScalarValue(page0, 'b', 'seconds', 3,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page0)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    page0_aggregated = list_of_scalar_values.ListOfScalarValues(
        page0, 'b', 'seconds', [2, 3],
        improvement_direction=improvement_direction.UP)
    b_summary = list_of_scalar_values.ListOfScalarValues(
        None, 'b', 'seconds', [2, 3],
        improvement_direction=improvement_direction.UP)

    self.assertEquals(2, len(values))
    self.assertIn(page0_aggregated, values)
    self.assertIn(b_summary, values)

  def testListValue(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()

    results.WillRunPage(page0)
    v0 = list_of_scalar_values.ListOfScalarValues(
        page0, 'b', 'seconds', [2, 2],
        improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v1 = list_of_scalar_values.ListOfScalarValues(
        page1, 'b', 'seconds', [3, 3],
        improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    b_summary = list_of_scalar_values.ListOfScalarValues(
        None, 'b', 'seconds', [2, 2, 3, 3], std=0.0,
        improvement_direction=improvement_direction.UP)

    self.assertEquals(3, len(values))
    self.assertIn(v0, values)
    self.assertIn(v1, values)
    self.assertIn(b_summary, values)

  def testHistogram(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()
    results.WillRunPage(page0)
    v0 = histogram.HistogramValue(
        page0, 'a', 'units',
        raw_value_json='{"buckets": [{"low": 1, "high": 2, "count": 1}]}',
        important=False, improvement_direction=improvement_direction.UP)
    results.AddValue(v0)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v1 = histogram.HistogramValue(
        page1, 'a', 'units',
        raw_value_json='{"buckets": [{"low": 2, "high": 3, "count": 1}]}',
        important=False, improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page1)

    summary = summary_module.Summary(results.all_page_specific_values)
    values = summary.interleaved_computed_per_page_values_and_summaries

    self.assertEquals(2, len(values))
    self.assertIn(v0, values)
    self.assertIn(v1, values)

  def testSummaryUsesKeyFunc(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    results = page_test_results.PageTestResults()

    results.WillRunPage(page0)
    v0 = scalar.ScalarValue(page0, 'a', 'seconds', 20,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v0)

    v1 = scalar.ScalarValue(page0, 'b', 'seconds', 42,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v1)
    results.DidRunPage(page0)

    results.WillRunPage(page1)
    v2 = scalar.ScalarValue(page1, 'a', 'seconds', 20,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v2)

    v3 = scalar.ScalarValue(page1, 'b', 'seconds', 42,
                            improvement_direction=improvement_direction.UP)
    results.AddValue(v3)
    results.DidRunPage(page1)

    summary = summary_module.Summary(
        results.all_page_specific_values,
        key_func=lambda v: True)
    values = summary.interleaved_computed_per_page_values_and_summaries

    v0_list = list_of_scalar_values.ListOfScalarValues(
        page0, 'a', 'seconds', [20, 42],
        improvement_direction=improvement_direction.UP)
    v2_list = list_of_scalar_values.ListOfScalarValues(
        page1, 'a', 'seconds', [20, 42],
        improvement_direction=improvement_direction.UP)
    # Std is computed using pooled standard deviation.
    merged_value = list_of_scalar_values.ListOfScalarValues(
        None, 'a', 'seconds', [20, 42, 20, 42], std=math.sqrt(242.0),
        improvement_direction=improvement_direction.UP)

    self.assertEquals(3, len(values))
    self.assertIn(v0_list, values)
    self.assertIn(v2_list, values)
    self.assertIn(merged_value, values)
