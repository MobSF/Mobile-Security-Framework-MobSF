# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import StringIO
import unittest

from telemetry import benchmark
from telemetry import story
from telemetry.internal.results import chart_json_output_formatter
from telemetry.internal.results import page_test_results
from telemetry import page as page_module
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.value import trace
from tracing.trace_data import trace_data


def _MakeStorySet():
  ps = story.StorySet(base_dir=os.path.dirname(__file__))
  ps.AddStory(page_module.Page('http://www.foo.com/', ps, ps.base_dir))
  ps.AddStory(page_module.Page('http://www.bar.com/', ps, ps.base_dir))
  return ps

class ChartJsonTest(unittest.TestCase):
  def setUp(self):
    self._output = StringIO.StringIO()
    self._story_set = _MakeStorySet()
    self._benchmark_metadata = benchmark.BenchmarkMetadata(
        'benchmark_name', 'benchmark_description')
    self._formatter = chart_json_output_formatter.ChartJsonOutputFormatter(
        self._output, self._benchmark_metadata)

  def testOutputAndParse(self):
    results = page_test_results.PageTestResults()

    self._output.truncate(0)

    results.WillRunPage(self._story_set[0])
    v0 = scalar.ScalarValue(results.current_page, 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    results.AddValue(v0)
    results.DidRunPage(self._story_set[0])

    self._formatter.Format(results)
    d = json.loads(self._output.getvalue())
    self.assertIn('foo', d['charts'])

  def testOutputAndParseDisabled(self):
    self._formatter.FormatDisabled()
    d = json.loads(self._output.getvalue())
    self.assertEquals(d['benchmark_name'], 'benchmark_name')
    self.assertFalse(d['enabled'])

  def testAsChartDictSerializable(self):
    v0 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    page_specific_values = [v0]
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)
    json.dumps(d)

  def testAsChartDictBaseKeys(self):
    page_specific_values = []
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertEquals(d['format_version'], '0.1')
    self.assertEquals(d['next_version'], '0.2')
    self.assertEquals(d['benchmark_metadata']['name'], 'benchmark_name')
    self.assertEquals(d['benchmark_metadata']['description'],
                      'benchmark_description')
    self.assertEquals(d['benchmark_metadata']['type'], 'telemetry_benchmark')
    self.assertTrue(d['enabled'])

  def testAsChartDictNoDescription(self):
    page_specific_values = []
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        benchmark.BenchmarkMetadata('benchmark_name', ''),
        page_specific_values,
        summary_values)

    self.assertEquals('', d['benchmark_metadata']['description'])

  def testAsChartDictPageSpecificValuesSamePageWithInteractionRecord(self):
    v0 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN,
                            tir_label='MyIR')
    v1 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 4,
                            improvement_direction=improvement_direction.DOWN,
                            tir_label='MyIR')
    page_specific_values = [v0, v1]
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('MyIR@@foo' in d['charts'])
    self.assertTrue('http://www.foo.com/' in d['charts']['MyIR@@foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictPageSpecificValuesSamePageWithoutInteractionRecord(self):
    v0 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    v1 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 4,
                            improvement_direction=improvement_direction.DOWN)
    page_specific_values = [v0, v1]
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('foo' in d['charts'])
    self.assertTrue('http://www.foo.com/' in d['charts']['foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictPageSpecificValuesAndComputedSummaryWithTraceName(self):
    v0 = scalar.ScalarValue(self._story_set[0], 'foo.bar', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    v1 = scalar.ScalarValue(self._story_set[1], 'foo.bar', 'seconds', 4,
                            improvement_direction=improvement_direction.DOWN)
    page_specific_values = [v0, v1]
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('foo' in d['charts'])
    self.assertTrue('http://www.foo.com/' in d['charts']['foo'])
    self.assertTrue('http://www.bar.com/' in d['charts']['foo'])
    self.assertTrue('bar' in d['charts']['foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictPageSpecificValuesAndComputedSummaryWithoutTraceName(self):
    v0 = scalar.ScalarValue(self._story_set[0], 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    v1 = scalar.ScalarValue(self._story_set[1], 'foo', 'seconds', 4,
                            improvement_direction=improvement_direction.DOWN)
    page_specific_values = [v0, v1]
    summary_values = []

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('foo' in d['charts'])
    self.assertTrue('http://www.foo.com/' in d['charts']['foo'])
    self.assertTrue('http://www.bar.com/' in d['charts']['foo'])
    self.assertTrue('summary' in d['charts']['foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictSummaryValueWithTraceName(self):
    v0 = list_of_scalar_values.ListOfScalarValues(
        None, 'foo.bar', 'seconds', [3, 4],
        improvement_direction=improvement_direction.DOWN)
    page_specific_values = []
    summary_values = [v0]

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('bar' in d['charts']['foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictSummaryValueWithoutTraceName(self):
    v0 = list_of_scalar_values.ListOfScalarValues(
        None, 'foo', 'seconds', [3, 4],
        improvement_direction=improvement_direction.DOWN)
    page_specific_values = []
    summary_values = [v0]

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertTrue('summary' in d['charts']['foo'])
    self.assertTrue(d['enabled'])

  def testAsChartDictWithTraceValuesThatHasTirLabel(self):
    v = trace.TraceValue(self._story_set[0],
                         trace_data.CreateTraceDataFromRawData([{'test': 1}]))
    v.tir_label = 'background'

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values=[v],
        summary_values=[v])

    self.assertTrue('trace' in d['charts'])
    self.assertTrue('http://www.foo.com/' in d['charts']['trace'],
                    msg=d['charts']['trace'])
    self.assertTrue(d['enabled'])

  def testAsChartDictValueSmokeTest(self):
    v0 = list_of_scalar_values.ListOfScalarValues(
        None, 'foo.bar', 'seconds', [3, 4],
        improvement_direction=improvement_direction.DOWN)
    page_specific_values = []
    summary_values = [v0]

    d = chart_json_output_formatter.ResultsAsChartDict(
        self._benchmark_metadata,
        page_specific_values,
        summary_values)

    self.assertEquals(d['charts']['foo']['bar']['values'], [3, 4])
