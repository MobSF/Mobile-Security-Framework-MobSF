# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json
import os
import shutil
import StringIO
import tempfile
import unittest

from telemetry import story
from telemetry import benchmark
from telemetry.internal.results import json_output_formatter
from telemetry.internal.results import page_test_results
from telemetry import page as page_module
from telemetry.value import improvement_direction
from telemetry.value import scalar
from telemetry.value import trace
from tracing.trace_data import trace_data


def _MakeStorySet():
  story_set = story.StorySet(base_dir=os.path.dirname(__file__))
  story_set.AddStory(
      page_module.Page('http://www.foo.com/', story_set, story_set.base_dir))
  story_set.AddStory(
      page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
  return story_set

def _HasPage(pages, page):
  return pages.get(page.id, None) != None

def _HasValueNamed(values, name):
  return len([x for x in values if x['name'] == name]) == 1

class JsonOutputFormatterTest(unittest.TestCase):
  def setUp(self):
    self._output = StringIO.StringIO()
    self._story_set = _MakeStorySet()
    self._formatter = json_output_formatter.JsonOutputFormatter(
        self._output,
        benchmark.BenchmarkMetadata('benchmark_name'))

  def testOutputAndParse(self):
    results = page_test_results.PageTestResults()

    self._output.truncate(0)

    results.WillRunPage(self._story_set[0])
    v0 = scalar.ScalarValue(results.current_page, 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    results.AddValue(v0)
    results.DidRunPage(self._story_set[0])

    self._formatter.Format(results)
    json.loads(self._output.getvalue())

  def testAsDictBaseKeys(self):
    results = page_test_results.PageTestResults()
    d = json_output_formatter.ResultsAsDict(results,
        self._formatter.benchmark_metadata)

    self.assertEquals(d['format_version'], '0.2')
    self.assertEquals(d['next_version'], '0.3')
    self.assertEquals(d['benchmark_metadata']['name'], 'benchmark_name')

  def testAsDictWithOnePage(self):
    results = page_test_results.PageTestResults()
    results.WillRunPage(self._story_set[0])
    v0 = scalar.ScalarValue(results.current_page, 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    results.AddValue(v0)
    results.DidRunPage(self._story_set[0])

    d = json_output_formatter.ResultsAsDict(results,
        self._formatter.benchmark_metadata)

    self.assertTrue(_HasPage(d['pages'], self._story_set[0]))
    self.assertTrue(_HasValueNamed(d['per_page_values'], 'foo'))

  def testAsDictWithTraceValue(self):
    tempdir = tempfile.mkdtemp()
    try:
      results = page_test_results.PageTestResults()
      results.WillRunPage(self._story_set[0])
      v0 = trace.TraceValue(
          results.current_page,
          trace_data.CreateTraceDataFromRawData([{'event': 'test'}]))
      results.AddValue(v0)
      results.DidRunPage(self._story_set[0])
      results._SerializeTracesToDirPath(tempdir)
      d = json_output_formatter.ResultsAsDict(results,
          self._formatter.benchmark_metadata)

      self.assertTrue(_HasPage(d['pages'], self._story_set[0]))
      self.assertTrue(_HasValueNamed(d['per_page_values'], 'trace'))
      self.assertEquals(len(d['files']), 1)
      output_trace_path = d['files'].values()[0]
      self.assertTrue(output_trace_path.startswith(tempdir))
      self.assertTrue(os.path.exists(output_trace_path))
    finally:
      shutil.rmtree(tempdir)

  def testAsDictWithTwoPages(self):
    results = page_test_results.PageTestResults()
    results.WillRunPage(self._story_set[0])
    v0 = scalar.ScalarValue(results.current_page, 'foo', 'seconds', 3,
                            improvement_direction=improvement_direction.DOWN)
    results.AddValue(v0)
    results.DidRunPage(self._story_set[0])

    results.WillRunPage(self._story_set[1])
    v1 = scalar.ScalarValue(results.current_page, 'bar', 'seconds', 4,
                            improvement_direction=improvement_direction.DOWN)
    results.AddValue(v1)
    results.DidRunPage(self._story_set[1])

    d = json_output_formatter.ResultsAsDict(results,
        self._formatter.benchmark_metadata)

    self.assertTrue(_HasPage(d['pages'], self._story_set[0]))
    self.assertTrue(_HasPage(d['pages'], self._story_set[1]))
    self.assertTrue(_HasValueNamed(d['per_page_values'], 'foo'))
    self.assertTrue(_HasValueNamed(d['per_page_values'], 'bar'))

  def testAsDictWithSummaryValueOnly(self):
    results = page_test_results.PageTestResults()
    v = scalar.ScalarValue(None, 'baz', 'seconds', 5,
                           improvement_direction=improvement_direction.DOWN)
    results.AddSummaryValue(v)

    d = json_output_formatter.ResultsAsDict(results,
        self._formatter.benchmark_metadata)

    self.assertFalse(d['pages'])
    self.assertTrue(_HasValueNamed(d['summary_values'], 'baz'))
