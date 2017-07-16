# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import StringIO
import unittest

import mock

from telemetry import story
from telemetry.internal.results import csv_pivot_table_output_formatter
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


class CsvPivotTableOutputFormatterTest(unittest.TestCase):

  # The line separator used by CSV formatter.
  _LINE_SEPARATOR = '\r\n'

  def setUp(self):
    self._output = StringIO.StringIO()
    self._story_set = _MakeStorySet()
    self._results = page_test_results.PageTestResults()
    self._formatter = None
    self.MakeFormatter()

  def MakeFormatter(self, trace_tag=''):
    self._formatter = (
        csv_pivot_table_output_formatter.CsvPivotTableOutputFormatter(
            self._output, trace_tag))

  def SimulateBenchmarkRun(self, list_of_page_and_values):
    """Simulate one run of a benchmark, using the supplied values.

    Args:
      list_of_pages_and_values: a list of tuple (page, list of values)
    """
    for page, values in list_of_page_and_values:
      self._results.WillRunPage(page)
      for v in values:
        v.page = page
        self._results.AddValue(v)
      self._results.DidRunPage(page)

  def Format(self):
    self._formatter.Format(self._results)
    return self._output.getvalue()

  def testSimple(self):
    # Test a simple benchmark with only one value:
    self.SimulateBenchmarkRun([
        (self._story_set[0], [scalar.ScalarValue(
            None, 'foo', 'seconds', 3,
            improvement_direction=improvement_direction.DOWN)])])
    expected = self._LINE_SEPARATOR.join([
        'story_set,page,name,value,units,run_index',
        'story_set,http://www.foo.com/,foo,3,seconds,0',
        ''])

    self.assertEqual(expected, self.Format())

  @mock.patch('py_utils.cloud_storage.Insert')
  def testMultiplePagesAndValues(self, cs_insert_mock):
    cs_insert_mock.return_value = 'https://cloud_storage_url/foo'
    trace_value = trace.TraceValue(
        None, trace_data.CreateTraceDataFromRawData('{"traceEvents": []}'))
    trace_value.UploadToCloud(bucket='foo')
    self.SimulateBenchmarkRun([
        (self._story_set[0], [
            scalar.ScalarValue(
              None, 'foo', 'seconds', 4,
              improvement_direction=improvement_direction.DOWN)]),
        (self._story_set[1], [
            scalar.ScalarValue(
                None, 'foo', 'seconds', 3.4,
                improvement_direction=improvement_direction.DOWN),
            trace_value,
            scalar.ScalarValue(
                None, 'bar', 'km', 10,
                improvement_direction=improvement_direction.DOWN),
            scalar.ScalarValue(
                None, 'baz', 'count', 5,
                improvement_direction=improvement_direction.DOWN)])])

    # Parse CSV output into list of lists.
    csv_string = self.Format()
    lines = csv_string.split(self._LINE_SEPARATOR)
    values = [s.split(',') for s in lines[1:-1]]

    self.assertEquals(len(values), 5)  # We expect 5 value in total.
    self.assertEquals(len(set((v[1] for v in values))), 2)  # 2 pages.
    self.assertEquals(len(set((v[2] for v in values))), 4)  # 4 value names.
    self.assertEquals(values[2],
        ['story_set', 'http://www.bar.com/', 'trace',
         'https://cloud_storage_url/foo', '', '1'])

  def testTraceTag(self):
    self.MakeFormatter(trace_tag='date,option')
    self.SimulateBenchmarkRun([
        (self._story_set[0], [
            scalar.ScalarValue(
                None, 'foo', 'seconds', 3,
                improvement_direction=improvement_direction.DOWN),
            scalar.ScalarValue(
                None, 'bar', 'tons', 5,
                improvement_direction=improvement_direction.DOWN)])])
    output = self.Format().split(self._LINE_SEPARATOR)

    self.assertTrue(output[0].endswith(',trace_tag_0,trace_tag_1'))
    for line in output[1:-1]:
      self.assertTrue(line.endswith(',date,option'))
