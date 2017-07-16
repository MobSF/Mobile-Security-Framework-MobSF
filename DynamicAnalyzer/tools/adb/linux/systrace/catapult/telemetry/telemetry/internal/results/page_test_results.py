# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import copy
import datetime
import json
import logging
import os
import random
import sys
import tempfile
import traceback

from py_utils import cloud_storage  # pylint: disable=import-error

from telemetry import value as value_module
from telemetry.internal.results import chart_json_output_formatter
from telemetry.internal.results import json_output_formatter
from telemetry.internal.results import progress_reporter as reporter_module
from telemetry.internal.results import story_run
from telemetry.value import failure
from telemetry.value import skip
from telemetry.value import trace

from tracing.value import convert_chart_json

class TelemetryInfo(object):
  def __init__(self):
    self._benchmark_name = None
    self._benchmark_start_ms = None
    self._label = None
    self._story_display_name = ''
    self._story_grouping_keys = {}
    self._storyset_repeat_counter = 0

  @property
  def benchmark_name(self):
    return self._benchmark_name

  @benchmark_name.setter
  def benchmark_name(self, benchmark_name):
    assert self.benchmark_name is None, (
      'benchmark_name must be set exactly once')
    self._benchmark_name = benchmark_name

  @property
  def benchmark_start_ms(self):
    return self._benchmark_start_ms

  @benchmark_start_ms.setter
  def benchmark_start_ms(self, benchmark_start_ms):
    assert self.benchmark_start_ms is None, (
      'benchmark_start_ms must be set exactly once')
    self._benchmark_start_ms = benchmark_start_ms

  @property
  def label(self):
    return self._label

  @label.setter
  def label(self, label):
    assert self.label is None, 'label cannot be set more than once'
    self._label = label

  @property
  def story_display_name(self):
    return self._story_display_name

  @property
  def story_grouping_keys(self):
    return self._story_grouping_keys

  @property
  def storyset_repeat_counter(self):
    return self._storyset_repeat_counter

  def WillRunStory(self, story, storyset_repeat_counter):
    self._story_display_name = story.display_name
    if story.grouping_keys:
      self._story_grouping_keys = story.grouping_keys
    self._storyset_repeat_counter = storyset_repeat_counter

  def AsDict(self):
    assert self.benchmark_name is not None, (
        'benchmark_name must be set exactly once')
    assert self.benchmark_start_ms is not None, (
        'benchmark_start_ms must be set exactly once')
    d = {}
    d['benchmarkName'] = self.benchmark_name
    d['benchmarkStartMs'] = self.benchmark_start_ms
    if self.label:
      d['label'] = self.label
    d['storyDisplayName'] = self.story_display_name
    d['storyGroupingKeys'] = self.story_grouping_keys
    d['storysetRepeatCounter'] = self.storyset_repeat_counter
    return d


class PageTestResults(object):
  def __init__(self, output_formatters=None,
               progress_reporter=None, trace_tag='', output_dir=None,
               value_can_be_added_predicate=lambda v, is_first: True,
               benchmark_enabled=True):
    """
    Args:
      output_formatters: A list of output formatters. The output
          formatters are typically used to format the test results, such
          as CsvPivotTableOutputFormatter, which output the test results as CSV.
      progress_reporter: An instance of progress_reporter.ProgressReporter,
          to be used to output test status/results progressively.
      trace_tag: A string to append to the buildbot trace name. Currently only
          used for buildbot.
      output_dir: A string specified the directory where to store the test
          artifacts, e.g: trace, videos,...
      value_can_be_added_predicate: A function that takes two arguments:
          a value.Value instance (except failure.FailureValue, skip.SkipValue
          or trace.TraceValue) and a boolean (True when the value is part of
          the first result for the story). It returns True if the value
          can be added to the test results and False otherwise.
    """
    # TODO(chrishenry): Figure out if trace_tag is still necessary.

    super(PageTestResults, self).__init__()
    self._progress_reporter = (
        progress_reporter if progress_reporter is not None
        else reporter_module.ProgressReporter())
    self._output_formatters = (
        output_formatters if output_formatters is not None else [])
    self._trace_tag = trace_tag
    self._output_dir = output_dir
    self._value_can_be_added_predicate = value_can_be_added_predicate

    self._current_page_run = None
    self._all_page_runs = []
    self._all_stories = set()
    self._representative_value_for_each_value_name = {}
    self._all_summary_values = []
    self._serialized_trace_file_ids_to_paths = {}
    self._pages_to_profiling_files = collections.defaultdict(list)
    self._pages_to_profiling_files_cloud_url = collections.defaultdict(list)

    # You'd expect this to be a set(), but Values are dictionaries, which are
    # unhashable. We could wrap Values with custom __eq/hash__, but we don't
    # actually need set-ness in python.
    self._value_set = []

    self._telemetry_info = TelemetryInfo()

    # State of the benchmark this set of results represents.
    self._benchmark_enabled = benchmark_enabled

  @property
  def telemetry_info(self):
    return self._telemetry_info

  @property
  def value_set(self):
    return self._value_set

  def AsHistogramDicts(self, benchmark_metadata):
    if self.value_set:
      return self.value_set
    chart_json = chart_json_output_formatter.ResultsAsChartDict(
        benchmark_metadata, self.all_page_specific_values,
        self.all_summary_values)
    info = self.telemetry_info
    chart_json['label'] = info.label
    chart_json['benchmarkStartMs'] = info.benchmark_start_ms

    file_descriptor, chart_json_path = tempfile.mkstemp()
    os.close(file_descriptor)
    json.dump(chart_json, file(chart_json_path, 'w'))

    vinn_result = convert_chart_json.ConvertChartJson(chart_json_path)

    os.remove(chart_json_path)

    if vinn_result.returncode != 0:
      logging.error('Error converting chart json to Histograms:\n' +
          vinn_result.stdout)
      return []
    return json.loads(vinn_result.stdout)

  def __copy__(self):
    cls = self.__class__
    result = cls.__new__(cls)
    for k, v in self.__dict__.items():
      if isinstance(v, collections.Container):
        v = copy.copy(v)
      setattr(result, k, v)
    return result

  @property
  def pages_to_profiling_files(self):
    return self._pages_to_profiling_files

  @property
  def serialized_trace_file_ids_to_paths(self):
    return self._serialized_trace_file_ids_to_paths

  @property
  def pages_to_profiling_files_cloud_url(self):
    return self._pages_to_profiling_files_cloud_url

  @property
  def all_page_specific_values(self):
    values = []
    for run in self._all_page_runs:
      values += run.values
    if self._current_page_run:
      values += self._current_page_run.values
    return values

  @property
  def all_summary_values(self):
    return self._all_summary_values

  @property
  def current_page(self):
    assert self._current_page_run, 'Not currently running test.'
    return self._current_page_run.story

  @property
  def current_page_run(self):
    assert self._current_page_run, 'Not currently running test.'
    return self._current_page_run

  @property
  def all_page_runs(self):
    return self._all_page_runs

  @property
  def pages_that_succeeded(self):
    """Returns the set of pages that succeeded."""
    pages = set(run.story for run in self.all_page_runs)
    pages.difference_update(self.pages_that_failed)
    return pages

  @property
  def pages_that_failed(self):
    """Returns the set of failed pages."""
    failed_pages = set()
    for run in self.all_page_runs:
      if run.failed:
        failed_pages.add(run.story)
    return failed_pages

  @property
  def failures(self):
    values = self.all_page_specific_values
    return [v for v in values if isinstance(v, failure.FailureValue)]

  @property
  def skipped_values(self):
    values = self.all_page_specific_values
    return [v for v in values if isinstance(v, skip.SkipValue)]

  def _GetStringFromExcInfo(self, err):
    return ''.join(traceback.format_exception(*err))

  def CleanUp(self):
    """Clean up any TraceValues contained within this results object."""
    for run in self._all_page_runs:
      for v in run.values:
        if isinstance(v, trace.TraceValue):
          v.CleanUp()
          run.values.remove(v)

  def __enter__(self):
    return self

  def __exit__(self, _, __, ___):
    self.CleanUp()

  def WillRunPage(self, page, storyset_repeat_counter=0):
    assert not self._current_page_run, 'Did not call DidRunPage.'
    self._current_page_run = story_run.StoryRun(page)
    self._progress_reporter.WillRunPage(self)
    self.telemetry_info.WillRunStory(
        page, storyset_repeat_counter)

  def DidRunPage(self, page):  # pylint: disable=unused-argument
    """
    Args:
      page: The current page under test.
    """
    assert self._current_page_run, 'Did not call WillRunPage.'
    self._progress_reporter.DidRunPage(self)
    self._all_page_runs.append(self._current_page_run)
    self._all_stories.add(self._current_page_run.story)
    self._current_page_run = None

  def AddValue(self, value):
    assert self._current_page_run, 'Not currently running test.'
    assert self._benchmark_enabled, 'Cannot add value to disabled results'
    self._ValidateValue(value)
    is_first_result = (
      self._current_page_run.story not in self._all_stories)

    story_keys = self._current_page_run.story.grouping_keys

    if story_keys:
      for k, v in story_keys.iteritems():
        assert k not in value.grouping_keys, (
            'Tried to add story grouping key ' + k + ' already defined by ' +
            'value')
        value.grouping_keys[k] = v

      # We sort by key name to make building the tir_label deterministic.
      story_keys_label = '_'.join(v for _, v in sorted(story_keys.iteritems()))
      if value.tir_label:
        assert value.tir_label == story_keys_label, (
            'Value has an explicit tir_label (%s) that does not match the '
            'one computed from story_keys (%s)' % (value.tir_label, story_keys))
      else:
        value.tir_label = story_keys_label

    if not (isinstance(value, skip.SkipValue) or
            isinstance(value, failure.FailureValue) or
            isinstance(value, trace.TraceValue) or
            self._value_can_be_added_predicate(value, is_first_result)):
      return
    # TODO(eakuefner/chrishenry): Add only one skip per pagerun assert here
    self._current_page_run.AddValue(value)
    self._progress_reporter.DidAddValue(value)

  def AddProfilingFile(self, page, file_handle):
    self._pages_to_profiling_files[page].append(file_handle)

  def AddSummaryValue(self, value):
    assert value.page is None
    self._ValidateValue(value)
    self._all_summary_values.append(value)

  def _ValidateValue(self, value):
    assert isinstance(value, value_module.Value)
    if value.name not in self._representative_value_for_each_value_name:
      self._representative_value_for_each_value_name[value.name] = value
    representative_value = self._representative_value_for_each_value_name[
        value.name]
    assert value.IsMergableWith(representative_value)

  def PrintSummary(self):
    if self._benchmark_enabled:
      self._progress_reporter.DidFinishAllTests(self)

      # Only serialize the trace if output_format is json.
      if (self._output_dir and
          any(isinstance(o, json_output_formatter.JsonOutputFormatter)
              for o in self._output_formatters)):
        self._SerializeTracesToDirPath(self._output_dir)
      for output_formatter in self._output_formatters:
        output_formatter.Format(self)
        output_formatter.PrintViewResults()
    else:
      for output_formatter in self._output_formatters:
        output_formatter.FormatDisabled()

  def FindValues(self, predicate):
    """Finds all values matching the specified predicate.

    Args:
      predicate: A function that takes a Value and returns a bool.
    Returns:
      A list of values matching |predicate|.
    """
    values = []
    for value in self.all_page_specific_values:
      if predicate(value):
        values.append(value)
    return values

  def FindPageSpecificValuesForPage(self, page, value_name):
    return self.FindValues(lambda v: v.page == page and v.name == value_name)

  def FindAllPageSpecificValuesNamed(self, value_name):
    return self.FindValues(lambda v: v.name == value_name)

  def FindAllPageSpecificValuesFromIRNamed(self, tir_label, value_name):
    return self.FindValues(lambda v: v.name == value_name
                           and v.tir_label == tir_label)

  def FindAllTraceValues(self):
    return self.FindValues(lambda v: isinstance(v, trace.TraceValue))

  def _SerializeTracesToDirPath(self, dir_path):
    """ Serialize all trace values to files in dir_path and return a list of
    file handles to those files. """
    for value in self.FindAllTraceValues():
      fh = value.Serialize(dir_path)
      self._serialized_trace_file_ids_to_paths[fh.id] = fh.GetAbsPath()

  def UploadTraceFilesToCloud(self, bucket):
    for value in self.FindAllTraceValues():
      value.UploadToCloud(bucket)

  def UploadProfilingFilesToCloud(self, bucket):
    for page, file_handle_list in self._pages_to_profiling_files.iteritems():
      for file_handle in file_handle_list:
        remote_path = ('profiler-file-id_%s-%s%-d%s' % (
            file_handle.id,
            datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
            random.randint(1, 100000),
            file_handle.extension))
        try:
          cloud_url = cloud_storage.Insert(
              bucket, remote_path, file_handle.GetAbsPath())
          sys.stderr.write(
              'View generated profiler files online at %s for page %s\n' %
              (cloud_url, page.display_name))
          self._pages_to_profiling_files_cloud_url[page].append(cloud_url)
        except cloud_storage.PermissionError as e:
          logging.error('Cannot upload profiling files to cloud storage due to '
                        ' permission error: %s' % e.message)
