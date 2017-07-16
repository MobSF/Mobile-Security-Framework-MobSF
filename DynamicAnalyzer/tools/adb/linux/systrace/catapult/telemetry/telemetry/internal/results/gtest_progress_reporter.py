# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

from telemetry.internal.results import progress_reporter
from telemetry.value import failure
from telemetry.value import skip


class GTestProgressReporter(progress_reporter.ProgressReporter):
  """A progress reporter that outputs the progress report in gtest style.

  Be careful each print should only handle one string. Otherwise, the output
  might be interrupted by Chrome logging, and the output interpretation might
  be incorrect. For example:
      print >> self._output_stream, "[ OK ]", testname
  should be written as
      print >> self._output_stream, "[ OK ] %s" % testname
  """

  def __init__(self, output_stream, output_skipped_tests_summary=False):
    super(GTestProgressReporter, self).__init__()
    self._output_stream = output_stream
    self._timestamp = None
    self._output_skipped_tests_summary = output_skipped_tests_summary

  def _GetMs(self):
    assert self._timestamp is not None, 'Did not call WillRunPage.'
    return (time.time() - self._timestamp) * 1000

  def _GenerateGroupingKeyString(self, page):
    return '' if not page.grouping_keys else '@%s' % str(page.grouping_keys)

  def DidAddValue(self, value):
    super(GTestProgressReporter, self).DidAddValue(value)
    if isinstance(value, failure.FailureValue):
      print >> self._output_stream, failure.GetStringFromExcInfo(
          value.exc_info)
      self._output_stream.flush()
    elif isinstance(value, skip.SkipValue):
      print >> self._output_stream, '===== SKIPPING TEST %s: %s =====' % (
          value.page.display_name, value.reason)
    # TODO(chrishenry): Consider outputting metric values as well. For
    # e.g., it can replace BuildbotOutputFormatter in
    # --output-format=html, which we used only so that users can grep
    # the results without opening results.html.

  def WillRunPage(self, page_test_results):
    super(GTestProgressReporter, self).WillRunPage(page_test_results)
    print >> self._output_stream, '[ RUN      ] %s%s' % (
        page_test_results.current_page.display_name,
        self._GenerateGroupingKeyString(page_test_results.current_page))

    self._output_stream.flush()
    self._timestamp = time.time()

  def DidRunPage(self, page_test_results):
    super(GTestProgressReporter, self).DidRunPage(page_test_results)
    page = page_test_results.current_page
    if page_test_results.current_page_run.failed:
      print >> self._output_stream, '[  FAILED  ] %s%s (%0.f ms)' % (
          page.display_name,
          self._GenerateGroupingKeyString(page_test_results.current_page),
          self._GetMs())
    else:
      print >> self._output_stream, '[       OK ] %s%s (%0.f ms)' % (
          page.display_name,
          self._GenerateGroupingKeyString(page_test_results.current_page),
          self._GetMs())
    self._output_stream.flush()

  def DidFinishAllTests(self, page_test_results):
    super(GTestProgressReporter, self).DidFinishAllTests(page_test_results)
    successful_runs = []
    failed_runs = []
    for run in page_test_results.all_page_runs:
      if run.failed:
        failed_runs.append(run)
      else:
        successful_runs.append(run)

    unit = 'test' if len(successful_runs) == 1 else 'tests'
    print >> self._output_stream, '[  PASSED  ] %d %s.' % (
        (len(successful_runs), unit))
    if len(failed_runs) > 0:
      unit = 'test' if len(failed_runs) == 1 else 'tests'
      print >> self._output_stream, '[  FAILED  ] %d %s, listed below:' % (
          (len(page_test_results.failures), unit))
      for failed_run in failed_runs:
        print >> self._output_stream, '[  FAILED  ]  %s%s' % (
            failed_run.story.display_name,
            self._GenerateGroupingKeyString(failed_run.story))
      print >> self._output_stream
      count = len(failed_runs)
      unit = 'TEST' if count == 1 else 'TESTS'
      print >> self._output_stream, '%d FAILED %s' % (count, unit)
    print >> self._output_stream

    if self._output_skipped_tests_summary:
      if len(page_test_results.skipped_values) > 0:
        print >> self._output_stream, 'Skipped pages:\n%s\n' % ('\n'.join(
            v.page.display_name for v in page_test_results.skipped_values))

    self._output_stream.flush()
