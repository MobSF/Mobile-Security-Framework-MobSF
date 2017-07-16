# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import json
import logging
import os
import tempfile

from py_utils import cloud_storage

from telemetry.internal.results import chart_json_output_formatter
from telemetry.internal.results import output_formatter

from tracing import results_renderer
from tracing.value import convert_chart_json


class HtmlOutputFormatter(output_formatter.OutputFormatter):
  def __init__(self, output_stream, metadata, reset_results,
               upload_bucket=None):
    super(HtmlOutputFormatter, self).__init__(output_stream)
    self._metadata = metadata
    self._upload_bucket = upload_bucket
    self._reset_results = reset_results

  def _ConvertChartJson(self, page_test_results):
    chart_json = chart_json_output_formatter.ResultsAsChartDict(
        self._metadata, page_test_results.all_page_specific_values,
        page_test_results.all_summary_values)
    info = page_test_results.telemetry_info
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

  def Format(self, page_test_results):
    histograms = page_test_results.value_set
    if not histograms:
      histograms = self._ConvertChartJson(page_test_results)

    results_renderer.RenderHTMLView(histograms,
        self._output_stream, self._reset_results)
    file_path = os.path.abspath(self._output_stream.name)
    if self._upload_bucket:
      remote_path = ('html-results/results-%s' %
                     datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
      try:
        url = cloud_storage.Insert(self._upload_bucket, remote_path, file_path)
        print 'View HTML results online at %s' % url
      except cloud_storage.PermissionError as e:
        logging.error('Cannot upload profiling files to cloud storage due to '
                      ' permission error: %s' % e.message)
