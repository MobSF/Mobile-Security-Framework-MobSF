# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import json
import logging
import os
import re

from telemetry.core import util
from telemetry import decorators
from telemetry.internal.results import chart_json_output_formatter
from telemetry.internal.results import output_formatter
from telemetry import value as value_module
from telemetry.value import list_of_scalar_values


_TEMPLATE_HTML_PATH = os.path.join(
    util.GetTelemetryDir(), 'support', 'html_output', 'results-template.html')
_JS_PLUGINS = [os.path.join('flot', 'jquery.flot.min.js'),
               os.path.join('WebKit', 'PerformanceTests', 'resources',
                            'jquery.tablesorter.min.js'),
               os.path.join('WebKit', 'PerformanceTests', 'resources',
                            'statistics.js')]
_UNIT_JSON = os.path.join(
    util.GetTelemetryDir(), 'telemetry', 'value', 'unit-info.json')


def _DatetimeInEs5CompatibleFormat(dt):
  return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')


def _ShortDatetimeInEs5CompatibleFormat(dt):
  return dt.strftime('%Y-%m-%d %H:%M:%S')


class LegacyHtmlOutputFormatter(output_formatter.OutputFormatter):
  def __init__(self, output_stream, metadata, reset_results, browser_type,
               results_label=None):
    super(LegacyHtmlOutputFormatter, self).__init__(output_stream)
    self._metadata = metadata
    self._reset_results = reset_results
    self._build_time = self._GetBuildTime()
    self._combined_results = []
    if results_label:
      self._results_label = results_label
    else:
      self._results_label = '%s (%s)' % (
          metadata.name, _ShortDatetimeInEs5CompatibleFormat(self._build_time))
    self._result = {
        'buildTime': _DatetimeInEs5CompatibleFormat(self._build_time),
        'label': self._results_label,
        'platform': browser_type,
        'tests': {}
        }

  def _GetBuildTime(self):
    return datetime.datetime.utcnow()

  def _GetHtmlTemplate(self):
    with open(_TEMPLATE_HTML_PATH) as f:
      return f.read()

  def _GetPlugins(self):
    plugins = ''
    for p in _JS_PLUGINS:
      with open(os.path.join(util.GetTelemetryThirdPartyDir(), p)) as f:
        plugins += f.read()
    return plugins

  def _GetUnitJson(self):
    with open(_UNIT_JSON) as f:
      return f.read()

  def _ReadExistingResults(self, output_stream):
    results_html = output_stream.read()
    if self._reset_results or not results_html:
      return []
    m = re.search(
        '^<script id="results-json" type="application/json">(.*?)</script>$',
        results_html, re.MULTILINE | re.DOTALL)
    if not m:
      logging.warn('Failed to extract previous results from HTML output')
      return []
    return json.loads(m.group(1))[:512]

  def _SaveResults(self, results):
    self._output_stream.seek(0)
    self._output_stream.write(unicode(results, 'utf-8'))
    self._output_stream.truncate()

  def _PrintPerfResult(self, measurement, trace, values, units,
                       result_type='default', std=None):
    metric_name = measurement
    if trace != measurement:
      metric_name += '.' + trace
    self._result['tests'].setdefault(self._test_name, {})
    self._result['tests'][self._test_name].setdefault('metrics', {})
    metric_data = {
        'current': values,
        'units': units,
        'important': result_type == 'default'
        }
    if std is not None:
      metric_data['std'] = std
    self._result['tests'][self._test_name]['metrics'][metric_name] = metric_data

  def _TranslateChartJson(self, chart_json_dict):
    dummy_dict = dict()

    for chart_name, traces in chart_json_dict['charts'].iteritems():
      for trace_name, value_dict in traces.iteritems():
        # TODO(eakuefner): refactor summarization so we don't have to jump
        # through hoops like this.
        if 'page_id' in value_dict:
          del value_dict['page_id']
          result_type = 'nondefault'
        else:
          result_type = 'default'

        # Note: we explicitly ignore TraceValues because Buildbot did.
        if value_dict['type'] == 'trace':
          continue
        value = value_module.Value.FromDict(value_dict, dummy_dict)

        perf_value = value.GetBuildbotValue()

        if '@@' in chart_name:
          chart_name_to_print = '%s-%s' % tuple(chart_name.split('@@'))
        else:
          chart_name_to_print = str(chart_name)

        if trace_name == 'summary':
          trace_name = chart_name_to_print

        std = None
        if isinstance(value, list_of_scalar_values.ListOfScalarValues):
          std = value.std

        self._PrintPerfResult(chart_name_to_print, trace_name, perf_value,
                              value.units, result_type, std)

  @property
  def _test_name(self):
    return self._metadata.name

  def GetResults(self):
    return self._result

  def GetCombinedResults(self):
    return self._combined_results

  @decorators.Deprecated(
      2017, 1, 7, 'Use HtmlOutputFormatter and file any issues on GitHub at '
      'https://github.com/catapult-project/catapult/issues/new?labels=Results2&title=[Results2]')
  def Format(self, page_test_results):
    chart_json_dict = chart_json_output_formatter.ResultsAsChartDict(
        self._metadata, page_test_results.all_page_specific_values,
        page_test_results.all_summary_values)

    self._TranslateChartJson(chart_json_dict)
    self._PrintPerfResult('telemetry_page_measurement_results', 'num_failed',
                          [len(page_test_results.failures)], 'count',
                          'unimportant')

    self._combined_results = self._ReadExistingResults(self._output_stream)
    self._combined_results.append(self._result)

    html = self._GetHtmlTemplate()
    html = html.replace('%json_results%', json.dumps(self.GetCombinedResults()))
    html = html.replace('%json_units%', self._GetUnitJson())
    html = html.replace('%plugins%', self._GetPlugins())
    self._SaveResults(html)
