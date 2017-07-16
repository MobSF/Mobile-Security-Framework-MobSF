# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import csv

from telemetry.internal.results import output_formatter
from telemetry.value import scalar
from telemetry.value import trace


class CsvPivotTableOutputFormatter(output_formatter.OutputFormatter):
  """Output the results as CSV suitable for reading into a spreadsheet.

  This will write a header row, and one row for each value. Each value row
  contains the value and unit, identifies the value (story_set, page, name), and
  (optionally) data from --output-trace-tag. This format matches what
  spreadsheet programs expect as input for a "pivot table".

  A trace tag (--output-trace-tag) can be used to tag each value, to allow
  easy combination of the resulting CSVs from several runs.
  If the trace_tag contains a comma, it will be written as several
  comma-separated values.

  This class only processes scalar values.
  """

  FIELDS = ['story_set', 'page', 'name', 'value', 'units', 'run_index']

  def __init__(self, output_stream, trace_tag=''):
    super(CsvPivotTableOutputFormatter, self).__init__(output_stream)
    self._trace_tag = trace_tag

  def Format(self, page_test_results):
    csv_writer = csv.writer(self.output_stream)

    # Observe trace_tag. Use comma to split up the trace tag.
    tag_values = self._trace_tag.split(',')
    tag_values = [x for x in tag_values if x] # filter empty list entries
    tag_headers = ['trace_tag_%d' % i for i in range(len(tag_values))]

    # Write header.
    csv_writer.writerow(self.FIELDS + tag_headers)

    # Write all values. Each row contains a value + page-level metadata.
    for run in page_test_results.all_page_runs:
      run_index = page_test_results.all_page_runs.index(run)
      page_dict = {
          'page': run.story.display_name,
          'story_set': run.story.page_set.Name(),
          'run_index': run_index,
      }
      for value in run.values:
        if (isinstance(value, scalar.ScalarValue) or
            isinstance(value, trace.TraceValue)):
          value_dict = {
            'name': value.name,
            'value': value.value,
            'units': value.units,
          }
          value_dict.update(page_dict.items())
          csv_writer.writerow(
              [value_dict[field] for field in self.FIELDS] + tag_values)
