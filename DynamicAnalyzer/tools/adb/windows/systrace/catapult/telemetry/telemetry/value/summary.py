# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from collections import defaultdict

from telemetry.value import failure
from telemetry.value import merge_values
from telemetry.value import skip


class Summary(object):
  """Computes summary values from the per-page-run values produced by a test.

  Some telemetry benchmark repeat a number of times in order to get a reliable
  measurement. The test does not have to handle merging of these runs:
  summarizer does it for you.

  For instance, if two pages run, 3 and 1 time respectively:
      ScalarValue(page1, 'foo', units='ms', 1)
      ScalarValue(page1, 'foo', units='ms', 1)
      ScalarValue(page1, 'foo', units='ms', 1)
      ScalarValue(page2, 'foo', units='ms', 2)

  Then summarizer will produce two sets of values. First,
  computed_per_page_values:
      [
         ListOfScalarValues(page1, 'foo', units='ms', [1,1,1])],
         ListOfScalarValues(page2, 'foo', units='ms', [2])]
      ]

  In addition, it will produce a summary value:
      [
         ListOfScalarValues(page=None, 'foo', units='ms', [1,1,1,2])]
      ]

  """
  def __init__(self, all_page_specific_values,
               key_func=merge_values.DefaultKeyFunc):
    had_failures = any(isinstance(v, failure.FailureValue) for v in
        all_page_specific_values)
    self.had_failures = had_failures
    self._computed_per_page_values = []
    self._computed_summary_values = []
    self._interleaved_computed_per_page_values_and_summaries = []
    self._key_func = key_func
    self._ComputePerPageValues(all_page_specific_values)

  @property
  def computed_per_page_values(self):
    return self._computed_per_page_values

  @property
  def computed_summary_values(self):
    return self._computed_summary_values

  @property
  def interleaved_computed_per_page_values_and_summaries(self):
    """Returns the computed per page values and summary values interleaved.

    All the results for a given name are printed together. First per page
    values, then summary values.

    """
    return self._interleaved_computed_per_page_values_and_summaries

  def _ComputePerPageValues(self, all_page_specific_values):
    all_successful_page_values = [
        v for v in all_page_specific_values if not (isinstance(
            v, failure.FailureValue) or isinstance(v, skip.SkipValue))]

    # We will later need to determine how many values were originally created
    # for each value name, to apply a workaround meant to clean up the printf
    # output.
    num_successful_pages_for_key = defaultdict(int)
    for v in all_successful_page_values:
      num_successful_pages_for_key[self._key_func(v)] += 1

    # By here, due to page repeat options, all_values_from_successful_pages
    # contains values of the same name not only from mulitple pages, but also
    # from the same name. So even if, for instance, only one page ran, it may
    # have run twice, producing two 'x' values.
    #
    # So, get rid of the repeated pages by merging.
    merged_page_values = merge_values.MergeLikeValuesFromSamePage(
        all_successful_page_values, self._key_func)

    # Now we have a bunch of values, but there is only one value_name per page.
    # Suppose page1 and page2 ran, producing values x and y. We want to print
    #    x for page1
    #    x for page2
    #    x for page1, page2 combined
    #
    #    y for page1
    #    y for page2
    #    y for page1, page2 combined
    #
    # We already have the x values in the values array. But, we will need
    # them indexable by summary key.
    #
    # The following dict maps summary_key -> list of pages that have values of
    # that name.
    per_page_values_by_key = defaultdict(list)
    for value in merged_page_values:
      per_page_values_by_key[self._key_func(value)].append(value)

    # We already have the x values in the values array. But, we also need
    # the values merged across the pages. And, we will need them indexed by
    # summary key so that we can find them when printing out value names in
    # alphabetical order.
    merged_pages_value_by_key = {}
    if not self.had_failures:
      for value in merge_values.MergeLikeValuesFromDifferentPages(
          merged_page_values, self._key_func):
        value_key = self._key_func(value)
        assert value_key not in merged_pages_value_by_key
        merged_pages_value_by_key[value_key] = value

    keys = sorted(set([self._key_func(v) for v in merged_page_values]))

    # Time to walk through the values by key, printing first the page-specific
    # values and then the merged_site value.
    for key in keys:
      per_page_values = per_page_values_by_key.get(key, [])

      # Sort the values by their URL.
      sorted_per_page_values = list(per_page_values)
      sorted_per_page_values.sort(
          key=lambda per_page_values: per_page_values.page.display_name)

      # Output the page-specific results.
      num_successful_pages_for_this_key = (
          num_successful_pages_for_key[key])
      for per_page_value in sorted_per_page_values:
        self._ComputePerPageValue(per_page_value,
                                  num_successful_pages_for_this_key)

      # Output the combined values.
      merged_pages_value = merged_pages_value_by_key.get(key, None)
      if merged_pages_value:
        self._computed_summary_values.append(merged_pages_value)
        self._interleaved_computed_per_page_values_and_summaries.append(
            merged_pages_value)

  def _ComputePerPageValue(
      self, value, num_successful_pages_for_this_value_name):
    if num_successful_pages_for_this_value_name >= 1:
      # Save the result.
      self._computed_per_page_values.append(value)
      self._interleaved_computed_per_page_values_and_summaries.append(value)
