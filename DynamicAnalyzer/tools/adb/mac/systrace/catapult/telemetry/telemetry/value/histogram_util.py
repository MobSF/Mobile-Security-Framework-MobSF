# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This is a helper module to get and manipulate histogram data.

The histogram data is the same data as is visible from "chrome://histograms".
More information can be found at: chromium/src/base/metrics/histogram.h
"""

import collections
import json
import logging

from telemetry.core import exceptions

BROWSER_HISTOGRAM = 'browser_histogram'
RENDERER_HISTOGRAM = 'renderer_histogram'


def GetHistogramBucketsFromJson(histogram_json):
  return GetHistogramBucketsFromRawValue(json.loads(histogram_json))


def GetHistogramBucketsFromRawValue(raw_value):
  buckets = raw_value.get('buckets', [])
  if buckets:
    # If there are values greater than the maximum allowable for the histogram,
    # the highest bucket will have a 'low': maxvalue entry in the dict but no
    # 'high' entry. Code often assumes the 'high' value will always be present,
    # and uses it to get bucket mean. So default it to the same value as low.
    buckets[-1].setdefault('high', buckets[-1]['low'])
  return buckets


def CustomizeBrowserOptions(options):
  """Allows histogram collection."""
  options.AppendExtraBrowserArgs(['--enable-stats-collection-bindings'])


def SubtractHistogram(histogram_json, start_histogram_json):
  """Subtracts a previous histogram from a histogram.

  Both parameters and the returned result are json serializations.
  """
  start_histogram = json.loads(start_histogram_json)
  start_histogram_buckets = GetHistogramBucketsFromRawValue(start_histogram)
  # It's ok if the start histogram is empty (we had no data, maybe even no
  # histogram at all, at the start of the test).
  if not start_histogram_buckets:
    return histogram_json

  histogram = json.loads(histogram_json)
  if ('pid' in start_histogram and 'pid' in histogram
      and start_histogram['pid'] != histogram['pid']):
    raise Exception(
        'Trying to compare histograms from different processes (%d and %d)'
        % (start_histogram['pid'], histogram['pid']))

  start_histogram_bucket_counts = dict()
  for b in start_histogram_buckets:
    start_histogram_bucket_counts[b['low']] = b['count']

  new_buckets = []
  for b in GetHistogramBucketsFromRawValue(histogram):
    new_bucket = b
    low = b['low']
    if low in start_histogram_bucket_counts:
      new_bucket['count'] = b['count'] - start_histogram_bucket_counts[low]
      if new_bucket['count'] < 0:
        logging.error('Histogram subtraction error, starting histogram most '
                      'probably invalid.')
    if new_bucket['count']:
      new_buckets.append(new_bucket)
  histogram['buckets'] = new_buckets
  histogram['count'] -= start_histogram['count']

  return json.dumps(histogram)


def AddHistograms(histogram_jsons):
  """Adds histograms together. Used for aggregating data.

  The parameter is a list of json serializations and the returned result is a
  json serialization too.

  Note that the histograms to be added together are typically from different
  processes.
  """

  buckets = collections.defaultdict(int)
  for histogram_json in histogram_jsons:
    for b in GetHistogramBucketsFromJson(histogram_json):
      key = (b['low'], b['high'])
      buckets[key] += b['count']

  buckets = [{'low': key[0], 'high': key[1], 'count': value}
      for key, value in buckets.iteritems()]
  buckets.sort(key=lambda h: h['low'])

  result_histogram = {}
  result_histogram['buckets'] = buckets
  return json.dumps(result_histogram)


def GetHistogram(histogram_type, histogram_name, tab):
  """Get a json serialization of a histogram."""
  assert histogram_type in [BROWSER_HISTOGRAM, RENDERER_HISTOGRAM]
  function = 'getHistogram'
  if histogram_type == BROWSER_HISTOGRAM:
    function = 'getBrowserHistogram'
  try:
    histogram_json = tab.EvaluateJavaScript(
        'statsCollectionController.{{ @f }}({{ name }})',
        f=function, name=histogram_name)
  except exceptions.EvaluateException:
    # Sometimes JavaScript flakily fails to execute: http://crbug.com/508431
    histogram_json = None
  if histogram_json:
    return histogram_json
  return None


def GetHistogramCount(histogram_type, histogram_name, tab):
  """Get the count of events for the given histograms."""
  histogram_json = GetHistogram(histogram_type, histogram_name, tab)
  histogram = json.loads(histogram_json)
  if 'count' in histogram:
    return histogram['count']
  else:
    return 0

def GetHistogramSum(histogram_type, histogram_name, tab):
  """Get the sum of events for the given histograms."""
  histogram_json = GetHistogram(histogram_type, histogram_name, tab)
  histogram = json.loads(histogram_json)
  if 'sum' in histogram:
    return histogram['sum']
  else:
    return 0
