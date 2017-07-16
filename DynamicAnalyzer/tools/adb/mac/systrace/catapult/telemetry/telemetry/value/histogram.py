# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json

from telemetry.util import perf_tests_helper
from telemetry import value as value_module
from telemetry.value import histogram_util
from telemetry.value import summarizable


class HistogramValueBucket(object):
  def __init__(self, low, high, count=0):
    self.low = low
    self.high = high
    self.count = count

  def AsDict(self):
    return {
      'low': self.low,
      'high': self.high,
      'count': self.count
    }

  def ToJSONString(self):
    return '{%s}' % ', '.join([
      '"low": %i' % self.low,
      '"high": %i' % self.high,
      '"count": %i' % self.count])

class HistogramValue(summarizable.SummarizableValue):
  def __init__(self, page, name, units,
               raw_value=None, raw_value_json=None, important=True,
               description=None, tir_label=None, improvement_direction=None,
               grouping_keys=None):
    super(HistogramValue, self).__init__(page, name, units, important,
                                         description, tir_label,
                                         improvement_direction, grouping_keys)
    if raw_value_json:
      assert raw_value == None, \
             'Don\'t specify both raw_value and raw_value_json'
      raw_value = json.loads(raw_value_json)
    if raw_value:
      self.buckets = []
      for bucket in histogram_util.GetHistogramBucketsFromRawValue(raw_value):
        self.buckets.append(HistogramValueBucket(
          low=bucket['low'],
          high=bucket['high'],
          count=bucket['count']))
    else:
      self.buckets = []

  def __repr__(self):
    if self.page:
      page_name = self.page.display_name
    else:
      page_name = 'None'
    return ('HistogramValue(%s, %s, %s, raw_json_string=%s, '
            'important=%s, description=%s, tir_label=%s, '
            'improvement_direction=%s, grouping_keys=%s)') % (
                page_name,
                self.name, self.units,
                self.ToJSONString(),
                self.important,
                self.description,
                self.tir_label,
                self.improvement_direction,
                self.grouping_keys)

  def GetBuildbotDataType(self, output_context):
    if self._IsImportantGivenOutputIntent(output_context):
      return 'histogram'
    return 'unimportant-histogram'

  def GetBuildbotValue(self):
    # More buildbot insanity: perf_tests_results_helper requires the histogram
    # to be an array of size one.
    return [self.ToJSONString()]

  def ToJSONString(self):
    # This has to hand-JSONify the histogram to ensure the order of keys
    # produced is stable across different systems.
    #
    # This is done because the buildbot unittests are string equality
    # assertions. Thus, tests that contain histograms require stable
    # stringification of the histogram.
    #
    # Sigh, buildbot, Y U gotta be that way.
    return '{"buckets": [%s]}' % (
      ', '.join([b.ToJSONString() for b in self.buckets]))

  def GetRepresentativeNumber(self):
    (mean, _) = perf_tests_helper.GeomMeanAndStdDevFromHistogram(
        self.ToJSONString())
    return mean

  def GetRepresentativeString(self):
    return self.GetBuildbotValue()

  @staticmethod
  def GetJSONTypeName():
    return 'histogram'

  def AsDict(self):
    d = super(HistogramValue, self).AsDict()
    d['buckets'] = [b.AsDict() for b in self.buckets]
    return d

  @staticmethod
  def FromDict(value_dict, page_dict):
    kwargs = value_module.Value.GetConstructorKwArgs(value_dict, page_dict)
    kwargs['raw_value'] = value_dict

    if 'improvement_direction' in value_dict:
      kwargs['improvement_direction'] = value_dict['improvement_direction']

    return HistogramValue(**kwargs)

  @classmethod
  def MergeLikeValuesFromSamePage(cls, values):
    assert len(values) > 0
    v0 = values[0]
    return HistogramValue(
        v0.page, v0.name, v0.units,
        raw_value_json=histogram_util.AddHistograms(
            [v.ToJSONString() for v in values]),
        description=v0.description,
        important=v0.important, tir_label=value_module.MergedTirLabel(values),
        improvement_direction=v0.improvement_direction,
        grouping_keys=v0.grouping_keys)

  @classmethod
  def MergeLikeValuesFromDifferentPages(cls, values):
    # Histograms cannot be merged across pages, at least for now. It should be
    # theoretically possible, just requires more work. Instead, return None.
    # This signals to the merging code that the data is unmergable and it will
    # cope accordingly.
    return None
