# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import numbers
import math

from telemetry import value as value_module
from telemetry.value import none_values
from telemetry.value import summarizable


def Variance(sample):
  """ Compute the population variance.

    Args:
      sample: a list of numbers.
  """
  k = len(sample) - 1  # Bessel correction
  if k <= 0:
    return 0.0
  m = _Mean(sample)
  return sum((x - m)**2 for x in sample)/k


def StandardDeviation(sample):
  """ Compute standard deviation for a list of numbers.

    Args:
      sample: a list of numbers.
  """
  return math.sqrt(Variance(sample))


def PooledStandardDeviation(list_of_samples, list_of_variances=None):
  """ Compute standard deviation for a list of samples.

  See: https://en.wikipedia.org/wiki/Pooled_variance for the formula.

  Args:
    list_of_samples: a list of lists, each is a list of numbers.
    list_of_variances: a list of numbers, the i-th element is the variance of
      the i-th sample in list_of_samples. If this is None, we use
      Variance(sample) to get the variance of the i-th sample.
  """
  pooled_variance = 0.0
  total_degrees_of_freedom = 0
  for i in xrange(len(list_of_samples)):
    l = list_of_samples[i]
    k = len(l) - 1  # Bessel correction
    if k <= 0:
      continue
    variance = list_of_variances[i] if list_of_variances else Variance(l)
    pooled_variance += k * variance
    total_degrees_of_freedom += k
  if total_degrees_of_freedom:
    return (pooled_variance / total_degrees_of_freedom) ** 0.5
  else:
    return 0.0


def _Mean(values):
  return float(sum(values)) / len(values) if len(values) > 0 else 0.0


class ListOfScalarValues(summarizable.SummarizableValue):
  """ ListOfScalarValues represents a list of numbers.

  By default, std is the standard deviation of all numbers in the list. Std can
  also be specified in the constructor if the numbers are not from the same
  population.
  """
  def __init__(self, page, name, units, values,
               important=True, description=None,
               tir_label=None, none_value_reason=None,
               std=None, improvement_direction=None, grouping_keys=None):
    super(ListOfScalarValues, self).__init__(page, name, units, important,
                                             description, tir_label,
                                             improvement_direction,
                                             grouping_keys)
    if values is not None:
      assert isinstance(values, list)
      assert len(values) > 0
      assert all(isinstance(v, numbers.Number) for v in values)
      assert std is None or isinstance(std, numbers.Number)
    else:
      assert std is None
    none_values.ValidateNoneValueReason(values, none_value_reason)
    self.values = values
    self.none_value_reason = none_value_reason
    if values is not None and std is None:
      std = StandardDeviation(values)
    assert std is None or std >= 0, (
        'standard deviation cannot be negative: %s' % std)
    self._std = std

  @property
  def std(self):
    return self._std

  @property
  def variance(self):
    return self._std ** 2

  def __repr__(self):
    if self.page:
      page_name = self.page.display_name
    else:
      page_name = 'None'
    return ('ListOfScalarValues(%s, %s, %s, %s, '
            'important=%s, description=%s, tir_label=%s, std=%s, '
            'improvement_direction=%s, grouping_keys=%s)') % (
                page_name,
                self.name,
                self.units,
                repr(self.values),
                self.important,
                self.description,
                self.tir_label,
                self.std,
                self.improvement_direction,
                self.grouping_keys)

  def GetBuildbotDataType(self, output_context):
    if self._IsImportantGivenOutputIntent(output_context):
      return 'default'
    return 'unimportant'

  def GetBuildbotValue(self):
    return self.values

  def GetRepresentativeNumber(self):
    return _Mean(self.values)

  def GetRepresentativeString(self):
    return repr(self.values)

  @staticmethod
  def GetJSONTypeName():
    return 'list_of_scalar_values'

  def AsDict(self):
    d = super(ListOfScalarValues, self).AsDict()
    d['values'] = self.values
    d['std'] = self.std

    if self.none_value_reason is not None:
      d['none_value_reason'] = self.none_value_reason

    return d

  @staticmethod
  def FromDict(value_dict, page_dict):
    kwargs = value_module.Value.GetConstructorKwArgs(value_dict, page_dict)
    kwargs['values'] = value_dict['values']
    kwargs['std'] = value_dict['std']

    if 'improvement_direction' in value_dict:
      kwargs['improvement_direction'] = value_dict['improvement_direction']
    if 'none_value_reason' in value_dict:
      kwargs['none_value_reason'] = value_dict['none_value_reason']

    return ListOfScalarValues(**kwargs)

  @classmethod
  def MergeLikeValuesFromSamePage(cls, values):
    assert len(values) > 0
    v0 = values[0]

    return cls._MergeLikeValues(values, v0.page, v0.name, v0.grouping_keys)

  @classmethod
  def MergeLikeValuesFromDifferentPages(cls, values):
    assert len(values) > 0
    v0 = values[0]
    return cls._MergeLikeValues(values, None, v0.name, v0.grouping_keys)

  @classmethod
  def _MergeLikeValues(cls, values, page, name, grouping_keys):
    v0 = values[0]
    merged_values = []
    list_of_samples = []
    none_value_reason = None
    pooled_std = None
    for v in values:
      if v.values is None:
        merged_values = None
        merged_none_values = [v for v in values if v.values is None]
        none_value_reason = (none_values.MERGE_FAILURE_REASON +
            ' None values: %s' % repr(merged_none_values))
        break
      merged_values.extend(v.values)
      list_of_samples.append(v.values)
    if merged_values and page is None:
      # Pooled standard deviation is only used when merging values comming from
      # different pages. Otherwise, fall back to the default computation done
      # in the cosntructor of ListOfScalarValues.
      pooled_std = PooledStandardDeviation(
          list_of_samples, list_of_variances=[v.variance for v in values])
    return ListOfScalarValues(
        page, name, v0.units,
        merged_values,
        important=v0.important,
        description=v0.description,
        tir_label=value_module.MergedTirLabel(values),
        std=pooled_std,
        none_value_reason=none_value_reason,
        improvement_direction=v0.improvement_direction,
        grouping_keys=grouping_keys)
