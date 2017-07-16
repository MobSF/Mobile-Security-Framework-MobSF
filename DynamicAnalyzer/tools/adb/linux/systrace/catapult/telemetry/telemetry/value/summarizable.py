# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import value as value_module
from telemetry.value import (improvement_direction
                             as improvement_direction_module)


class SummarizableValue(value_module.Value):
  def __init__(self, page, name, units, important, description, tir_label,
               improvement_direction, grouping_keys):
    """A summarizable value result from a test."""
    super(SummarizableValue, self).__init__(
        page, name, units, important, description, tir_label, grouping_keys)
# TODO(eakuefner): uncomment this assert after Telemetry clients are fixed.
# Note: Telemetry unittests satisfy this assert.
#    assert improvement_direction_module.IsValid(improvement_direction)
    self._improvement_direction = improvement_direction

  @property
  def improvement_direction(self):
    return self._improvement_direction

  def AsDict(self):
    d = super(SummarizableValue, self).AsDict()
    if improvement_direction_module.IsValid(self.improvement_direction):
      d['improvement_direction'] = self.improvement_direction
    return d

  @staticmethod
  def GetJSONTypeName():
    return 'summarizable'

  def AsDictWithoutBaseClassEntries(self):
    d = super(SummarizableValue, self).AsDictWithoutBaseClassEntries()
    if 'improvement_direction' in d:
      del d['improvement_direction']
    return d

  def GetBuildbotDataType(self, output_context):
    """Returns the buildbot's equivalent data_type.

    This should be one of the values accepted by perf_tests_results_helper.py.
    """
    raise NotImplementedError()

  def GetBuildbotValue(self):
    """Returns the buildbot's equivalent value."""
    raise NotImplementedError()

  @classmethod
  def MergeLikeValuesFromSamePage(cls, values):
    raise NotImplementedError()

  @classmethod
  def MergeLikeValuesFromDifferentPages(cls, values):
    raise NotImplementedError()

  def GetRepresentativeNumber(self):
    """Gets a single scalar value that best-represents this value.

    Returns None if not possible.
    """
    raise NotImplementedError()

  def GetRepresentativeString(self):
    """Gets a string value that best-represents this value.

    Returns None if not possible.
    """
    raise NotImplementedError()
