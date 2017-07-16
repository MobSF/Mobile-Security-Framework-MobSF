# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
from telemetry.value import failure
from telemetry.value import improvement_direction
from telemetry.value import scalar


def TranslateMreFailure(mre_failure, page):
  return failure.FailureValue.FromMessage(page, mre_failure.stack)


def TranslateScalarValue(scalar_value, page):
  # This function should not modify scalar_value because it is also held by
  # PageTestResults.value_set.
  scalar_value = copy.deepcopy(scalar_value)

  value = scalar_value['numeric']['value']
  scalar_value['value'] = value
  if value is None:
    scalar_value['none_value_reason'] = 'Common scalar contained None'

  name = scalar_value['name']

  unit_parts = scalar_value['numeric']['unit'].split('_')
  if len(unit_parts) != 2:
    raise ValueError('Must specify improvement direction for value ' + name)

  scalar_value['units'] = unit_parts[0]

  if unit_parts[1] == 'biggerIsBetter':
    scalar_value['improvement_direction'] = improvement_direction.UP
  else:
    assert unit_parts[1] == 'smallerIsBetter'
    scalar_value['improvement_direction'] = improvement_direction.DOWN

  scalar_value['page_id'] = page.id
  scalar_value['name'] = name
  return scalar.ScalarValue.FromDict(scalar_value, {page.id: page})
