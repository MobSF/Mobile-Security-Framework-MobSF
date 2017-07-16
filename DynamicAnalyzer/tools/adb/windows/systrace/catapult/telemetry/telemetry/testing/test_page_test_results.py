# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.results import page_test_results
from telemetry.page import page as page_module
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar


class TestPageTestResults(
    page_test_results.PageTestResults):
  def __init__(self, test):
    super(TestPageTestResults, self).__init__()
    self.test = test
    page = page_module.Page("http://www.google.com", {})
    self.WillRunPage(page)

  def GetPageSpecificValueNamed(self, name):
    values = [value for value in self.all_page_specific_values
         if value.name == name]
    assert len(values) == 1, 'Could not find value named %s' % name
    return values[0]

  def AssertHasPageSpecificScalarValue(self, name, units, expected_value):
    value = self.GetPageSpecificValueNamed(name)
    self.test.assertEquals(units, value.units)
    self.test.assertTrue(isinstance(value, scalar.ScalarValue))
    self.test.assertEquals(expected_value, value.value)

  def AssertHasPageSpecificListOfScalarValues(self, name, units,
                                              expected_values):
    value = self.GetPageSpecificValueNamed(name)
    self.test.assertEquals(units, value.units)
    self.test.assertTrue(
        isinstance(value, list_of_scalar_values.ListOfScalarValues))
    self.test.assertItemsEqual(expected_values, value.values)

  def __str__(self):
    return '\n'.join([repr(x) for x in self.all_page_specific_values])
