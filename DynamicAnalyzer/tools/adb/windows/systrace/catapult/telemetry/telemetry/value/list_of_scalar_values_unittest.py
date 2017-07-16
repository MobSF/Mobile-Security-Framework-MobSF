# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import unittest

from telemetry import story
from telemetry import page as page_module
from telemetry import value
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import none_values


class StatisticComputationTest(unittest.TestCase):
  def testVariance(self):
    self.assertAlmostEqual(
        list_of_scalar_values.Variance([]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.Variance([3]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.Variance([600, 470, 170, 430, 300]), 27130)

  def testStandardDeviation(self):
    self.assertAlmostEqual(
        list_of_scalar_values.StandardDeviation([]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.StandardDeviation([1]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.StandardDeviation([600, 470, 170, 430, 300]),
        164.71186, places=4)

  def testPooledVariance(self):
    self.assertAlmostEqual(
        list_of_scalar_values.PooledStandardDeviation([[], [], []]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.PooledStandardDeviation([[1], [], [3], []]), 0)
    self.assertAlmostEqual(
        list_of_scalar_values.PooledStandardDeviation([[1], [2], [3], [4]]), 0)
    self.assertAlmostEqual(list_of_scalar_values.PooledStandardDeviation(
        [[600, 470, 170, 430, 300],           # variance = 27130, std = 164.7
        [4000, 4020, 4230],                   # variance = 16233, std = 127.41
        [260, 700, 800, 900, 0, 120, 150]]),  # variance = 136348, std = 369.2
        282.7060,  # SQRT((27130 4 + 16233*2 + 136348*6)/12)
        places=4)
    self.assertAlmostEqual(list_of_scalar_values.PooledStandardDeviation(
        [[600, 470, 170, 430, 300],
         [4000, 4020, 4230],
         [260, 700, 800, 900, 0, 120, 150]],
        list_of_variances=[100000, 200000, 300000]),
        465.47466,  # SQRT((100000*4 + 200000* 2 + 300000*6)/12)
        places=4)


class TestBase(unittest.TestCase):
  def setUp(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page('http://www.baz.com/', story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page('http://www.foo.com/', story_set, story_set.base_dir))
    self.story_set = story_set

  @property
  def pages(self):
    return self.story_set.stories

class ValueTest(TestBase):
  def testRepr(self):
    page = self.pages[0]
    v = list_of_scalar_values.ListOfScalarValues(
        page, 'x', 'unit', [10, 9, 9, 7], important=True, description='desc',
        tir_label='my_ir', std=42,
        improvement_direction=improvement_direction.DOWN)

    expected = ('ListOfScalarValues(http://www.bar.com/, x, unit, '
                '[10, 9, 9, 7], important=True, description=desc, '
                'tir_label=my_ir, std=42, '
                'improvement_direction=down, grouping_keys={})')

    self.assertEquals(expected, str(v))

  def testListSamePageMerging(self):
    page0 = self.pages[0]
    v0 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [10, 9, 9, 7], description='list-based metric',
        improvement_direction=improvement_direction.DOWN)
    v1 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [300, 302, 303, 304], description='list-based metric',
        improvement_direction=improvement_direction.DOWN)
    self.assertTrue(v1.IsMergableWith(v0))

    vM = (list_of_scalar_values.ListOfScalarValues.
          MergeLikeValuesFromSamePage([v0, v1]))
    self.assertEquals(page0, vM.page)
    self.assertEquals('x', vM.name)
    self.assertEquals('unit', vM.units)
    self.assertEquals(True, vM.important)
    self.assertEquals([10, 9, 9, 7, 300, 302, 303, 304], vM.values)
    # Values from the same page use regular standard deviation.
    self.assertAlmostEqual(156.88849, vM.std, places=4)
    self.assertEquals('list-based metric', vM.description)
    self.assertEquals(improvement_direction.DOWN, vM.improvement_direction)

  def testListDifferentPageMerging(self):
    page0 = self.pages[0]
    page1 = self.pages[1]
    v0 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [10, 9, 9, 7], improvement_direction=improvement_direction.DOWN)
    v1 = list_of_scalar_values.ListOfScalarValues(
        page1, 'x', 'unit',
        [300, 302, 303, 304], improvement_direction=improvement_direction.DOWN)
    self.assertTrue(v1.IsMergableWith(v0))

    vM = (list_of_scalar_values.ListOfScalarValues.
          MergeLikeValuesFromDifferentPages([v0, v1]))
    self.assertEquals(None, vM.page)
    self.assertEquals('x', vM.name)
    self.assertEquals('unit', vM.units)
    self.assertEquals(True, vM.important)
    self.assertEquals([10, 9, 9, 7, 300, 302, 303, 304], vM.values)
    # Values from different pages use pooled standard deviation.
    # SQRT((19/12 * 3 + 35/12 * 3)/6) = 1.5
    self.assertAlmostEqual(1.5, vM.std)
    self.assertEquals(improvement_direction.DOWN, vM.improvement_direction)

  def testListWithNoneValueMerging(self):
    page0 = self.pages[0]
    v0 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [1, 2], improvement_direction=improvement_direction.UP)
    v1 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        None, none_value_reason='n',
        improvement_direction=improvement_direction.UP)
    self.assertTrue(v1.IsMergableWith(v0))

    vM = (list_of_scalar_values.ListOfScalarValues.
          MergeLikeValuesFromSamePage([v0, v1]))
    self.assertEquals(None, vM.values)
    expected_none_value_reason = (
        'Merging values containing a None value results in a None value. '
        'None values: [ListOfScalarValues(http://www.bar.com/, x, unit, None, '
        'important=True, description=None, tir_label=None, std=None,'
        ' improvement_direction=up, grouping_keys={})]')
    self.assertEquals(expected_none_value_reason, vM.none_value_reason)
    self.assertEquals(improvement_direction.UP, vM.improvement_direction)

  def testListWithNoneValueMustHaveNoneReason(self):
    page0 = self.pages[0]
    self.assertRaises(none_values.NoneValueMissingReason,
                      lambda: list_of_scalar_values.ListOfScalarValues(
                          page0, 'x', 'unit', None,
                          improvement_direction=improvement_direction.DOWN))

  def testListWithNoneReasonMustHaveNoneValue(self):
    page0 = self.pages[0]
    self.assertRaises(none_values.ValueMustHaveNoneValue,
                      lambda: list_of_scalar_values.ListOfScalarValues(
                          page0, 'x', 'unit', [1, 2],
                          none_value_reason='n',
                          improvement_direction=improvement_direction.UP))

  def testAsDict(self):
    v = list_of_scalar_values.ListOfScalarValues(
        None, 'x', 'unit', [1, 2],
        important=False, improvement_direction=improvement_direction.DOWN)
    d = v.AsDictWithoutBaseClassEntries()

    self.assertEquals(d['values'], [1, 2])
    self.assertAlmostEqual(d['std'], 0.7071, places=4)

  def testMergedValueAsDict(self):
    page0 = self.pages[0]
    v0 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [10, 9, 9, 7], improvement_direction=improvement_direction.DOWN)
    v1 = list_of_scalar_values.ListOfScalarValues(
        page0, 'x', 'unit',
        [300, 302, 303, 304], improvement_direction=improvement_direction.DOWN)
    self.assertTrue(v1.IsMergableWith(v0))

    vM = (list_of_scalar_values.ListOfScalarValues.
          MergeLikeValuesFromSamePage([v0, v1]))
    d = vM.AsDict()
    self.assertEquals(d['values'], [10, 9, 9, 7, 300, 302, 303, 304])
    # Values from the same page use regular standard deviation.
    self.assertAlmostEqual(d['std'], 156.88849, places=4)


  def testNoneValueAsDict(self):
    v = list_of_scalar_values.ListOfScalarValues(
        None, 'x', 'unit', None,
        important=False, none_value_reason='n',
        improvement_direction=improvement_direction.UP)
    d = v.AsDictWithoutBaseClassEntries()

    self.assertEquals(d, {
          'values': None,
          'none_value_reason': 'n',
          'std': None
        })

  def testFromDictInts(self):
    d = {
      'type': 'list_of_scalar_values',
      'name': 'x',
      'units': 'unit',
      'values': [1, 2],
      'std': 0.7071,
      'improvement_direction': improvement_direction.DOWN
    }
    v = value.Value.FromDict(d, {})

    self.assertTrue(isinstance(v, list_of_scalar_values.ListOfScalarValues))
    self.assertEquals(v.values, [1, 2])
    self.assertEquals(v.std, 0.7071)
    self.assertEquals(improvement_direction.DOWN, v.improvement_direction)

  def testFromDictFloats(self):
    d = {
      'type': 'list_of_scalar_values',
      'name': 'x',
      'units': 'unit',
      'values': [1.3, 2.7, 4.5, 2.1, 3.4],
      'std': 0.901,
      'improvement_direction': improvement_direction.UP
    }
    v = value.Value.FromDict(d, {})

    self.assertTrue(isinstance(v, list_of_scalar_values.ListOfScalarValues))
    self.assertEquals(v.values, [1.3, 2.7, 4.5, 2.1, 3.4])
    self.assertEquals(v.std, 0.901)

  def testFromDictWithoutImprovementDirection(self):
    d = {
      'type': 'list_of_scalar_values',
      'name': 'x',
      'units': 'unit',
      'values': [1, 2],
      'std': 0.7071,
    }
    v = value.Value.FromDict(d, {})

    self.assertTrue(isinstance(v, list_of_scalar_values.ListOfScalarValues))
    self.assertIsNone(v.improvement_direction)

  def testFromDictNoneValue(self):
    d = {
      'type': 'list_of_scalar_values',
      'name': 'x',
      'units': 'unit',
      'values': None,
      'std': None,
      'none_value_reason': 'n',
      'improvement_direction': improvement_direction.DOWN
    }
    v = value.Value.FromDict(d, {})

    self.assertTrue(isinstance(v, list_of_scalar_values.ListOfScalarValues))
    self.assertEquals(v.values, None)
    self.assertEquals(v.none_value_reason, 'n')
