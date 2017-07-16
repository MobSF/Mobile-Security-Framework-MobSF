# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import unittest

from telemetry import story
from telemetry import page as page_module
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import merge_values
from telemetry.value import scalar


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

class MergeValueTest(TestBase):
  def testDefaultKeyFuncWithTirLabel(self):
    page0 = self.pages[0]

    value = scalar.ScalarValue(
        page0, 'x', 'units', 1,
        improvement_direction=improvement_direction.UP,
        tir_label='foo')

    self.assertEquals(('x', 'foo'), merge_values.DefaultKeyFunc(value))

  def testSamePageMergeBasic(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'x', 'units', 4,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page0, 'x', 'units', 2,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'x', 'units', 5,
                      improvement_direction=improvement_direction.UP)]

    merged_values = merge_values.MergeLikeValuesFromSamePage(all_values)
    # Sort the results so that their order is predictable for the subsequent
    # assertions.
    merged_values.sort(key=lambda x: x.page.url)

    self.assertEquals(2, len(merged_values))

    self.assertEquals((page0, 'x'),
                      (merged_values[0].page, merged_values[0].name))
    self.assertEquals([1, 2], merged_values[0].values)

    self.assertEquals((page1, 'x'),
                      (merged_values[1].page, merged_values[1].name))
    self.assertEquals([4, 5], merged_values[1].values)

  def testSamePageMergeNonstandardKeyFunc(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'x', 'units', 4,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page0, 'y', 'units', 2,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'y', 'units', 5,
                      improvement_direction=improvement_direction.UP)]

    merged_values = merge_values.MergeLikeValuesFromSamePage(
      all_values, key_func=lambda v: v.page.display_name)
    # Sort the results so that their order is predictable for the subsequent
    # assertions.
    merged_values.sort(key=lambda x: x.page.url)

    self.assertEquals(2, len(merged_values))
    self.assertEquals([1, 2], merged_values[0].values)
    self.assertEquals([4, 5], merged_values[1].values)

  def testSamePageMergeOneValue(self):
    page0 = self.pages[0]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.DOWN)]

    # Sort the results so that their order is predictable for the subsequent
    # assertions.
    merged_values = merge_values.MergeLikeValuesFromSamePage(all_values)
    self.assertEquals(1, len(merged_values))
    self.assertEquals(all_values[0].name, merged_values[0].name)
    self.assertEquals(all_values[0].units, merged_values[0].units)

  def testSamePageMergeWithInteractionRecord(self):
    page0 = self.pages[0]

    all_values = [scalar.ScalarValue(
                      page0, 'foo-x', 'units', 1, tir_label='foo',
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page0, 'foo-x', 'units', 4, tir_label='foo',
                      improvement_direction=improvement_direction.UP)]

    merged_values = merge_values.MergeLikeValuesFromSamePage(all_values)
    self.assertEquals(1, len(merged_values))
    self.assertEquals('foo', merged_values[0].tir_label)

  def testSamePageMergeWithTwoInteractionRecords(self):
    page0 = self.pages[0]

    all_values = [scalar.ScalarValue(page0, 'x', 'units', 1, tir_label='foo'),
                  scalar.ScalarValue(page0, 'x', 'units', 4, tir_label='bar')]

    merged_values = merge_values.MergeLikeValuesFromSamePage(all_values)
    self.assertEquals(2, len(merged_values))
    self.assertEquals('foo', merged_values[0].tir_label)
    self.assertEquals('bar', merged_values[1].tir_label)

  def testDifferentPageMergeBasic(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'x', 'units', 2,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page0, 'y', 'units', 10,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'y', 'units', 20,
                      improvement_direction=improvement_direction.UP)]

    merged_values = merge_values.MergeLikeValuesFromDifferentPages(all_values)
    merged_values.sort(key=lambda x: x.name)
    self.assertEquals(2, len(merged_values))

    self.assertEquals((None, 'x'),
                      (merged_values[0].page, merged_values[0].name))
    self.assertEquals([1, 2], merged_values[0].values)

    self.assertEquals((None, 'y'),
                      (merged_values[1].page, merged_values[1].name))
    self.assertEquals([10, 20], merged_values[1].values)

  def testDifferentPageMergeNonstandardKeyFunc(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'x', 'units', 2,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page0, 'y', 'units', 10,
                      improvement_direction=improvement_direction.UP),
                  scalar.ScalarValue(
                      page1, 'y', 'units', 20,
                      improvement_direction=improvement_direction.UP)]

    merged_values = merge_values.MergeLikeValuesFromDifferentPages(
      all_values, key_func=lambda v: True)

    self.assertEquals(1, len(merged_values))
    self.assertEquals([1, 2, 10, 20], merged_values[0].values)

  def testDifferentPageMergeSingleValueStillMerges(self):
    page0 = self.pages[0]

    all_values = [scalar.ScalarValue(
                      page0, 'x', 'units', 1,
                      improvement_direction=improvement_direction.DOWN)]

    # Sort the results so that their order is predictable for the subsequent
    # assertions.
    merged_values = merge_values.MergeLikeValuesFromDifferentPages(all_values)
    self.assertEquals(1, len(merged_values))

    self.assertEquals((None, 'x'),
                      (merged_values[0].page, merged_values[0].name))
    self.assertTrue(
        isinstance(merged_values[0], list_of_scalar_values.ListOfScalarValues))
    self.assertEquals([1], merged_values[0].values)

  def testDifferentPageMergeWithInteractionRecord(self):
    page0 = self.pages[0]
    page1 = self.pages[1]

    v0 = scalar.ScalarValue(page0, 'x', 'units', 1, tir_label='foo')
    v1 = scalar.ScalarValue(page0, 'y', 'units', 30, tir_label='bar')
    v2 = scalar.ScalarValue(page1, 'x', 'units', 2, tir_label='foo')
    v3 = scalar.ScalarValue(page1, 'y', 'units', 40, tir_label='baz')

    all_values = [v0, v1, v2, v3]

    merged_x = list_of_scalar_values.ListOfScalarValues(
      None, 'x', 'units', [1, 2], tir_label='foo')
    merged_y_bar = list_of_scalar_values.ListOfScalarValues(
      None, 'y', 'units', [30], tir_label='bar')
    merged_y_baz = list_of_scalar_values.ListOfScalarValues(
      None, 'y', 'units', [40], tir_label='baz')

    merged_values = merge_values.MergeLikeValuesFromDifferentPages(all_values)
    merged_values.sort(key=lambda x: x.tir_label)

    self.assertEquals([merged_y_bar, merged_y_baz, merged_x], merged_values)
