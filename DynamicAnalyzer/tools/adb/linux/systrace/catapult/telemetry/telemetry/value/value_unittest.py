# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import unittest

from telemetry import story
from telemetry import page as page_module
from telemetry import value


class TestBase(unittest.TestCase):
  def setUp(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page_module.Page("http://www.bar.com/", story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page("http://www.baz.com/", story_set, story_set.base_dir))
    story_set.AddStory(
        page_module.Page("http://www.foo.com/", story_set, story_set.base_dir))
    self.story_set = story_set

  @property
  def pages(self):
    return self.story_set.stories

class ValueForTest(value.Value):
  @classmethod
  def MergeLikeValuesFromSamePage(cls, values):
    pass

  @classmethod
  def MergeLikeValuesFromDifferentPages(cls, values):
    pass

  def GetBuildbotDataType(self, output_context):
    pass

  def GetBuildbotValue(self):
    pass

  def GetChartAndTraceNameForComputedSummaryResult(
      self, trace_tag):
    pass

  def GetRepresentativeNumber(self):
    pass

  def GetRepresentativeString(self):
    pass

  @staticmethod
  def GetJSONTypeName():
    pass

class ValueForAsDictTest(ValueForTest):
  @staticmethod
  def GetJSONTypeName():
    return 'baz'

class ValueForFromDictTest(ValueForTest):
  @staticmethod
  def FromDict(value_dict, page_dict):
    kwargs = value.Value.GetConstructorKwArgs(value_dict, page_dict)
    return ValueForFromDictTest(**kwargs)

  @staticmethod
  def GetJSONTypeName():
    return 'value_for_from_dict_test'

class ValueTest(TestBase):
  def testCompat(self):
    page0 = self.pages[0]
    page1 = self.pages[0]

    a = value.Value(page0, 'x', 'unit', important=False, description=None,
                    tir_label='foo', grouping_keys=None)
    b = value.Value(page1, 'x', 'unit', important=False, description=None,
                    tir_label='foo', grouping_keys=None)
    self.assertTrue(b.IsMergableWith(a))

    a = value.Value(page0, 'x', 'unit', important=False, description=None,
                    tir_label='foo', grouping_keys=None)
    b = value.Value(page0, 'x', 'unit', important=False, description=None,
                     tir_label='bar', grouping_keys=None)
    self.assertTrue(b.IsMergableWith(a))

  def testIncompat(self):
    page0 = self.pages[0]

    a = value.Value(page0, 'x', 'unit', important=False, description=None,
                    tir_label=None, grouping_keys=None)
    b = value.Value(page0, 'x', 'incompatUnit', important=False,
                    tir_label=None, description=None, grouping_keys=None)
    self.assertFalse(b.IsMergableWith(a))

    a = value.Value(page0, 'x', 'unit', important=False, description=None,
                    tir_label=None, grouping_keys=None)
    b = value.Value(page0, 'x', 'unit', important=True, description=None,
                    tir_label=None, grouping_keys=None)
    self.assertFalse(b.IsMergableWith(a))

    a = value.Value(page0, 'x', 'unit', important=False, description=None,
                    tir_label=None, grouping_keys=None)
    b = ValueForTest(page0, 'x', 'unit', important=True, description=None,
                     tir_label=None, grouping_keys=None)
    self.assertFalse(b.IsMergableWith(a))

  def testNameMustBeString(self):
    with self.assertRaises(ValueError):
      value.Value(None, 42, 'unit', important=False, description=None,
                  tir_label=None, grouping_keys=None)

  def testUnitsMustBeString(self):
    with self.assertRaises(ValueError):
      value.Value(None, 'x', 42, important=False, description=None,
                  tir_label=None, grouping_keys=None)

  def testImportantMustBeBool(self):
    with self.assertRaises(ValueError):
      value.Value(None, 'x', 'unit', important='foo', description=None,
                  tir_label=None, grouping_keys=None)

  def testDescriptionMustBeStringOrNone(self):
    with self.assertRaises(ValueError):
      value.Value(None, 'x', 'unit', important=False, description=42,
                  tir_label=None, grouping_keys=None)

  def testInteractionRecordMustBeStringOrNone(self):
    with self.assertRaises(ValueError):
      value.Value(None, 'x', 'unit', important=False, description=None,
                  tir_label=42, grouping_keys=None)

  def testGroupingKeysMustBeDictOrNone(self):
    with self.assertRaises(ValueError):
      value.Value(None, 'x', 'unit', important=False, description=None,
                  tir_label=42, grouping_keys='foo')

  def testAsDictBaseKeys(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=True, description=None,
                           tir_label='bar', grouping_keys={'foo': 'baz'})
    d = v.AsDict()

    self.assertEquals(d, {
          'name': 'x',
          'type': 'baz',
          'units': 'unit',
          'important': True,
          'tir_label': 'bar',
          'grouping_keys': {'foo': 'baz'}
        })

  def testAsDictWithPage(self):
    page0 = self.pages[0]

    v = ValueForAsDictTest(page0, 'x', 'unit', important=False,
                           description=None, tir_label=None, grouping_keys=None)
    d = v.AsDict()

    self.assertIn('page_id', d)

  def testAsDictWithoutPage(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=False, description=None,
                           tir_label=None, grouping_keys=None)
    d = v.AsDict()

    self.assertNotIn('page_id', d)

  def testAsDictWithDescription(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=False,
                           description='Some description.',
                           tir_label=None, grouping_keys=None)
    d = v.AsDict()
    self.assertEqual('Some description.', d['description'])

  def testAsDictWithoutDescription(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=False, description=None,
                           tir_label=None, grouping_keys=None)
    self.assertNotIn('description', v.AsDict())

  def testAsDictWithInteractionRecord(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=False,
                           description='Some description.',
                           tir_label='foo', grouping_keys=None)
    d = v.AsDict()
    self.assertEqual('foo', d['tir_label'])

  def testAsDictWithoutInteractionRecord(self):
    v = ValueForAsDictTest(None, 'x', 'unit', important=False, description=None,
                           tir_label=None, grouping_keys=None)
    self.assertNotIn('tir_label', v.AsDict())

  def testFromDictBaseKeys(self):
    d = {
      'type': 'value_for_from_dict_test',
      'name': 'x',
      'units': 'unit'
    }

    v = value.Value.FromDict(d, None)
    self.assertEquals(v.name, 'x')
    self.assertTrue(isinstance(v, ValueForFromDictTest))
    self.assertEquals(v.units, 'unit')

  def testFromDictWithPage(self):
    page0 = self.pages[0]
    page_dict = {page0.id: page0}

    d = {
      'type': 'value_for_from_dict_test',
      'name': 'x',
      'units': 'unit',
      'page_id': page0.id
    }

    v = value.Value.FromDict(d, page_dict)

    self.assertEquals(v.page.id, page0.id)

  def testFromDictWithPageId0(self):
    page_dict = {0: 'foo'}

    d = {
      'type': 'value_for_from_dict_test',
      'name': 'x',
      'units': 'unit',
      'page_id': 0
    }

    v = value.Value.FromDict(d, page_dict)

    self.assertEquals(v.page, 'foo')

  def testFromDictWithoutPage(self):
    d = {
      'type': 'value_for_from_dict_test',
      'name': 'x',
      'units': 'unit'
    }

    v = value.Value.FromDict(d, {})

    self.assertEquals(v.page, None)

  def testFromDictWithDescription(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit',
          'description': 'foo'
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.description, 'foo')

  def testFromDictWithoutDescription(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit'
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.description, None)

  def testFromDictWithInteractionRecord(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit',
          'description': 'foo',
          'tir_label': 'bar'
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.tir_label, 'bar')

  def testFromDictWithoutInteractionRecord(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit'
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.tir_label, None)

  def testFromDictWithGroupingKeys(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit',
          'description': 'foo',
          'tir_label': 'bar',
          'grouping_keys': {'foo': 'bar'}
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.grouping_keys, {'foo': 'bar'})

  def testFromDictWithoutGroupingKeys(self):
    d = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit'
        }

    v = value.Value.FromDict(d, {})
    self.assertEquals(v.grouping_keys, {})

  def testListOfValuesFromListOfDicts(self):
    d0 = {
          'type': 'value_for_from_dict_test',
          'name': 'x',
          'units': 'unit'
        }
    d1 = {
          'type': 'value_for_from_dict_test',
          'name': 'y',
          'units': 'unit'
        }
    vs = value.Value.ListOfValuesFromListOfDicts([d0, d1], {})
    self.assertEquals(vs[0].name, 'x')
    self.assertEquals(vs[1].name, 'y')

  def testMergedTirLabelForSameLabel(self):
    v = ValueForTest(None, 'foo', 'ms', False, 'd', 'bar', {})

    tir_label = value.MergedTirLabel([v, v])
    self.assertEquals(tir_label, 'bar')

  def testMergedTirLabelForDifferentLabels(self):
    v0 = ValueForTest(None, 'foo', 'ms', False, 'd', 'bar', {})
    v1 = ValueForTest(None, 'foo', 'ms', False, 'd', 'baz', {})

    tir_label = value.MergedTirLabel([v0, v1])
    self.assertIsNone(tir_label)
