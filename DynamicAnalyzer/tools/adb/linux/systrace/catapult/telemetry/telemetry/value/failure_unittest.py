# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import traceback
import unittest

from telemetry import story
from telemetry import page as page_module
from telemetry import value
from telemetry.value import failure


class TestBase(unittest.TestCase):
  def setUp(self):
    self.story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    self.story_set.AddStory(page_module.Page(
        'http://www.bar.com/', self.story_set, self.story_set.base_dir))

  @property
  def pages(self):
    return self.story_set.stories

class ValueTest(TestBase):
  def testRepr(self):
    v = failure.FailureValue.FromMessage(self.pages[0], 'Failure')

    exc_info_str = failure.GetStringFromExcInfo(v.exc_info)
    expected = 'FailureValue(http://www.bar.com/, %s)' % exc_info_str

    self.assertEquals(expected, str(v))

  def testName(self):
    v0 = failure.FailureValue.FromMessage(self.pages[0], 'Failure')
    self.assertEquals('Exception', v0.name)
    try:
      raise NotImplementedError()
    except Exception:
      v1 = failure.FailureValue(self.pages[0], sys.exc_info())
    self.assertEquals('NotImplementedError', v1.name)

  def testBuildbotAndRepresentativeValue(self):
    v = failure.FailureValue.FromMessage(self.pages[0], 'Failure')
    self.assertIsNone(v.GetBuildbotValue())
    self.assertIsNone(v.GetBuildbotDataType(
        value.COMPUTED_PER_PAGE_SUMMARY_OUTPUT_CONTEXT))
    self.assertIsNone(v.GetChartAndTraceNameForPerPageResult())
    self.assertIsNone(v.GetRepresentativeNumber())
    self.assertIsNone(v.GetRepresentativeString())

  def testAsDict(self):
    v = failure.FailureValue.FromMessage(self.pages[0], 'Failure')
    d = v.AsDictWithoutBaseClassEntries()
    self.assertTrue(d['value'].find('Exception: Failure') > -1)

  def testFromDict(self):
    try:
      raise Exception('test')
    except Exception:
      exc_info = sys.exc_info()
    d = {
      'type': 'failure',
      'name': exc_info[0].__name__,
      'units': '',
      'value': ''.join(traceback.format_exception(*exc_info))
    }
    v = value.Value.FromDict(d, {})

    self.assertTrue(isinstance(v, failure.FailureValue))
    self.assertEquals(v.name, 'Exception')
