# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry import story
from telemetry import page as page_module
from telemetry import value
from telemetry.value import skip


class TestBase(unittest.TestCase):
  def setUp(self):
    story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    story_set.AddStory(
        page_module.Page('http://www.bar.com/', story_set, story_set.base_dir))
    self.story_set = story_set

  @property
  def pages(self):
    return self.story_set.stories

class ValueTest(TestBase):
  def testRepr(self):
    v = skip.SkipValue(self.pages[0], 'page skipped for testing reason',
                       description='desc')

    expected = ('SkipValue(http://www.bar.com/, '
                'page skipped for testing reason, '
                'description=desc)')

    self.assertEquals(expected, str(v))

  def testBuildbotAndRepresentativeValue(self):
    v = skip.SkipValue(self.pages[0], 'page skipped for testing reason')
    self.assertIsNone(v.GetBuildbotValue())
    self.assertIsNone(v.GetBuildbotDataType(
        value.COMPUTED_PER_PAGE_SUMMARY_OUTPUT_CONTEXT))
    self.assertIsNone(v.GetChartAndTraceNameForPerPageResult())
    self.assertIsNone(v.GetRepresentativeNumber())
    self.assertIsNone(v.GetRepresentativeString())

  def testAsDict(self):
    v = skip.SkipValue(self.pages[0], 'page skipped for testing reason')
    d = v.AsDictWithoutBaseClassEntries()
    self.assertEquals(d['reason'], 'page skipped for testing reason')

  def testFromDict(self):
    d = {
      'type': 'skip',
      'name': 'skip',
      'units': '',
      'reason': 'page skipped for testing reason'
    }
    v = value.Value.FromDict(d, {})
    self.assertTrue(isinstance(v, skip.SkipValue))
    self.assertEquals(v.reason, 'page skipped for testing reason')
