# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import story
from telemetry.page import page
from telemetry.story import story_filter as story_filter_module


class FilterTest(unittest.TestCase):

  def setUp(self):
    story_set = story.StorySet()
    self.p1 = page.Page(
      url='file://your/smile/widen.html', page_set=story_set,
      name='MayYour.smile_widen', tags=['tag1', 'tag2'])
    self.p2 = page.Page(
      url='file://share_a/smile/too.html', page_set=story_set,
      name='ShareA.smiles_too', tags=['tag1'])
    self.p3 = page.Page(
      url='file://share_a/smile/too.html', page_set=story_set,
      tags=['tag2'])
    self.pages = [self.p1, self.p2, self.p3]

  @staticmethod
  def ProcessCommandLineArgs(parser=None, **kwargs):
    class Options(object):
      def __init__(
          self, story_filter=None, story_filter_exclude=None,
          story_tag_filter=None, story_tag_filter_exclude=None):
        self.story_filter = story_filter
        self.story_filter_exclude = story_filter_exclude
        self.story_tag_filter = story_tag_filter
        self.story_tag_filter_exclude = story_tag_filter_exclude
    story_filter_module.StoryFilter.ProcessCommandLineArgs(
        parser, Options(**kwargs))

  def PageSelections(self):
    return [story_filter_module.StoryFilter.IsSelected(p) for p in self.pages]

  def testNoFilterMatchesAll(self):
    self.ProcessCommandLineArgs()
    self.assertEquals([True, True, True], self.PageSelections())

  def testBadRegexCallsParserError(self):
    class MockParserException(Exception):
      pass
    class MockParser(object):
      def error(self, _):
        raise MockParserException
    with self.assertRaises(MockParserException):
      self.ProcessCommandLineArgs(parser=MockParser(), story_filter='+')

  def testUniqueSubstring(self):
    self.ProcessCommandLineArgs(story_filter='smile_widen')
    self.assertEquals([True, False, False], self.PageSelections())

  def testSharedSubstring(self):
    self.ProcessCommandLineArgs(story_filter='smile')
    self.assertEquals([True, True, True], self.PageSelections())

  def testNoMatch(self):
    self.ProcessCommandLineArgs(story_filter='frown')
    self.assertEquals([False, False, False], self.PageSelections())

  def testExclude(self):
    self.ProcessCommandLineArgs(story_filter_exclude='ShareA')
    self.assertEquals([True, False, True], self.PageSelections())

  def testExcludeTakesPriority(self):
    self.ProcessCommandLineArgs(
        story_filter='smile',
        story_filter_exclude='wide')
    self.assertEquals([False, True, True], self.PageSelections())

  def testNoNameMatchesDisplayName(self):
    self.ProcessCommandLineArgs(story_filter='share_a/smile')
    self.assertEquals([False, False, True], self.PageSelections())

  def testNotagMatch(self):
    self.ProcessCommandLineArgs(story_tag_filter='tagX')
    self.assertEquals([False, False, False], self.PageSelections())

  def testtagsAllMatch(self):
    self.ProcessCommandLineArgs(story_tag_filter='tag1,tag2')
    self.assertEquals([True, True, True], self.PageSelections())

  def testExcludetagTakesPriority(self):
    self.ProcessCommandLineArgs(
        story_tag_filter='tag1',
        story_tag_filter_exclude='tag2')
    self.assertEquals([False, True, False], self.PageSelections())
