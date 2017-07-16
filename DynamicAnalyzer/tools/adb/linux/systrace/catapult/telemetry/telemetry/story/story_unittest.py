# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import story
from telemetry.story import shared_state


# pylint: disable=abstract-method
class SharedStateBar(shared_state.SharedState):
  pass


class StoryFoo(story.Story):
  def __init__(self, name='', tags=None):
    super(StoryFoo, self).__init__(
        SharedStateBar, name, tags)


class StoryTest(unittest.TestCase):
  def testStoriesHaveDifferentIds(self):
    s0 = story.Story(SharedStateBar, 'foo')
    s1 = story.Story(SharedStateBar, 'bar')
    self.assertNotEqual(s0.id, s1.id)

  def testNamelessStoryDisplayName(self):
    s = StoryFoo()
    self.assertEquals('StoryFoo', s.display_name)

  def testNamedStoryDisplayName(self):
    s = StoryFoo('Bar')
    self.assertEquals('Bar', s.display_name)

  def testStoryFileSafeName(self):
    s = StoryFoo('Foo Bar:Baz~0')
    self.assertEquals('Foo_Bar_Baz_0', s.file_safe_name)

  def testNamelessStoryAsDict(self):
    s = story.Story(SharedStateBar)
    s_dict = s.AsDict()
    self.assertEquals(s_dict['id'], s.id)
    self.assertNotIn('name', s_dict)

  def testNamedStoryAsDict(self):
    s = story.Story(SharedStateBar, 'Foo')
    s_dict = s.AsDict()
    self.assertEquals(s_dict['id'], s.id)
    self.assertEquals('Foo', s_dict['name'])

  def testMakeJavaScriptDeterministic(self):
    s = story.Story(SharedStateBar)
    self.assertTrue(s.make_javascript_deterministic)

    s = story.Story(SharedStateBar, make_javascript_deterministic=False)
    self.assertFalse(s.make_javascript_deterministic)

    s = story.Story(SharedStateBar, make_javascript_deterministic=True)
    self.assertTrue(s.make_javascript_deterministic)
