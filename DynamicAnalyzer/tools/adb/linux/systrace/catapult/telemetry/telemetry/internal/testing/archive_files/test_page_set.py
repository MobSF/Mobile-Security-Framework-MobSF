# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import story
from telemetry.page import page
from telemetry.internal.testing.pages.external_page import ExternalPage


class InternalPage(page.Page):
  def __init__(self, story_set):
    super(InternalPage, self).__init__('file://bar.html', story=story_set)

class TestPageSet(story.StorySet):
  """A pageset for testing purpose"""

  def __init__(self):
    super(TestPageSet, self).__init__(
      archive_data_file='data/archive_files/test.json',
      credentials_path='data/credential',
      user_agent_type='desktop',
      bucket=story.PUBLIC_BUCKET)

    #top google property; a google tab is often open
    class Google(page.Page):
      def __init__(self, story_set):
        # pylint: disable=bad-super-call
        super(Google, self).__init__('https://www.google.com',
                                     page_set=story_set)

      def RunGetActionRunner(self, action_runner):
        return action_runner

    self.AddStory(Google(self))
    self.AddStory(InternalPage(self))
    self.AddStory(ExternalPage(self))
