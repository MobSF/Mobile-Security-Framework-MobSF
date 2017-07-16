# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import story
from telemetry import page


class ExamplePage(page.Page):

  def __init__(self, page_set):
    super(ExamplePage, self).__init__(
        url='https://google.com/search?q=lemon',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    # To see all the web APIs that action_runner supports, see:
    # telemetry.page.action_runner module.

    action_runner.Wait(0.5)
    # Create interaction record will create a region of interest in tracing that
    # cover the wait, tap, and scroll actions nested in the block below.
    with action_runner.CreateInteraction('Scroll-And-Tap'):
      action_runner.Wait(0.3)
      action_runner.ScrollPage()
      action_runner.TapElement(text='Next')
    action_runner.Wait(1)
    with action_runner.CreateInteraction('Scroll'):
      action_runner.ScrollPage()
    with action_runner.CreateInteraction('Wait-two'):
      action_runner.Wait(1)


class SimpleStorySet(story.StorySet):
  def __init__(self):
    super(SimpleStorySet, self).__init__(
        archive_data_file='data/simple_story_set.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)
    self.AddStory(ExamplePage(self))
