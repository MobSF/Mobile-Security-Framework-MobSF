# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class Failure(Exception):
  """StoryTest Exception raised when an undesired but designed-for problem."""


class StoryTest(object):
  """A class for creating story tests.

  The overall test run control flow follows this order:
    test.WillRunStory
    state.WillRunStory
    state.RunStory
    test.Measure
    state.DidRunStory
    test.DidRunStory
  """

  def WillRunStory(self, platform):
    """Override to do any action before running the story.

    This is run before state.WillRunStory.
    Args:
      platform: The platform that the story will run on.
    """
    raise NotImplementedError()

  def Measure(self, platform, results):
    """Override to take the measurement.

    This is run only if state.RunStory is successful.
    Args:
      platform: The platform that the story will run on.
      results: The results of running the story.
    """
    raise NotImplementedError()

  def DidRunStory(self, platform):
    """Override to do any action after running the story, e.g., clean up.

    This is run after state.DidRunStory. And this is always called even if the
    test run failed.
    Args:
      platform: The platform that the story will run on.
    """
    raise NotImplementedError()
