# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.android import shared_android_state
from telemetry import story

class AndroidStory(story.Story):
  def __init__(self, start_intent, is_app_ready_predicate=None,
               name='', tags=None, is_local=False):
    """Creates a new story for Android app.

    Args:
      start_intent: See AndroidPlatform.LaunchAndroidApplication.
      is_app_ready_predicate: See AndroidPlatform.LaunchAndroidApplication.
      name: See Story.__init__.
      tags: See Story.__init__
      is_app_ready_predicate: See Story.__init__.
    """
    super(AndroidStory, self).__init__(
        shared_android_state.SharedAndroidState, name=name, tags=tags,
        is_local=is_local)
    self.start_intent = start_intent
    self.is_app_ready_predicate = is_app_ready_predicate

  def Run(self, shared_state):
    """Execute the interactions with the applications."""
    raise NotImplementedError
