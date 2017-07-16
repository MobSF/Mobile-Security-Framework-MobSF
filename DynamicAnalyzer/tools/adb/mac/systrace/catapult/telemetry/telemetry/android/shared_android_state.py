# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.core import android_platform
from telemetry.core import platform
from telemetry.internal.platform import android_device
from telemetry import story as story_module
from telemetry.web_perf import timeline_based_measurement


class SharedAndroidState(story_module.SharedState):
  """Manage test state/transitions across multiple android.AndroidStory's.

  WARNING: the class is not ready for public consumption.
  Email telemetry@chromium.org if you feel like you must use it.
  """

  def __init__(self, test, finder_options, story_set):
    """This method is styled on unittest.TestCase.setUpClass.

    Args:
      test: a web_perf.TimelineBasedMeasurement instance.
      options: a BrowserFinderOptions instance with command line options.
      story_set: a story.StorySet instance.
    """
    super(SharedAndroidState, self).__init__(test, finder_options, story_set)
    if not isinstance(
        test, timeline_based_measurement.TimelineBasedMeasurement):
      raise ValueError(
          'SharedAndroidState only accepts TimelineBasedMeasurement tests'
          ' (not %s).' % test.__class__)
    self._test = test
    self._finder_options = finder_options
    self._android_app = None
    self._current_story = None
    device = android_device.GetDevice(finder_options)
    assert device, 'Android device required.'
    self._android_platform = platform.GetPlatformForDevice(
        device, finder_options)
    assert self._android_platform, 'Unable to create android platform.'
    assert isinstance(
        self._android_platform, android_platform.AndroidPlatform)

  @property
  def app(self):
    return self._android_app

  @property
  def platform(self):
    return self._android_platform

  def WillRunStory(self, story):
    assert not self._android_app
    self._current_story = story
    self._android_app = self._android_platform.LaunchAndroidApplication(
        story.start_intent, story.is_app_ready_predicate)
    self._test.WillRunStory(self._android_platform.tracing_controller)

  def CanRunStory(self, story):
    """This does not apply to android app stories."""
    return True

  def RunStory(self, results):
    self._current_story.Run(self)
    self._test.Measure(self._android_platform.tracing_controller, results)

  def DidRunStory(self, results):
    self._test.DidRunStory(self._android_platform.tracing_controller)
    if self._android_app:
      self._android_app.Close()
      self._android_app = None

  def TearDownState(self):
    """Tear down anything created in the __init__ method that is not needed.

    Currently, there is no clean-up needed from SharedAndroidState.__init__.
    """
    pass

  def DumpStateUponFailure(self, story, results):
    # TODO: Dump the state of the Android app.
    pass
