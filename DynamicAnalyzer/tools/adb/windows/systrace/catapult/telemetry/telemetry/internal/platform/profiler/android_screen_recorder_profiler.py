# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# devil may not be available if we're not in an Android checkout.
try:
  from devil.android.tools import video_recorder
except ImportError:
  video_recorder = None

from telemetry.internal.platform import profiler
from telemetry.internal.backends.chrome import android_browser_finder


_VIDEO_MEGABITS_PER_SECOND = 4


class AndroidScreenRecordingProfiler(profiler.Profiler):
  """Captures a screen recording on Android."""

  def __init__(self, browser_backend, platform_backend, output_path, state):
    super(AndroidScreenRecordingProfiler, self).__init__(
        browser_backend, platform_backend, output_path, state)
    self._output_path = output_path + '.mp4'
    self._recorder = video_recorder.VideoRecorder(
        browser_backend.device,
        megabits_per_second=_VIDEO_MEGABITS_PER_SECOND)
    self._recorder.Start()

  @classmethod
  def name(cls):
    return 'android-screen-recorder'

  @classmethod
  def is_supported(cls, browser_type):
    if browser_type == 'any':
      return android_browser_finder.CanFindAvailableBrowsers()
    return browser_type.startswith('android')

  def CollectProfile(self):
    self._recorder.Stop()
    self._recorder.Pull(self._output_path)

    print 'Screen recording saved as %s' % self._output_path
    print 'To view, open in Chrome or a video player'
    return [self._output_path]
