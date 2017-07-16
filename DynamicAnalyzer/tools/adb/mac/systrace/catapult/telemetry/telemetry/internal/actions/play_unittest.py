# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.internal.actions import play
from telemetry.testing import tab_test_case

import py_utils


AUDIO_1_PLAYING_CHECK = 'window.__hasEventCompleted("#audio_1", "playing");'
VIDEO_1_PLAYING_CHECK = 'window.__hasEventCompleted("#video_1", "playing");'
VIDEO_1_ENDED_CHECK = 'window.__hasEventCompleted("#video_1", "ended");'


class PlayActionTest(tab_test_case.TabTestCase):

  def setUp(self):
    tab_test_case.TabTestCase.setUp(self)
    self.Navigate('video_test.html')

  @decorators.Disabled('android', 'linux')  # crbug.com/418577
  def testPlayWithNoSelector(self):
    """Tests that with no selector Play action plays first video element."""
    action = play.PlayAction(playing_event_timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Both videos not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))
    action.RunAction(self._tab)
    # Assert only first video has played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))

  @decorators.Disabled('android', 'linux')  # crbug.com/418577
  def testPlayWithVideoSelector(self):
    """Tests that Play action plays video element matching selector."""
    action = play.PlayAction(selector='#video_1',
                             playing_event_timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Both videos not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))
    action.RunAction(self._tab)
    # Assert only video matching selector has played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))

  @decorators.Disabled('android', 'linux')  # crbug.com/418577
  def testPlayWithAllSelector(self):
    """Tests that Play action plays all video elements with selector='all'."""
    action = play.PlayAction(selector='all',
                             playing_event_timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Both videos not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))
    action.RunAction(self._tab)
    # Assert all media elements played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertTrue(self._tab.EvaluateJavaScript(AUDIO_1_PLAYING_CHECK))

  # http://crbug.com/273887
  @decorators.Disabled('linux')  # crbug.com/418577
  def testPlayWaitForPlayTimeout(self):
    """Tests that wait_for_playing timeouts if video does not play."""
    action = play.PlayAction(selector='#video_1',
                             playing_event_timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    self._tab.EvaluateJavaScript('document.getElementById("video_1").src = ""')
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertRaises(py_utils.TimeoutException, action.RunAction, self._tab)

  @decorators.Disabled('android', 'linux')  # crbug.com/418577
  def testPlayWaitForEnded(self):
    """Tests that wait_for_ended waits for video to end."""
    action = play.PlayAction(selector='#video_1',
                             ended_event_timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Assert video not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))
    action.RunAction(self._tab)
    # Assert video ended.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testPlayWithoutWaitForEnded(self):
    """Tests that wait_for_ended waits for video to end."""
    action = play.PlayAction(selector='#video_1',
                             ended_event_timeout_in_seconds=0)
    action.WillRunAction(self._tab)
    # Assert video not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))
    action.RunAction(self._tab)
    # Assert video did not end.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testPlayWaitForEndedTimeout(self):
    """Tests that action raises exception if timeout is reached."""
    action = play.PlayAction(selector='#video_1',
                             ended_event_timeout_in_seconds=0.1)
    action.WillRunAction(self._tab)
    # Assert video not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_PLAYING_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))
    self.assertRaises(py_utils.TimeoutException, action.RunAction, self._tab)
    # Assert video did not end.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_ENDED_CHECK))
