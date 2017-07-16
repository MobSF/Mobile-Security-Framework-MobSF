# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.internal.actions import seek
from telemetry.testing import tab_test_case

import py_utils


AUDIO_1_SEEKED_CHECK = 'window.__hasEventCompleted("#audio_1", "seeked");'
VIDEO_1_SEEKED_CHECK = 'window.__hasEventCompleted("#video_1", "seeked");'


class SeekActionTest(tab_test_case.TabTestCase):

  def setUp(self):
    tab_test_case.TabTestCase.setUp(self)
    self.Navigate('video_test.html')

  @decorators.Disabled('linux')  # crbug.com/418577
  def testSeekWithNoSelector(self):
    """Tests that with no selector Seek  action seeks first media element."""
    action = seek.SeekAction(seconds=1, timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    action.RunAction(self._tab)
    # Assert only first video has played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_SEEKED_CHECK))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testSeekWithVideoSelector(self):
    """Tests that Seek action seeks video element matching selector."""
    action = seek.SeekAction(seconds=1, selector='#video_1',
                             timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Both videos not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_SEEKED_CHECK))
    action.RunAction(self._tab)
    # Assert only video matching selector has played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_SEEKED_CHECK))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testSeekWithAllSelector(self):
    """Tests that Seek action seeks all video elements with selector='all'."""
    action = seek.SeekAction(seconds=1, selector='all',
                             timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    # Both videos not playing before running action.
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertFalse(self._tab.EvaluateJavaScript(AUDIO_1_SEEKED_CHECK))
    action.RunAction(self._tab)
    # Assert all media elements played.
    self.assertTrue(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertTrue(self._tab.EvaluateJavaScript(AUDIO_1_SEEKED_CHECK))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testSeekWaitForSeekTimeout(self):
    """Tests that wait_for_seeked timeouts if video does not seek."""
    action = seek.SeekAction(seconds=1, selector='#video_1',
                             timeout_in_seconds=0.1)
    action.WillRunAction(self._tab)
    self._tab.EvaluateJavaScript('document.getElementById("video_1").src = ""')
    self.assertFalse(self._tab.EvaluateJavaScript(VIDEO_1_SEEKED_CHECK))
    self.assertRaises(py_utils.TimeoutException, action.RunAction, self._tab)
