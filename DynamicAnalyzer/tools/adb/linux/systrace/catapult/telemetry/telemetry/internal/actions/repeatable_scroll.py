# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import numbers

from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils
from telemetry.web_perf import timeline_interaction_record


class RepeatableScrollAction(page_action.PageAction):

  def __init__(self, x_scroll_distance_ratio=0.0, y_scroll_distance_ratio=0.5,
               repeat_count=0, repeat_delay_ms=250, timeout=60,
               prevent_fling=None, speed=None):
    super(RepeatableScrollAction, self).__init__()
    self._x_scroll_distance_ratio = x_scroll_distance_ratio
    self._y_scroll_distance_ratio = y_scroll_distance_ratio
    self._repeat_count = repeat_count
    self._repeat_delay_ms = repeat_delay_ms
    self._windowsize = []
    self._timeout = timeout
    self._prevent_fling = prevent_fling
    self._speed = speed

  def WillRunAction(self, tab):
    utils.InjectJavaScript(tab, 'gesture_common.js')
    # Get the dimensions of the screen.
    self._windowsize = tab.EvaluateJavaScript(
        '[__GestureCommon_GetWindowWidth(),'
        ' __GestureCommon_GetWindowHeight()]')
    assert len(self._windowsize) == 2
    assert all(isinstance(d, numbers.Number) for d in self._windowsize)

  def RunAction(self, tab):
    # Set up a browser driven repeating scroll. The delay between the scrolls
    # should be unaffected by render thread responsivness (or lack there of).
    tab.SynthesizeScrollGesture(
        x=int(self._windowsize[0] / 2),
        y=int(self._windowsize[1] / 2),
        xDistance=int(self._x_scroll_distance_ratio * self._windowsize[0]),
        yDistance=int(-self._y_scroll_distance_ratio * self._windowsize[1]),
        preventFling=self._prevent_fling,
        speed=self._speed,
        repeatCount=self._repeat_count,
        repeatDelayMs=self._repeat_delay_ms,
        interactionMarkerName=timeline_interaction_record.GetJavaScriptMarker(
            'Gesture_ScrollAction', [timeline_interaction_record.REPEATABLE]),
        timeout=self._timeout)
