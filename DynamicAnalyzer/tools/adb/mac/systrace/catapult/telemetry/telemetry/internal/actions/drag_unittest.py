# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import math

from telemetry import decorators
from telemetry.internal.actions import drag
from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils
from telemetry.testing import tab_test_case


class DragActionTest(tab_test_case.TabTestCase):
  def CheckWithinRange(self, value, expected, error_ratio):
    error_range = abs(expected * error_ratio)
    return abs(value - expected) <= error_range

  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  # crbug.com/483212 (CrOS)
  @decorators.Disabled('android', 'chromeos')
  def testDragAction(self):
    self.Navigate('draggable.html')

    utils.InjectJavaScript(self._tab, 'gesture_common.js')

    div_width = self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).width')
    div_height = self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).height')

    i = drag.DragAction(left_start_ratio=0.5, top_start_ratio=0.5,
            left_end_ratio=0.25, top_end_ratio=0.25)
    try:
      i.WillRunAction(self._tab)
    except page_action.PageActionNotSupported:
      logging.warning('This browser does not support drag gesture. Please try'
                      ' updating chrome.')
      return

    self._tab.ExecuteJavaScript('''
        window.__dragAction.beginMeasuringHook = function() {
            window.__didBeginMeasuring = true;
        };
        window.__dragAction.endMeasuringHook = function() {
            window.__didEndMeasuring = true;
        };''')
    i.RunAction(self._tab)

    self.assertTrue(self._tab.EvaluateJavaScript('window.__didBeginMeasuring'))
    self.assertTrue(self._tab.EvaluateJavaScript('window.__didEndMeasuring'))

    div_position_x = self._tab.EvaluateJavaScript(
        'document.getElementById("drag_div").offsetLeft')
    div_position_y = self._tab.EvaluateJavaScript(
        'document.getElementById("drag_div").offsetTop')

    # 0.25 is the ratio of displacement to the initial size.
    expected_x = math.floor(div_width * -0.25)
    expected_y = math.floor(div_height * -0.25)
    error_ratio = 0.1

    self.assertTrue(
        self.CheckWithinRange(div_position_x, expected_x, error_ratio),
        msg="Moved element's left coordinate: %d, expected: %d" %
        (div_position_x, expected_x))
    self.assertTrue(
        self.CheckWithinRange(div_position_y, expected_y, error_ratio),
        msg="Moved element's top coordinate: %d, expected: %d" %
        (div_position_y, expected_y))
