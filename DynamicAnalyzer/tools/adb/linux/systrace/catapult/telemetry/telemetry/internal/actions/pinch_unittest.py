# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action
from telemetry.testing import tab_test_case


class PinchActionTest(tab_test_case.TabTestCase):
  def setUp(self):
    super(PinchActionTest, self).setUp()

  def testPinchByApiCalledWithCorrectArguments(self):
    self.Navigate('blank.html')
    if not page_action.IsGestureSourceTypeSupported(self._tab, 'touch'):
      return

    action_runner = self._tab.action_runner
    action_runner.ExecuteJavaScript('''
        chrome.gpuBenchmarking.pinchBy = function(
            scaleFactor, anchorLeft, anchorTop, callback, speed) {
          window.__test_scaleFactor = scaleFactor;
          window.__test_anchorLeft = anchorLeft;
          window.__test_anchorTop = anchorTop;
          window.__test_callback = callback;
          window.__test_speed = speed;
          window.__pinchActionDone = true;
        };''')
    action_runner.PinchPage(scale_factor=2)
    self.assertEqual(
        2, action_runner.EvaluateJavaScript('window.__test_scaleFactor'))
    self.assertTrue(
        action_runner.EvaluateJavaScript('!isNaN(window.__test_anchorLeft)'))
    self.assertTrue(
        action_runner.EvaluateJavaScript('!isNaN(window.__test_anchorTop)'))
    self.assertTrue(
        action_runner.EvaluateJavaScript('!!window.__test_callback'))
    self.assertEqual(
        800, action_runner.EvaluateJavaScript('window.__test_speed'))
