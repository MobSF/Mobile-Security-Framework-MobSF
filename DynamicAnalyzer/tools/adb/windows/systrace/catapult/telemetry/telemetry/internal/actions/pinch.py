# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils
from telemetry.util import js_template


class PinchAction(page_action.PageAction):
  def __init__(self, selector=None, text=None, element_function=None,
               left_anchor_ratio=0.5, top_anchor_ratio=0.5,
               scale_factor=None, speed_in_pixels_per_second=800,
               synthetic_gesture_source=page_action.GESTURE_SOURCE_DEFAULT):
    super(PinchAction, self).__init__()
    self._selector = selector
    self._text = text
    self._element_function = element_function
    self._left_anchor_ratio = left_anchor_ratio
    self._top_anchor_ratio = top_anchor_ratio
    self._scale_factor = scale_factor
    self._speed = speed_in_pixels_per_second
    self._synthetic_gesture_source = ('chrome.gpuBenchmarking.%s_INPUT' %
                                      synthetic_gesture_source)

    if (self._selector is None and self._text is None and
        self._element_function is None):
      self._element_function = 'document.body'

  def WillRunAction(self, tab):
    utils.InjectJavaScript(tab, 'gesture_common.js')
    utils.InjectJavaScript(tab, 'pinch.js')

    # Fail if browser doesn't support synthetic pinch gestures.
    if not tab.EvaluateJavaScript('window.__PinchAction_SupportedByBrowser()'):
      raise page_action.PageActionNotSupported(
          'Synthetic pinch not supported for this browser')

    tab.ExecuteJavaScript("""
        window.__pinchActionDone = false;
        window.__pinchAction = new __PinchAction(function() {
          window.__pinchActionDone = true;
        });""")

  @staticmethod
  def _GetDefaultScaleFactorForPage(tab):
    current_scale_factor = tab.EvaluateJavaScript(
        'window.outerWidth / window.innerWidth')
    return 3.0 / current_scale_factor

  def RunAction(self, tab):
    scale_factor = (self._scale_factor if self._scale_factor else
                    PinchAction._GetDefaultScaleFactorForPage(tab))
    code = js_template.Render('''
        function(element, info) {
          if (!element) {
            throw Error('Cannot find element: ' + info);
          }
          window.__pinchAction.start({
            element: element,
            left_anchor_ratio: {{ left_anchor_ratio }},
            top_anchor_ratio: {{ top_anchor_ratio }},
            scale_factor: {{ scale_factor }},
            speed: {{ speed }}
          });
        }''',
        left_anchor_ratio=self._left_anchor_ratio,
        top_anchor_ratio=self._top_anchor_ratio,
        scale_factor=scale_factor,
        speed=self._speed)
    page_action.EvaluateCallbackWithElement(
        tab, code, selector=self._selector, text=self._text,
        element_function=self._element_function)
    tab.WaitForJavaScriptCondition('window.__pinchActionDone', timeout=60)
