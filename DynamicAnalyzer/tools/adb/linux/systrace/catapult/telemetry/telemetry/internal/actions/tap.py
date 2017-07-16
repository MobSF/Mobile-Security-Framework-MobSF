# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils
from telemetry.util import js_template


class TapAction(page_action.PageAction):
  def __init__(self, selector=None, text=None, element_function=None,
               left_position_percentage=0.5, top_position_percentage=0.5,
               duration_ms=50,
               synthetic_gesture_source=page_action.GESTURE_SOURCE_DEFAULT):
    super(TapAction, self).__init__()
    self.selector = selector
    self.text = text
    self.element_function = element_function
    self.left_position_percentage = left_position_percentage
    self.top_position_percentage = top_position_percentage
    self.duration_ms = duration_ms
    self._synthetic_gesture_source = ('chrome.gpuBenchmarking.%s_INPUT' %
                                      synthetic_gesture_source)

  def WillRunAction(self, tab):
    utils.InjectJavaScript(tab, 'gesture_common.js')
    utils.InjectJavaScript(tab, 'tap.js')

    # Fail if browser doesn't support synthetic tap gestures.
    if not tab.EvaluateJavaScript('window.__TapAction_SupportedByBrowser()'):
      raise page_action.PageActionNotSupported(
          'Synthetic tap not supported for this browser')

    tab.ExecuteJavaScript("""
        window.__tapActionDone = false;
        window.__tapAction = new __TapAction(function() {
          window.__tapActionDone = true;
        });""")

  def HasElementSelector(self):
    return (self.element_function is not None or self.selector is not None or
            self.text is not None)

  def RunAction(self, tab):
    if not self.HasElementSelector():
      self.element_function = 'document.body'

    code = js_template.Render('''
        function(element, errorMsg) {
          if (!element) {
            throw Error('Cannot find element: ' + errorMsg);
          }
          window.__tapAction.start({
            element: element,
            left_position_percentage: {{ left_position_percentage }},
            top_position_percentage: {{ top_position_percentage }},
            duration_ms: {{ duration_ms }},
            gesture_source_type: {{ @gesture_source_type }}
          });
        }''',
        left_position_percentage=self.left_position_percentage,
        top_position_percentage=self.top_position_percentage,
        duration_ms=self.duration_ms,
        gesture_source_type=self._synthetic_gesture_source)

    page_action.EvaluateCallbackWithElement(
        tab, code, selector=self.selector, text=self.text,
        element_function=self.element_function)
    # The second disjunct handles the case where the tap action leads to an
    # immediate navigation (in which case the expression below might already be
    # evaluated on the new page).
    tab.WaitForJavaScriptCondition(
        'window.__tapActionDone || window.__tapAction === undefined',
        timeout=60)
