# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils
from telemetry.util import js_template


class ScrollAction(page_action.PageAction):
  # TODO(chrishenry): Ignore attributes, to be deleted when usage in
  # other repo is cleaned up.
  def __init__(self, selector=None, text=None, element_function=None,
               left_start_ratio=0.5, top_start_ratio=0.5, direction='down',
               distance=None, distance_expr=None,
               speed_in_pixels_per_second=800, use_touch=False,
               synthetic_gesture_source=page_action.GESTURE_SOURCE_DEFAULT):
    super(ScrollAction, self).__init__()
    if direction not in ('down', 'up', 'left', 'right',
                         'downleft', 'downright',
                         'upleft', 'upright'):
      raise page_action.PageActionNotSupported(
          'Invalid scroll direction: %s' % self.direction)
    self._selector = selector
    self._text = text
    self._element_function = element_function
    self._left_start_ratio = left_start_ratio
    self._top_start_ratio = top_start_ratio
    self._direction = direction
    self._speed = speed_in_pixels_per_second
    self._use_touch = use_touch
    self._synthetic_gesture_source = ('chrome.gpuBenchmarking.%s_INPUT' %
                                      synthetic_gesture_source)

    self._distance_func = js_template.RenderValue(None)
    if distance:
      assert not distance_expr
      distance_expr = str(distance)
    if distance_expr:
      self._distance_func = js_template.Render(
          'function() { return 0 + {{ @expr }}; }', expr=distance_expr)

  def WillRunAction(self, tab):
    if self._direction in ('downleft', 'downright', 'upleft', 'upright'):
      # Diagonal scrolling support was added in Chrome branch number 2332.
      branch_num = (
          tab.browser._browser_backend.devtools_client.GetChromeBranchNumber())
      if branch_num < 2332:
        raise ValueError('Diagonal scrolling requires Chrome branch number'
                         ' 2332 or later. Found branch number %d' %
                         branch_num)
    utils.InjectJavaScript(tab, 'gesture_common.js')
    utils.InjectJavaScript(tab, 'scroll.js')

    # Fail if browser doesn't support synthetic scroll gestures.
    if not tab.EvaluateJavaScript(
        'window.__ScrollAction_SupportedByBrowser()'):
      raise page_action.PageActionNotSupported(
          'Synthetic scroll not supported for this browser')

    # Fail if this action requires touch and we can't send touch events.
    if self._use_touch:
      if not page_action.IsGestureSourceTypeSupported(tab, 'touch'):
        raise page_action.PageActionNotSupported(
            'Touch scroll not supported for this browser')

      if (self._synthetic_gesture_source ==
          'chrome.gpuBenchmarking.MOUSE_INPUT'):
        raise page_action.PageActionNotSupported(
            'Scroll requires touch on this page but mouse input was requested')

    tab.ExecuteJavaScript("""
        window.__scrollActionDone = false;
        window.__scrollAction = new __ScrollAction(
            {{ @callback }}, {{ @distance }});""",
        callback='function() { window.__scrollActionDone = true; }',
        distance=self._distance_func)

  def RunAction(self, tab):
    if (self._selector is None and self._text is None and
        self._element_function is None):
      self._element_function = '(document.scrollingElement || document.body)'

    gesture_source_type = self._synthetic_gesture_source
    if self._use_touch:
      gesture_source_type = 'chrome.gpuBenchmarking.TOUCH_INPUT'

    code = js_template.Render('''
        function(element, info) {
          if (!element) {
            throw Error('Cannot find element: ' + info);
          }
          window.__scrollAction.start({
            element: element,
            left_start_ratio: {{ left_start_ratio }},
            top_start_ratio: {{ top_start_ratio }},
            direction: {{ direction }},
            speed: {{ speed }},
            gesture_source_type: {{ @gesture_source_type }}
          });
        }''',
        left_start_ratio=self._left_start_ratio,
        top_start_ratio=self._top_start_ratio,
        direction=self._direction,
        speed=self._speed,
        gesture_source_type=gesture_source_type)
    page_action.EvaluateCallbackWithElement(
        tab, code, selector=self._selector, text=self._text,
        element_function=self._element_function)
    tab.WaitForJavaScriptCondition('window.__scrollActionDone', timeout=60)
