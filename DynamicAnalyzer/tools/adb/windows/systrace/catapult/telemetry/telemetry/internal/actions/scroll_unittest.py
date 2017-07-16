# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.internal.actions import scroll
from telemetry.internal.actions import utils
from telemetry.testing import tab_test_case

class ScrollActionTest(tab_test_case.TabTestCase):
  def _MakePageVerticallyScrollable(self):
    # Make page taller than window so it's scrollable vertically.
    self._tab.ExecuteJavaScript('document.body.style.height ='
        '(3 * __GestureCommon_GetWindowHeight() + 1) + "px";')

  def _MakePageHorizontallyScrollable(self):
    # Make page wider than window so it's scrollable horizontally.
    self._tab.ExecuteJavaScript('document.body.style.width ='
        '(3 * __GestureCommon_GetWindowWidth() + 1) + "px";')

  def setUp(self):
    tab_test_case.TabTestCase.setUp(self)
    self.Navigate('blank.html')
    utils.InjectJavaScript(self._tab, 'gesture_common.js')

  def testScrollAction(self):

    self._MakePageVerticallyScrollable()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollTop'), 0)

    i = scroll.ScrollAction()
    i.WillRunAction(self._tab)

    self._tab.ExecuteJavaScript("""
        window.__scrollAction.beginMeasuringHook = function() {
            window.__didBeginMeasuring = true;
        };
        window.__scrollAction.endMeasuringHook = function() {
            window.__didEndMeasuring = true;
        };""")
    i.RunAction(self._tab)

    self.assertTrue(self._tab.EvaluateJavaScript('window.__didBeginMeasuring'))
    self.assertTrue(self._tab.EvaluateJavaScript('window.__didEndMeasuring'))

    scroll_position = self._tab.EvaluateJavaScript(
        'document.scrollingElement.scrollTop')
    self.assertTrue(scroll_position != 0,
                    msg='scroll_position=%d;' % (scroll_position))

  # https://github.com/catapult-project/catapult/issues/3099
  @decorators.Disabled('android')
  def testDiagonalScrollAction(self):
    # Diagonal scrolling was not supported in the ScrollAction until Chrome
    # branch number 2332
    branch_num = self._tab.browser._browser_backend.devtools_client \
        .GetChromeBranchNumber()
    if branch_num < 2332:
      return

    self._MakePageVerticallyScrollable()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollTop'), 0)

    self._MakePageHorizontallyScrollable()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollLeft'),
        0)

    i = scroll.ScrollAction(direction='downright')
    i.WillRunAction(self._tab)

    i.RunAction(self._tab)

    viewport_top = self._tab.EvaluateJavaScript(
        'document.scrollingElement.scrollTop')
    self.assertTrue(viewport_top != 0, msg='viewport_top=%d;' % viewport_top)

    viewport_left = self._tab.EvaluateJavaScript(
        'document.scrollingElement.scrollLeft')
    self.assertTrue(viewport_left != 0, msg='viewport_left=%d;' % viewport_left)

  def testBoundingClientRect(self):
    # Verify that the rect returned by getBoundingVisibleRect() in scroll.js is
    # completely contained within the viewport. Scroll events dispatched by the
    # scrolling API use the center of this rect as their location, and this
    # location needs to be within the viewport bounds to correctly decide
    # between main-thread and impl-thread scroll. If the scrollable area were
    # not clipped to the viewport bounds, then the instance used here (the
    # scrollable area being more than twice as tall as the viewport) would
    # result in a scroll location outside of the viewport bounds.
    self._MakePageVerticallyScrollable()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollTop'), 0)

    self._MakePageHorizontallyScrollable()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollLeft'),
        0)

    self._tab.ExecuteJavaScript("""
        window.scrollTo(__GestureCommon_GetWindowWidth(),
                        __GestureCommon_GetWindowHeight());""")

    rect_top = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).top'))
    rect_height = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).height'))
    rect_bottom = rect_top + rect_height

    rect_left = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).left'))
    rect_width = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetBoundingVisibleRect(document.body).width'))
    rect_right = rect_left + rect_width

    viewport_height = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetWindowHeight()'))
    viewport_width = int(self._tab.EvaluateJavaScript(
        '__GestureCommon_GetWindowWidth()'))

    self.assertTrue(rect_top >= 0,
        msg='%s >= %s' % (rect_top, 0))
    self.assertTrue(rect_left >= 0,
        msg='%s >= %s' % (rect_left, 0))
    self.assertTrue(rect_bottom <= viewport_height,
        msg='%s + %s <= %s' % (rect_top, rect_height, viewport_height))
    self.assertTrue(rect_right <= viewport_width,
        msg='%s + %s <= %s' % (rect_left, rect_width, viewport_width))
