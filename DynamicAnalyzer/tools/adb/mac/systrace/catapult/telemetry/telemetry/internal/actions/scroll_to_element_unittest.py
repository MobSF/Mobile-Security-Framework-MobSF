# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.internal.actions import scroll_to_element
from telemetry.internal.actions import utils
from telemetry.testing import tab_test_case


class ScrollToElementActionTest(tab_test_case.TabTestCase):

  def _MakePageVerticallyScrollable(self):
    # Make page taller than window so it's scrollable vertically.
    self._tab.ExecuteJavaScript('document.body.style.height ='
        '(6 * __GestureCommon_GetWindowHeight() + 1) + "px";')

  def _VisibleAreaOfElement(self, selector='#element'):
    return self._tab.EvaluateJavaScript("""
      (function() {
        var element = document.querySelector({{ selector }});
        var rect = __GestureCommon_GetBoundingVisibleRect(element);
        return rect.width * rect.height;
      })()
    """, selector=selector)

  def _InsertContainer(self, theid='container'):
    self._tab.ExecuteJavaScript("""
      var container = document.createElement("div")
      container.id = {{ theid }};
      container.style.position = 'relative';
      container.style.height = '100%';
      document.body.appendChild(container);
    """, theid=theid)

  def _InsertElement(self, theid='element', container_selector='body'):
    self._tab.ExecuteJavaScript("""
      var container = document.querySelector({{ container_selector }});
      var element = document.createElement("div");
      element.id = {{ theid }};
      element.textContent = 'My element';
      element.style.position = 'absolute';
      element.style.top = (__GestureCommon_GetWindowHeight() * 3) + "px";
      container.appendChild(element);
    """, theid=theid, container_selector=container_selector)

  def setUp(self):
    tab_test_case.TabTestCase.setUp(self)
    self.Navigate('blank.html')
    utils.InjectJavaScript(self._tab, 'gesture_common.js')

  # https://github.com/catapult-project/catapult/issues/3099
  @decorators.Disabled('android')
  def testScrollToElement(self):
    self._MakePageVerticallyScrollable()
    self._InsertElement()
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollTop'), 0)

    # Before we scroll down the element should not be visible at all.
    self.assertEquals(self._VisibleAreaOfElement(), 0)

    i = scroll_to_element.ScrollToElementAction(selector='#element')
    i.WillRunAction(self._tab)
    i.RunAction(self._tab)

    # After we scroll down at least some of the element should be visible.
    self.assertGreater(self._VisibleAreaOfElement(selector='#element'), 0)

  # https://github.com/catapult-project/catapult/issues/3099
  @decorators.Disabled('android')
  def testScrollContainerToElement(self):
    self._MakePageVerticallyScrollable()
    self._InsertContainer()
    self._InsertElement(container_selector='#container')
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.scrollingElement.scrollTop'), 0)

    # Before we scroll down the element should not be visible at all.
    self.assertEquals(self._VisibleAreaOfElement(), 0)

    i = scroll_to_element.ScrollToElementAction(
        selector='#element', container_selector='#container')
    i.WillRunAction(self._tab)
    i.RunAction(self._tab)

    # After we scroll down at least some of the element should be visible.
    self.assertGreater(self._VisibleAreaOfElement(), 0)
