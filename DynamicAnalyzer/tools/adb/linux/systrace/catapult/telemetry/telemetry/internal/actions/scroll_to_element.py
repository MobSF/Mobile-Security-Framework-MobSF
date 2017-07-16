# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action
from telemetry.internal.actions.scroll import ScrollAction
from telemetry.util import js_template


class ScrollToElementAction(page_action.PageAction):


  def __init__(self, selector=None, element_function=None,
               container_selector=None, container_element_function=None,
               speed_in_pixels_per_second=800):
    """Perform scroll gesture on container until an element is in view.

    Both the element and the container can be specified by a CSS selector
    xor a JavaScript function, provided as a string, which returns an element.
    The element is required so exactly one of selector and element_function
    must be provided. The container is optional so at most one of
    container_selector and container_element_function can be provided.
    The container defaults to document.scrollingElement or document.body if
    scrollingElement is not set.

    Args:
      selector: A CSS selector describing the element.
      element_function: A JavaScript function (as string) that is used
          to retrieve the element. For example:
          'function() { return foo.element; }'.
      container_selector: A CSS selector describing the container element.
      container_element_function: A JavaScript function (as a string) that is
          used to retrieve the container element.
      speed_in_pixels_per_second: Speed to scroll.
    """
    super(ScrollToElementAction, self).__init__()
    self._selector = selector
    self._element_function = element_function
    self._container_selector = container_selector
    self._container_element_function = container_element_function
    self._speed = speed_in_pixels_per_second
    self._distance = None
    self._direction = None
    self._scroller = None
    assert (self._selector or self._element_function), (
        'Must have either selector or element function')

  def WillRunAction(self, tab):
    if self._selector:
      element = js_template.Render(
          'document.querySelector({{ selector }})', selector=self._selector)
    else:
      element = self._element_function

    self._distance = tab.EvaluateJavaScript('''
        (function(elem){
          var rect = elem.getBoundingClientRect();
          if (rect.bottom < 0) {
            // The bottom of the element is above the viewport.
            // Scroll up until the top of the element is on screen.
            return rect.top - (window.innerHeight / 2);
          }
          if (rect.top - window.innerHeight >= 0) {
            // rect.top provides the pixel offset of the element from the
            // top of the page. Because that exceeds the viewport's height,
            // we know that the element is below the viewport.
            return rect.top - (window.innerHeight / 2);
          }
          return 0;
        })({{ @element }});
        ''', element=element)
    self._direction = 'down' if self._distance > 0 else 'up'
    self._distance = abs(self._distance)
    self._scroller = ScrollAction(
        direction=self._direction,
        selector=self._container_selector,
        element_function=self._container_element_function,
        distance=self._distance,
        speed_in_pixels_per_second=self._speed)

  def RunAction(self, tab):
    if self._distance == 0:  # Element is already in view.
      return
    self._scroller.WillRunAction(tab)
    self._scroller.RunAction(tab)
