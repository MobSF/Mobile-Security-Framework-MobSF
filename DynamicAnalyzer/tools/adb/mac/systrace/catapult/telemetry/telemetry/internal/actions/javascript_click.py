# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import page_action


class ClickElementAction(page_action.PageAction):
  def __init__(self, selector=None, text=None, element_function=None):
    super(ClickElementAction, self).__init__()
    self.selector = selector
    self.text = text
    self.element_function = element_function

  def RunAction(self, tab):
    code = '''
        function(element, errorMsg) {
          if (!element) {
            throw Error('Cannot find element: ' + errorMsg);
          }
          element.click();
        }'''
    page_action.EvaluateCallbackWithElement(
        tab, code, selector=self.selector, text=self.text,
        element_function=self.element_function)
