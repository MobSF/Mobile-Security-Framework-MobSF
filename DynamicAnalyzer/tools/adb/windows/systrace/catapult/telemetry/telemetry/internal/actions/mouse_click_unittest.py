# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import exceptions
from telemetry.internal.actions import mouse_click
from telemetry.testing import tab_test_case


class MouseClickActionTest(tab_test_case.TabTestCase):

  def testMouseClickAction(self):
    self.Navigate('blank.html')

    self._tab.ExecuteJavaScript("""
        (function() {
           function createElement(id, textContent) {
             var el = document.createElement("div");
             el.id = id;
             el.textContent = textContent;
             document.body.appendChild(el);
           }

           createElement('test-1', 'foo');
        })();""")
    i = mouse_click.MouseClickAction(selector='#test-1')
    i.WillRunAction(self._tab)
    i.RunAction(self._tab)
    self.assertTrue(self._tab.EvaluateJavaScript(
        'window.__mouseClickActionDone'))

  def testMouseClickActionOnNonExistingElement(self):
    self.Navigate('blank.html')

    self._tab.ExecuteJavaScript("""
        (function() {
           function createElement(id, textContent) {
             var el = document.createElement("div");
             el.id = id;
             el.textContent = textContent;
             document.body.appendChild(el);
           }

           createElement('test-1', 'foo');
        })();""")
    i = mouse_click.MouseClickAction(selector='#test-2')
    i.WillRunAction(self._tab)
    def WillFail():
      i.RunAction(self._tab)
    self.assertRaises(exceptions.EvaluateException, WillFail)
