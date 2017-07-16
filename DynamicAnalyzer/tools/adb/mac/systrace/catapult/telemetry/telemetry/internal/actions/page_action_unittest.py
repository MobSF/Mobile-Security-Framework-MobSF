# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for page_action."""

from telemetry.internal.actions import page_action
from telemetry.testing import tab_test_case


class PageActionTest(tab_test_case.TabTestCase):

  def testEvaluateCallbackWithElement(self):
    self.Navigate('blank.html')
    self._tab.action_runner.ExecuteJavaScript('''
        (function() {
           function createElement(id, textContent) {
             var el = document.createElement("div");
             el.id = id;
             el.textContent = textContent;
             document.body.appendChild(el);
           }

           createElement('test-1', 'foo');
           createElement('test-2', 'bar');
           createElement('test-3', 'baz');
        })();''')
    self.assertEqual(
        'foo',
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el) { return el.textContent; }',
            selector='#test-1'))
    self.assertEqual(
        'bar',
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el) { return el.textContent; }',
            text='bar'))
    self.assertEqual(
        'baz',
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el) { return el.textContent; }',
            element_function='document.getElementById("test-3")'))
    self.assertEqual(
        'baz',
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el) { return el.textContent; }',
            element_function='''
                (function() {
                  return document.getElementById("test-3");
                })()'''))

    # Test for when the element is not found.
    self.assertEqual(
        None,
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el) { return el; }',
            element_function='document.getElementById("test-4")'))

    # Test the info message.
    self.assertEqual(
        'using selector "#test-1"',
        page_action.EvaluateCallbackWithElement(
            self._tab, 'function(el, info) { return info; }',
            selector='#test-1'))

  def testEvaluateCallbackWithElementWithConflictingParams(self):
    def Evaluate1():
      page_action.EvaluateCallbackWithElement(
          self._tab, 'function() {}', selector='div', text='foo')
    self.assertRaises(page_action.PageActionFailed, Evaluate1)

    def Evaluate2():
      page_action.EvaluateCallbackWithElement(
          self._tab, 'function() {}', selector='div', element_function='foo')
    self.assertRaises(page_action.PageActionFailed, Evaluate2)

    def Evaluate3():
      page_action.EvaluateCallbackWithElement(
          self._tab, 'function() {}', text='foo', element_function='')
    self.assertRaises(page_action.PageActionFailed, Evaluate3)
