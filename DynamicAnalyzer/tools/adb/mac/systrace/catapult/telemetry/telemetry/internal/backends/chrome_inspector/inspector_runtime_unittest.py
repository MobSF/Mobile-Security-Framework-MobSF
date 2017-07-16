# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import exceptions
from telemetry.testing import tab_test_case

import py_utils


class InspectorRuntimeTest(tab_test_case.TabTestCase):
  def testRuntimeEvaluateSimple(self):
    res = self._tab.EvaluateJavaScript('1+1')
    assert res == 2

  def testRuntimeEvaluateThatFails(self):
    with self.assertRaises(exceptions.EvaluateException) as ex_context:
      self._tab.EvaluateJavaScript('var x = 1;\nfsdfsdfsf')
    exception_message = str(ex_context.exception)
    self.assertIn('ReferenceError: fsdfsdfsf is not defined', exception_message)

  def testRuntimeEvaluateOfSomethingThatCantJSONize(self):

    def test():
      self._tab.EvaluateJavaScript("""
        var cur = {};
        var root = {next: cur};
        for (var i = 0; i < 1000; i++) {
          next = {};
          cur.next = next;
          cur = next;
        }
        root;""")
    self.assertRaises(exceptions.EvaluateException, test)

  def testRuntimeExecuteOfSomethingThatCantJSONize(self):
    self._tab.ExecuteJavaScript('window')

  def testIFrame(self):
    starting_contexts = self._tab.EnableAllContexts()

    self.Navigate('host.html')

    # Access host page.
    test_defined_js = "typeof(testVar) != 'undefined'"
    self._tab.WaitForJavaScriptCondition(test_defined_js, timeout=10)

    py_utils.WaitFor(lambda: self._tab.EnableAllContexts() != starting_contexts,
                 timeout=10)

    self.assertEquals(self._tab.EvaluateJavaScript('testVar'), 'host')

    def TestVarReady(context_id):
      """Returns True if the context and testVar are both ready."""
      try:
        return self._tab.EvaluateJavaScript(
            test_defined_js, context_id=context_id)
      except exceptions.EvaluateException:
        # This happens when the context is not ready.
        return False

    def TestVar(context_id):
      """Waits for testVar and the context to be ready, then returns the value
      of testVar."""
      py_utils.WaitFor(lambda: TestVarReady(context_id), timeout=10)
      return self._tab.EvaluateJavaScript('testVar', context_id=context_id)

    all_contexts = self._tab.EnableAllContexts()
    # Access parent page using EvaluateJavaScriptInContext.
    self.assertEquals(TestVar(context_id=all_contexts-3), 'host')

    # Access the iframes without guarantees on which order they loaded.
    iframe1 = TestVar(context_id=all_contexts-2)
    iframe2 = TestVar(context_id=all_contexts-1)
    iframe3 = TestVar(context_id=all_contexts)
    self.assertEqual(set([iframe1, iframe2, iframe3]),
                     set(['iframe1', 'iframe2', 'iframe3']))

    # Accessing a non-existent iframe throws an exception.
    self.assertRaises(exceptions.EvaluateException,
        lambda: self._tab.EvaluateJavaScript(
            '1+1', context_id=all_contexts + 1))
