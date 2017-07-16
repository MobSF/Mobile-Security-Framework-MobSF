# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry.testing import tab_test_case

import py_utils


class TabConsoleTest(tab_test_case.TabTestCase):
  def testConsoleOutputStream(self):
    self.Navigate('page_that_logs_to_console.html')

    initial = self._tab.EvaluateJavaScript('window.__logCount')
    def GotLog():
      current = self._tab.EvaluateJavaScript('window.__logCount')
      return current > initial
    py_utils.WaitFor(GotLog, 5)

    console_output = (
        self._tab._inspector_backend.GetCurrentConsoleOutputBuffer())
    lines = [l for l in console_output.split('\n') if len(l)]

    self.assertTrue(len(lines) >= 1)
    for line in lines:
      prefix = 'http://(.+)/page_that_logs_to_console.html:9'
      expected_line = r'\(log\) %s: Hello, world' % prefix
      self.assertTrue(re.match(expected_line, line))
