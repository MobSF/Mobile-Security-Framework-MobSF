# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import navigate
from telemetry.testing import tab_test_case


class NavigateActionTest(tab_test_case.TabTestCase):
  def testNavigateAction(self):
    i = navigate.NavigateAction(url=self.UrlOfUnittestFile('blank.html'))
    i.RunAction(self._tab)
    self.assertEquals(
        self._tab.EvaluateJavaScript('document.location.pathname;'),
        '/blank.html')
