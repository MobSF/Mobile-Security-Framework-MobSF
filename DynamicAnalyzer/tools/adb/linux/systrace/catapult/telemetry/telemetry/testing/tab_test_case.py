# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import exceptions
from telemetry.testing import browser_test_case


class TabTestCase(browser_test_case.BrowserTestCase):
  def __init__(self, *args):
    super(TabTestCase, self).__init__(*args)
    self._tab = None

  def setUp(self):
    super(TabTestCase, self).setUp()

    if self._browser.supports_tab_control:
      try:
        while len(self._browser.tabs) < 1:
          self._browser.tabs.New()
        while len(self._browser.tabs) > 1:
          self._browser.tabs[0].Close()
        self._tab = self._browser.tabs[0]
      except exceptions.TimeoutException:
        self._RestartBrowser()
    else:
      self._RestartBrowser()
    self._tab.Navigate('about:blank')
    self._tab.WaitForDocumentReadyStateToBeInteractiveOrBetter()

  def Navigate(self, filename, script_to_evaluate_on_commit=None):
    """Navigates |tab| to |filename| in the unittest data directory.

    Also sets up http server to point to the unittest data directory.
    """
    url = self.UrlOfUnittestFile(filename)
    self._tab.Navigate(url, script_to_evaluate_on_commit)
    self._tab.WaitForDocumentReadyStateToBeComplete()
    self._tab.WaitForFrameToBeDisplayed()

  def _RestartBrowser(self):
    if not self._browser.tabs:
      self.tearDownClass()
      self.setUpClass()
    self._tab = self._browser.tabs[0]

  @property
  def tabs(self):
    return self._browser.tabs
