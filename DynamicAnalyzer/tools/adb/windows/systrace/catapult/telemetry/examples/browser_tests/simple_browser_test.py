# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys
import os

from telemetry.testing import serially_executed_browser_test_case


def ConvertPathToTestName(url):
  return url.replace('.', '_')


class SimpleBrowserTest(
    serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase):

  @classmethod
  def GenerateTestCases_JavascriptTest(cls, options):
    del options  # unused
    for path in ['page_with_link.html', 'page_with_clickables.html']:
      yield 'add_1_and_2_' + ConvertPathToTestName(path), (path, 1, 2, 3)

  @classmethod
  def SetUpProcess(cls):
    super(cls, SimpleBrowserTest).SetUpProcess()
    cls.SetBrowserOptions(cls._finder_options)
    cls.StartBrowser()
    cls.action_runner = cls.browser.tabs[0].action_runner
    cls.SetStaticServerDirs(
        [os.path.join(os.path.abspath(__file__), '..', 'pages')])

  def JavascriptTest(self, file_path, num_1, num_2, expected_sum):
    url = self.UrlOfStaticFilePath(file_path)
    self.action_runner.Navigate(url)
    actual_sum = self.action_runner.EvaluateJavaScript(
        '{{ num_1 }} + {{ num_2 }}', num_1=num_1, num_2=num_2)
    self.assertEquals(expected_sum, actual_sum)

  def TestClickablePage(self):
    url = self.UrlOfStaticFilePath('page_with_clickables.html')
    self.action_runner.Navigate(url)
    self.action_runner.ExecuteJavaScript('valueSettableByTest = 1997')
    self.action_runner.ClickElement(text='Click/tap me')
    self.assertEqual(
        1997, self.action_runner.EvaluateJavaScript('valueToTest'))

  def TestAndroidUI(self):
    if self.platform.GetOSName() != 'android':
      self.skipTest('The test is for android only')
    url = self.UrlOfStaticFilePath('page_with_clickables.html')
    # Nativgate to page_with_clickables.html
    self.action_runner.Navigate(url)
    # Click on history
    self.platform.system_ui.WaitForUiNode(
        resource_id='com.google.android.apps.chrome:id/menu_button')
    self.platform.system_ui.GetUiNode(
        resource_id='com.google.android.apps.chrome:id/menu_button').Tap()
    self.platform.system_ui.WaitForUiNode(content_desc='History')
    self.platform.system_ui.GetUiNode(content_desc='History').Tap()
    # Click on the first entry of the history (page_with_clickables.html)
    self.action_runner.WaitForElement('#id-0')
    self.action_runner.ClickElement('#id-0')
    # Verify that the page's js is interactable
    self.action_runner.WaitForElement(text='Click/tap me')
    self.action_runner.ExecuteJavaScript('valueSettableByTest = 1997')
    self.action_runner.ClickElement(text='Click/tap me')
    self.assertEqual(
        1997, self.action_runner.EvaluateJavaScript('valueToTest'))


def load_tests(loader, tests, pattern):
  del loader, tests, pattern  # Unused.
  return serially_executed_browser_test_case.LoadAllTestsInModule(
      sys.modules[__name__])
