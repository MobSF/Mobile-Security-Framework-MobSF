# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import shutil
import tempfile
import unittest

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.browser import browser as browser_module
from telemetry.internal.browser import browser_finder
from telemetry.internal.platform import gpu_device
from telemetry.internal.platform import gpu_info
from telemetry.internal.platform import system_info
from telemetry.internal.util import path
from telemetry.testing import browser_test_case
from telemetry.testing import options_for_unittests
from telemetry.timeline import tracing_config

import mock
import py_utils

class IntentionalException(Exception):
  pass


class BrowserTest(browser_test_case.BrowserTestCase):
  def testBrowserCreation(self):
    self.assertEquals(1, len(self._browser.tabs))

    # Different browsers boot up to different things.
    assert self._browser.tabs[0].url

  @decorators.Enabled('has tabs')
  def testNewCloseTab(self):
    existing_tab = self._browser.tabs[0]
    self.assertEquals(1, len(self._browser.tabs))
    existing_tab_url = existing_tab.url

    new_tab = self._browser.tabs.New()
    self.assertEquals(2, len(self._browser.tabs))
    self.assertEquals(existing_tab.url, existing_tab_url)
    self.assertEquals(new_tab.url, 'about:blank')

    new_tab.Close()
    self.assertEquals(1, len(self._browser.tabs))
    self.assertEquals(existing_tab.url, existing_tab_url)

  def testMultipleTabCalls(self):
    self._browser.tabs[0].Navigate(self.UrlOfUnittestFile('blank.html'))
    self._browser.tabs[0].WaitForDocumentReadyStateToBeInteractiveOrBetter()

  def testTabCallByReference(self):
    tab = self._browser.tabs[0]
    tab.Navigate(self.UrlOfUnittestFile('blank.html'))
    self._browser.tabs[0].WaitForDocumentReadyStateToBeInteractiveOrBetter()

  @decorators.Enabled('has tabs')
  def testCloseReferencedTab(self):
    self._browser.tabs.New()
    tab = self._browser.tabs[0]
    tab.Navigate(self.UrlOfUnittestFile('blank.html'))
    tab.Close()
    self.assertEquals(1, len(self._browser.tabs))

  @decorators.Enabled('has tabs')
  def testForegroundTab(self):
    # Should be only one tab at this stage, so that must be the foreground tab
    original_tab = self._browser.tabs[0]
    self.assertEqual(self._browser.foreground_tab, original_tab)
    new_tab = self._browser.tabs.New()
    # New tab shouls be foreground tab
    self.assertEqual(self._browser.foreground_tab, new_tab)
    # Make sure that activating the background tab makes it the foreground tab
    original_tab.Activate()
    self.assertEqual(self._browser.foreground_tab, original_tab)
    # Closing the current foreground tab should switch the foreground tab to the
    # other tab
    original_tab.Close()
    self.assertEqual(self._browser.foreground_tab, new_tab)

  # This test uses the reference browser and doesn't have access to
  # helper binaries like crashpad_database_util.
  @decorators.Enabled('linux')
  def testGetMinidumpPathOnCrash(self):
    tab = self._browser.tabs[0]
    with self.assertRaises(exceptions.AppCrashException):
      tab.Navigate('chrome://crash', timeout=5)
    crash_minidump_path = self._browser.GetMostRecentMinidumpPath()
    self.assertIsNotNone(crash_minidump_path)

  def testGetSystemInfo(self):
    if not self._browser.supports_system_info:
      logging.warning(
          'Browser does not support getting system info, skipping test.')
      return

    info = self._browser.GetSystemInfo()

    self.assertTrue(isinstance(info, system_info.SystemInfo))
    self.assertTrue(hasattr(info, 'model_name'))
    self.assertTrue(hasattr(info, 'gpu'))
    self.assertTrue(isinstance(info.gpu, gpu_info.GPUInfo))
    self.assertTrue(hasattr(info.gpu, 'devices'))
    self.assertTrue(len(info.gpu.devices) > 0)
    for g in info.gpu.devices:
      self.assertTrue(isinstance(g, gpu_device.GPUDevice))

  def testGetSystemInfoNotCachedObject(self):
    if not self._browser.supports_system_info:
      logging.warning(
          'Browser does not support getting system info, skipping test.')
      return

    info_a = self._browser.GetSystemInfo()
    info_b = self._browser.GetSystemInfo()
    self.assertFalse(info_a is info_b)

  def testGetSystemTotalMemory(self):
    self.assertTrue(self._browser.memory_stats['SystemTotalPhysicalMemory'] > 0)


  # crbug.com/628836 (CrOS, where system-guest indicates ChromeOS guest)
  # github.com/catapult-project/catapult/issues/3130 (Windows)
  @decorators.Disabled('cros-chrome-guest', 'system-guest', 'chromeos', 'win')
  def testIsTracingRunning(self):
    tracing_controller = self._browser.platform.tracing_controller
    if not tracing_controller.IsChromeTracingSupported():
      return
    self.assertFalse(tracing_controller.is_tracing_running)
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    tracing_controller.StartTracing(config)
    self.assertTrue(tracing_controller.is_tracing_running)
    tracing_controller.StopTracing()
    self.assertFalse(tracing_controller.is_tracing_running)


class CommandLineBrowserTest(browser_test_case.BrowserTestCase):
  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.AppendExtraBrowserArgs('--user-agent=telemetry')

  def testCommandLineOverriding(self):
    # This test starts the browser with --user-agent=telemetry. This tests
    # whether the user agent is then set.
    t = self._browser.tabs[0]
    t.Navigate(self.UrlOfUnittestFile('blank.html'))
    t.WaitForDocumentReadyStateToBeInteractiveOrBetter()
    self.assertEquals(t.EvaluateJavaScript('navigator.userAgent'),
                      'telemetry')

class DirtyProfileBrowserTest(browser_test_case.BrowserTestCase):
  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.profile_type = 'small_profile'

  @decorators.Disabled('chromeos')  # crbug.com/243912
  def testDirtyProfileCreation(self):
    self.assertEquals(1, len(self._browser.tabs))


class BrowserLoggingTest(browser_test_case.BrowserTestCase):
  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.logging_verbosity = options.VERBOSE_LOGGING

  @decorators.Disabled('chromeos', 'android')
  def testLogFileExist(self):
    self.assertTrue(
       os.path.isfile(self._browser._browser_backend.log_file_path))


def _GenerateBrowserProfile(number_of_tabs):
  """ Generate a browser profile which browser had |number_of_tabs| number of
  tabs opened before it was closed.
      Returns:
        profile_dir: the directory of profile.
  """
  profile_dir = tempfile.mkdtemp()
  options = options_for_unittests.GetCopy()
  options.browser_options.output_profile_path = profile_dir
  browser_to_create = browser_finder.FindBrowser(options)
  browser_to_create.platform.network_controller.InitializeIfNeeded()
  try:
    with browser_to_create.Create(options) as browser:
      browser.platform.SetHTTPServerDirectories(path.GetUnittestDataDir())
      blank_file_path = os.path.join(path.GetUnittestDataDir(), 'blank.html')
      blank_url = browser.platform.http_server.UrlOf(blank_file_path)
      browser.foreground_tab.Navigate(blank_url)
      browser.foreground_tab.WaitForDocumentReadyStateToBeComplete()
      for _ in xrange(number_of_tabs - 1):
        tab = browser.tabs.New()
        tab.Navigate(blank_url)
        tab.WaitForDocumentReadyStateToBeComplete()
    return profile_dir
  finally:
    browser_to_create.platform.network_controller.Close()


class BrowserCreationTest(unittest.TestCase):
  def setUp(self):
    self.mock_browser_backend = mock.MagicMock()
    self.mock_platform_backend = mock.MagicMock()

  def testCleanedUpCalledWhenExceptionRaisedInBrowserCreation(self):
    self.mock_platform_backend.platform.FlushDnsCache.side_effect = (
        IntentionalException('Boom!'))
    with self.assertRaises(IntentionalException):
      browser_module.Browser(
         self.mock_browser_backend, self.mock_platform_backend,
         credentials_path=None)
    self.assertTrue(self.mock_platform_backend.WillCloseBrowser.called)

  def testOriginalExceptionNotSwallow(self):
    self.mock_platform_backend.platform.FlushDnsCache.side_effect = (
        IntentionalException('Boom!'))
    self.mock_platform_backend.WillCloseBrowser.side_effect = (
        IntentionalException('Cannot close browser!'))
    with self.assertRaises(IntentionalException) as context:
      browser_module.Browser(
         self.mock_browser_backend, self.mock_platform_backend,
         credentials_path=None)
    self.assertIn('Boom!', context.exception.message)


class BrowserRestoreSessionTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls._number_of_tabs = 4
    cls._profile_dir = _GenerateBrowserProfile(cls._number_of_tabs)
    cls._options = options_for_unittests.GetCopy()
    cls._options.browser_options.AppendExtraBrowserArgs(
        ['--restore-last-session'])
    cls._options.browser_options.profile_dir = cls._profile_dir
    cls._browser_to_create = browser_finder.FindBrowser(cls._options)
    cls._browser_to_create.platform.network_controller.InitializeIfNeeded()

  @decorators.Enabled('has tabs')
  @decorators.Disabled('chromeos', 'win', 'mac')
  # TODO(nednguyen): Enable this test on windowsn platform
  def testRestoreBrowserWithMultipleTabs(self):
    with self._browser_to_create.Create(self._options) as browser:
      # The number of tabs will be self._number_of_tabs + 1 as it includes the
      # old tabs and a new blank tab.
      expected_number_of_tabs = self._number_of_tabs + 1
      try:
        py_utils.WaitFor(
            lambda: len(browser.tabs) == expected_number_of_tabs, 10)
      except:
        logging.error('Number of tabs is %s' % len(browser.tabs))
        raise
      self.assertEquals(expected_number_of_tabs, len(browser.tabs))

  @classmethod
  def tearDownClass(cls):
    cls._browser_to_create.platform.network_controller.Close()
    shutil.rmtree(cls._profile_dir)


class TestBrowserOperationDoNotLeakTempFiles(unittest.TestCase):

  @decorators.Enabled('win', 'mac', 'linux')
  @decorators.Isolated
  def testBrowserNotLeakingTempFiles(self):
    options = options_for_unittests.GetCopy()
    browser_to_create = browser_finder.FindBrowser(options)
    self.assertIsNotNone(browser_to_create)
    before_browser_run_temp_dir_content = os.listdir(tempfile.tempdir)
    browser_to_create.platform.network_controller.InitializeIfNeeded()
    try:
      with browser_to_create.Create(options) as browser:
        tab = browser.tabs.New()
        tab.Navigate('about:blank')
        self.assertEquals(2, tab.EvaluateJavaScript('1 + 1'))
      after_browser_run_temp_dir_content = os.listdir(tempfile.tempdir)
      self.assertEqual(before_browser_run_temp_dir_content,
                       after_browser_run_temp_dir_content)
    finally:
      browser_to_create.platform.network_controller.Close()
