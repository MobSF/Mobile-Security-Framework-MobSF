# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry.core import cros_interface
from telemetry.core import util
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import extension_to_load
from telemetry.testing import options_for_unittests


class CrOSTestCase(unittest.TestCase):
  def setUp(self):
    options = options_for_unittests.GetCopy()
    self._cri = cros_interface.CrOSInterface(options.cros_remote,
                                             options.cros_remote_ssh_port,
                                             options.cros_ssh_identity)
    self._is_guest = options.browser_type == 'cros-chrome-guest'
    self._username = options.browser_options.username
    self._password = options.browser_options.password
    self._gaia_id = options.browser_options.gaia_id
    self._load_extension = None

  def _CreateBrowser(self, autotest_ext=False, auto_login=True,
                     gaia_login=False, username=None, password=None,
                     gaia_id=None, dont_override_profile=False):
    """Finds and creates a browser for tests. if autotest_ext is True,
    also loads the autotest extension"""
    options = options_for_unittests.GetCopy()

    if autotest_ext:
      extension_path = os.path.join(util.GetUnittestDataDir(), 'autotest_ext')
      assert os.path.isdir(extension_path)
      self._load_extension = extension_to_load.ExtensionToLoad(
          path=extension_path,
          browser_type=options.browser_type)
      options.browser_options.extensions_to_load = [self._load_extension]

    browser_to_create = browser_finder.FindBrowser(options)
    self.assertTrue(browser_to_create)
    browser_options = options.browser_options
    browser_options.create_browser_with_oobe = True
    browser_options.auto_login = auto_login
    browser_options.gaia_login = gaia_login
    browser_options.dont_override_profile = dont_override_profile
    if username is not None:
      browser_options.username = username
    if password is not None:
      browser_options.password = password
    if gaia_id is not None:
      browser_options.gaia_id = gaia_id

    return browser_to_create.Create(options)

  def _GetAutotestExtension(self, browser):
    """Returns the autotest extension instance"""
    extension = browser.extensions[self._load_extension]
    self.assertTrue(extension)
    return extension

  def _IsCryptohomeMounted(self):
    """Returns True if cryptohome is mounted. as determined by the cmd
    cryptohome --action=is_mounted"""
    return self._cri.RunCmdOnDevice(
        ['/usr/sbin/cryptohome', '--action=is_mounted'])[0].strip() == 'true'

  def _GetLoginStatus(self, browser):
    extension = self._GetAutotestExtension(browser)
    self.assertTrue(extension.EvaluateJavaScript(
        "typeof('chrome.autotestPrivate') != 'undefined'"))
    extension.ExecuteJavaScript('''
        window.__login_status = null;
        chrome.autotestPrivate.loginStatus(function(s) {
          window.__login_status = s;
        });
    ''')
    return extension.WaitForJavaScriptCondition(
        'window.__login_status', timeout=10)
