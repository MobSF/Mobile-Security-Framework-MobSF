# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import urllib2
import os

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.backends.chrome import cros_test_case

import py_utils


class CrOSCryptohomeTest(cros_test_case.CrOSTestCase):
  @decorators.Enabled('chromeos')
  def testCryptohome(self):
    """Verifies cryptohome mount status for regular and guest user and when
    logged out"""
    with self._CreateBrowser() as b:
      self.assertEquals(1, len(b.tabs))
      self.assertTrue(b.tabs[0].url)
      self.assertTrue(self._IsCryptohomeMounted())
      self.assertTrue(
          self._cri.IsCryptohomeMounted(self._username, self._is_guest))

      # TODO(achuith): Remove dependency on /home/chronos/user.
      chronos_fs = self._cri.FilesystemMountedAt('/home/chronos/user')
      self.assertTrue(chronos_fs)
      if self._is_guest:
        self.assertEquals(chronos_fs, 'guestfs')
      else:
        crypto_fs = self._cri.FilesystemMountedAt(
            self._cri.CryptohomePath(self._username))
        self.assertEquals(crypto_fs, chronos_fs)

    self.assertFalse(self._IsCryptohomeMounted())
    self.assertFalse(
        self._cri.IsCryptohomeMounted(self._username, self._is_guest))
    self.assertEquals(self._cri.FilesystemMountedAt('/home/chronos/user'),
                      '/dev/mapper/encstateful')


class CrOSLoginTest(cros_test_case.CrOSTestCase):
  def _GetCredentials(self, credentials=None):
    """Read username and password from credentials.txt. The file is a single
    line of the format username:password. Alternatively, |credentials| is used,
    also of the same format."""
    credentials_file = os.path.join(os.path.dirname(__file__),
                                    'credentials.txt')
    if not credentials and os.path.exists(credentials_file):
      with open(credentials_file) as f:
        credentials = f.read().strip()

    if not credentials:
      return (None, None)

    user, password = credentials.split(':')
    # Canonicalize.
    if user.find('@') == -1:
      username = user
      domain = 'gmail.com'
    else:
      username, domain = user.split('@')

    # Remove dots.
    if domain == 'gmail.com':
      username = username.replace('.', '')
    return ('%s@%s' % (username, domain), password)

  @decorators.Enabled('chromeos')
  def testGetCredentials(self):
    (username, password) = self._GetCredentials('user.1:foo.1')
    self.assertEquals(username, 'user1@gmail.com')
    self.assertEquals(password, 'foo.1')

    (username, password) = self._GetCredentials('user.1@chromium.org:bar.1')
    self.assertEquals(username, 'user.1@chromium.org')
    self.assertEquals(password, 'bar.1')

  @decorators.Enabled('chromeos')
  def testLoginStatus(self):
    """Tests autotestPrivate.loginStatus"""
    if self._is_guest:
      return
    with self._CreateBrowser(autotest_ext=True) as b:
      login_status = self._GetLoginStatus(b)
      self.assertEquals(type(login_status), dict)

      self.assertEquals(not self._is_guest, login_status['isRegularUser'])
      self.assertEquals(self._is_guest, login_status['isGuest'])
      self.assertEquals(login_status['email'], self._username)
      self.assertFalse(login_status['isScreenLocked'])

  @decorators.Enabled('chromeos')
  def testLogout(self):
    """Tests autotestPrivate.logout"""
    if self._is_guest:
      return
    with self._CreateBrowser(autotest_ext=True) as b:
      extension = self._GetAutotestExtension(b)
      try:
        extension.ExecuteJavaScript('chrome.autotestPrivate.logout();')
      except exceptions.Error:
        pass
      py_utils.WaitFor(lambda: not self._IsCryptohomeMounted(), 20)

  @decorators.Disabled('all')
  def testGaiaLogin(self):
    """Tests gaia login. Use credentials in credentials.txt if it exists,
    otherwise use powerloadtest."""
    if self._is_guest:
      return
    username, password = self._GetCredentials()
    if not username or not password:
      username = 'powerloadtest@gmail.com'
      password = urllib2.urlopen(
          'https://sites.google.com/a/chromium.org/dev/chromium-os/testing/'
          'power-testing/pltp/pltp').read().rstrip()
    with self._CreateBrowser(gaia_login=True,
                             username=username,
                             password=password):
      self.assertTrue(py_utils.WaitFor(self._IsCryptohomeMounted, 10))

  @decorators.Enabled('chromeos')
  def testEnterpriseEnroll(self):
    """Tests enterprise enrollment. Credentials are expected to be found in a
    credentials.txt file. The account must be from an enterprise domain and
    have device enrollment permission. The device must be unowned."""
    if self._is_guest:
      return

    username, password = self._GetCredentials()
    if not username or not password:
      return
    # Enroll the device.
    with self._CreateBrowser(auto_login=False) as browser:
      browser.oobe.NavigateGaiaLogin(username, password,
                                     enterprise_enroll=True,
                                     for_user_triggered_enrollment=True)

    # Check for the existence of the device policy file.
    self.assertTrue(py_utils.WaitFor(lambda: self._cri.FileExistsOnDevice(
        '/home/.shadow/install_attributes.pb'), 15))


class CrOSScreenLockerTest(cros_test_case.CrOSTestCase):
  def _IsScreenLocked(self, browser):
    return self._GetLoginStatus(browser)['isScreenLocked']

  def _LockScreen(self, browser):
    self.assertFalse(self._IsScreenLocked(browser))

    extension = self._GetAutotestExtension(browser)
    self.assertTrue(extension.EvaluateJavaScript(
        "typeof chrome.autotestPrivate.lockScreen == 'function'"))
    logging.info('Locking screen')
    extension.ExecuteJavaScript('chrome.autotestPrivate.lockScreen();')

    logging.info('Waiting for the lock screen')
    def ScreenLocked():
      return (browser.oobe_exists and
          browser.oobe.EvaluateJavaScript("typeof Oobe == 'function'") and
          browser.oobe.EvaluateJavaScript(
              "typeof Oobe.authenticateForTesting == 'function'"))
    py_utils.WaitFor(ScreenLocked, 10)
    self.assertTrue(self._IsScreenLocked(browser))

  def _AttemptUnlockBadPassword(self, browser):
    logging.info('Trying a bad password')
    def ErrorBubbleVisible():
      return not browser.oobe.EvaluateJavaScript(
          "document.getElementById('bubble').hidden")

    self.assertFalse(ErrorBubbleVisible())
    browser.oobe.ExecuteJavaScript(
        "Oobe.authenticateForTesting({{ username }}, 'bad');",
        username=self._username)
    py_utils.WaitFor(ErrorBubbleVisible, 10)
    self.assertTrue(self._IsScreenLocked(browser))

  def _UnlockScreen(self, browser):
    logging.info('Unlocking')
    browser.oobe.ExecuteJavaScript(
        'Oobe.authenticateForTesting({{ username }}, {{ password }});',
        username=self._username, password=self._password)
    py_utils.WaitFor(lambda: not browser.oobe_exists, 10)
    self.assertFalse(self._IsScreenLocked(browser))

  @decorators.Disabled('all')
  def testScreenLock(self):
    """Tests autotestPrivate.screenLock"""
    if self._is_guest:
      return
    with self._CreateBrowser(autotest_ext=True) as browser:
      self._LockScreen(browser)
      self._AttemptUnlockBadPassword(browser)
      self._UnlockScreen(browser)
