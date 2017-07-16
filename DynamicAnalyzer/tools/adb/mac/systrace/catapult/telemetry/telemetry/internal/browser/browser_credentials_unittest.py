# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import tempfile
import unittest

from telemetry.internal.browser import browser_credentials


SIMPLE_CREDENTIALS_STRING = """
{
  "google": {
    "username": "example",
    "password": "asdf"
  }
}
"""

class BackendStub(object):
  def __init__(self, credentials_type):
    self.login_needed_called = None
    self.login_no_longer_needed_called = None
    self.credentials_type = credentials_type

  def LoginNeeded(self, config, _, tab):
    self.login_needed_called = (config, tab)
    return True

  def LoginNoLongerNeeded(self, tab):
    self.login_no_longer_needed_called = (tab, )


class TestBrowserCredentials(unittest.TestCase):
  def testCredentialsInfrastructure(self):
    google_backend = BackendStub("google")
    othersite_backend = BackendStub("othersite")
    browser_cred = browser_credentials.BrowserCredentials(
      [google_backend,
       othersite_backend])
    try:
      with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(SIMPLE_CREDENTIALS_STRING)

      browser_cred.credentials_path = f.name

      # Should true because it has a password and a backend.
      self.assertTrue(browser_cred.CanLogin('google'))

      # Should be false succeed because it has no password.
      self.assertFalse(browser_cred.CanLogin('othersite'))

      # Should fail because it has no backend.
      self.assertRaises(
        Exception,
        lambda: browser_cred.CanLogin('foobar'))

      class FakeTab(object):
        def __init__(self):
          self.action_runner = None

      tab = FakeTab()
      ret = browser_cred.LoginNeeded(tab, 'google')
      self.assertTrue(ret)
      self.assertTrue(google_backend.login_needed_called is not None)
      self.assertEqual(tab, google_backend.login_needed_called[0])
      self.assertEqual("example",
                       google_backend.login_needed_called[1]["username"])
      self.assertEqual("asdf",
                       google_backend.login_needed_called[1]["password"])

      browser_cred.LoginNoLongerNeeded(tab, 'google')
      self.assertTrue(google_backend.login_no_longer_needed_called is not None)
      self.assertEqual(tab, google_backend.login_no_longer_needed_called[0])
    finally:
      os.remove(f.name)
