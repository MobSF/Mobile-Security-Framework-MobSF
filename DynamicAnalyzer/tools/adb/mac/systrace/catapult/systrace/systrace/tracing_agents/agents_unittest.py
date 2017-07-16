# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from systrace import util

from devil.android import device_utils
from devil.android.sdk import intent
from devil.android.sdk import keyevent


class BaseAgentTest(unittest.TestCase):
  def setUp(self):
    devices = device_utils.DeviceUtils.HealthyDevices()
    self.browser = 'stable'
    self.package_info = util.get_supported_browsers()[self.browser]
    self.device = devices[0]

    curr_browser = self.GetChromeProcessID()
    if curr_browser == None:
      self.StartBrowser()

  def tearDown(self):
    # Stop the browser after each test to ensure that it doesn't interfere
    # with subsequent tests, e.g. by holding the devtools socket open.
    self.device.ForceStop(self.package_info.package)

  def StartBrowser(self):
    # Turn on the device screen.
    self.device.SetScreen(True)

    # Unlock device.
    self.device.SendKeyEvent(keyevent.KEYCODE_MENU)

    # Start browser.
    self.device.StartActivity(
      intent.Intent(activity=self.package_info.activity,
                    package=self.package_info.package,
                    data='about:blank',
                    extras={'create_new_tab': True}),
      blocking=True, force_stop=True)

  def GetChromeProcessID(self):
    chrome_processes = self.device.GetPids(self.package_info.package)
    if (self.package_info.package in chrome_processes and
        len(chrome_processes[self.package_info.package]) > 0):
      return chrome_processes[self.package_info.package][0]
    return None
