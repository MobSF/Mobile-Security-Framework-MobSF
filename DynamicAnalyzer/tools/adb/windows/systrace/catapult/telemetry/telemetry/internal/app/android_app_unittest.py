# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import time
import unittest

from telemetry.core import platform as platform_module
from telemetry.internal.app import android_app
from telemetry.internal.backends import android_app_backend
from telemetry.internal.platform import android_device
from telemetry.testing import options_for_unittests

from devil.android.sdk import intent


class AndroidAppTest(unittest.TestCase):
  def setUp(self):
    self._options = options_for_unittests.GetCopy()
    self._device = android_device.GetDevice(self._options)

  def CreateAndroidApp(self, start_intent):
    platform = platform_module.GetPlatformForDevice(self._device, self._options)
    platform_backend = platform._platform_backend
    app_backend = android_app_backend.AndroidAppBackend(
        platform_backend, start_intent)
    return android_app.AndroidApp(app_backend, platform_backend)

  def testWebView(self):
    if self._device is None:
      logging.warning('No device found, skipping test.')
      return

    start_intent = intent.Intent(
        package='com.google.android.googlequicksearchbox',
        activity='.SearchActivity',
        action='com.google.android.googlequicksearchbox.GOOGLE_SEARCH',
        data=None,
        extras={'query': 'google'},
        category=None)
    search_app = self.CreateAndroidApp(start_intent)
    search_process = search_app.GetProcess(':search')
    search_process._UpdateDevToolsClient()

    # TODO(ariblue): Replace the app used in this test with one in which the
    # setWebContentsDebuggingEnabled method is called on the WebView class.
    # This will configure webviews for debugging with chrome devtools inspector
    # and allow us to remove this check.
    if search_process._devtools_client is None:
      return

    webview = search_app.GetProcess(':search').GetWebViews().pop()
    webview.Navigate('https://www.google.com/search?q=flowers')
    time.sleep(5)
