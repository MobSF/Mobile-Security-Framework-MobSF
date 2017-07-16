# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import mock
import unittest

from telemetry.internal.backends import android_browser_backend_settings


class AndroidBrowserBackendSettingsUnittest(unittest.TestCase):

  def testWebViewGetDevtoolsRemotePortRetrySuccess(self):
    mock_device = mock.Mock()
    mock_device.GetPids.side_effect = [
        {},
        {},
        {'webview.package': ['1111']},
    ]

    settings = android_browser_backend_settings.WebviewBackendSettings(
        package='webview.package')
    with mock.patch('time.sleep', return_value=None):
      self.assertEquals(
          settings.GetDevtoolsRemotePort(mock_device),
          'localabstract:webview_devtools_remote_1111')

  def testWebViewGetDevtoolsRemotePortMultipleProcessesFailure(self):
    mock_device = mock.Mock()
    mock_device.GetPids.side_effect = [
        {'webview.package': ['1111', '2222']}
    ]

    settings = android_browser_backend_settings.WebviewBackendSettings(
        package='webview.package')
    with mock.patch('time.sleep', return_value=None):
      with self.assertRaises(Exception):
        settings.GetDevtoolsRemotePort(mock_device)

  def testWebViewGetDevtoolsRemotePortTimeoutFailure(self):
    mock_device = mock.Mock()
    mock_device.GetPids.side_effect = [
        {},
        {},
        {},
        {},
    ]

    settings = android_browser_backend_settings.WebviewBackendSettings(
        package='webview.package')
    with mock.patch('time.sleep', return_value=None) as time_mock:
      with self.assertRaises(Exception):
        settings.GetDevtoolsRemotePort(mock_device)
      time_mock.assert_has_calls(
          [mock.call(1), mock.call(2), mock.call(4), mock.call(8)])
