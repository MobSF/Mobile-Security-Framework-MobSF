# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Finds iOS browsers that can be controlled by telemetry."""

import logging
import re

from telemetry.core import platform
from telemetry.internal.backends.chrome import ios_browser_backend
from telemetry.internal.backends.chrome_inspector import inspector_backend
from telemetry.internal.browser import browser
from telemetry.internal.browser import possible_browser
from telemetry.internal.platform import ios_device
from telemetry.internal.platform import ios_platform_backend


# Key matches output from ios-webkit-debug-proxy and the value is a readable
# description of the browser.
IOS_BROWSERS = {'CriOS': 'ios-chrome', 'Version': 'ios-safari'}
DEVICE_LIST_URL = 'http://127.0.0.1:9221/json'
IOS_WEBKIT_DEBUG_PROXY = 'ios_webkit_debug_proxy'


class PossibleIOSBrowser(possible_browser.PossibleBrowser):

  """A running iOS browser instance."""
  def __init__(self, browser_type, _):
    super(PossibleIOSBrowser, self).__init__(browser_type, 'ios', True)

  # TODO(baxley): Implement the following methods for iOS.
  def Create(self, finder_options):
    browser_backend = ios_browser_backend.IosBrowserBackend(
        self._platform_backend, finder_options.browser_options)
    return browser.Browser(
        browser_backend, self._platform_backend, self._credentials_path)

  def SupportsOptions(self, browser_options):
    #TODO(baxley): Implement me.
    return True

  def UpdateExecutableIfNeeded(self):
    #TODO(baxley): Implement me.
    pass

  def _InitPlatformIfNeeded(self):
    if self._platform:
      return

    self._platform_backend = ios_platform_backend.IosPlatformBackend()
    self._platform = platform.Platform(self._platform_backend)

def SelectDefaultBrowser(_):
  return None  # TODO(baxley): Implement me.


def CanFindAvailableBrowsers():
  # TODO(baxley): Add support for all platforms possible. Probably Linux,
  # probably not Windows.
  return platform.GetHostPlatform().GetOSName() == 'mac'


def FindAllBrowserTypes(_):
  return IOS_BROWSERS.values()


def FindAllAvailableBrowsers(finder_options, device):
  """Find all running iOS browsers on connected devices."""
  if not isinstance(device, ios_device.IOSDevice):
    return []

  if not CanFindAvailableBrowsers():
    return []

  options = finder_options.browser_options

  options.browser_type = 'ios-chrome'
  host = platform.GetHostPlatform()
  backend = ios_browser_backend.IosBrowserBackend(host, options)
  # TODO(baxley): Use idevice to wake up device or log debug statement.
  if not host.IsApplicationRunning(IOS_WEBKIT_DEBUG_PROXY):
    host.LaunchApplication(IOS_WEBKIT_DEBUG_PROXY)
    if not host.IsApplicationRunning(IOS_WEBKIT_DEBUG_PROXY):
      return []

  device_urls = backend.GetDeviceUrls()
  if not device_urls:
    logging.debug('Could not find any devices over %s.'
                  % IOS_WEBKIT_DEBUG_PROXY)
    return []

  debug_urls = backend.GetWebSocketDebuggerUrls(device_urls)

  # Get the userAgent for each UIWebView to find the browsers.
  browser_pattern = (r'\)\s(%s)\/(\d+[\.\d]*)\sMobile'
                     % '|'.join(IOS_BROWSERS.keys()))
  browser_types = set()
  for url in debug_urls:
    context = {'webSocketDebuggerUrl': url, 'id': 1}
    try:
      inspector = inspector_backend.InspectorBackend(
          backend.app, backend.devtools_client, context)
      res = inspector.EvaluateJavaScript("navigator.userAgent")
    finally:
      inspector.Disconnect()
    match_browsers = re.search(browser_pattern, res)
    if match_browsers:
      browser_types.add(match_browsers.group(1))

  browsers = []
  for browser_type in browser_types:
    browsers.append(PossibleIOSBrowser(IOS_BROWSERS[browser_type],
                                       finder_options))
  return list(browsers)
