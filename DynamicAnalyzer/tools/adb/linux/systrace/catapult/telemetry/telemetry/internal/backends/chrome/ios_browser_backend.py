# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import json
import logging
import re
import urllib2

from telemetry.internal.backends.chrome import chrome_browser_backend
from telemetry.internal.backends.chrome import system_info_backend

import py_utils


class IosBrowserBackend(chrome_browser_backend.ChromeBrowserBackend):
  _DEBUGGER_URL_BUILDER = 'ws://localhost:%i/devtools/page/%i'
  _DEBUGGER_URL_REGEX = r'ws://localhost:(\d+)/devtools/page/(\d+)'
  _DEVICE_LIST_URL = 'http://localhost:9221/json'

  def __init__(self, ios_platform_backend, browser_options):
    browser_options.output_profile_path = '.'
    super(IosBrowserBackend, self).__init__(
        ios_platform_backend,
        supports_tab_control=False,
        supports_extensions=False,
        browser_options=browser_options)
    self._webviews = []
    self._port = None
    self._page = None
    self._system_info_backend = None
    self.UpdateRunningBrowsersInfo()

  def UpdateRunningBrowsersInfo(self):
    """ Refresh to match current state of the running browser.
    """
    device_urls = self.GetDeviceUrls()
    urls = self.GetWebSocketDebuggerUrls(device_urls)
    for url in urls:
      m = re.match(self._DEBUGGER_URL_REGEX, url)
      if m:
        self._webviews.append([int(m.group(1)), int(m.group(2))])
      else:
        logging.error('Unexpected url format: %s' % url)

    # TODO(baxley): For now, grab first item from |_webviews|. Ideally, we'd
    # prefer to have the currently displayed tab, or something similar.
    if self._webviews:
      self._port = self._webviews[0][0]
      self._page = self._webviews[0][1]

  def GetDeviceUrls(self):
    device_urls = []
    try:
      with contextlib.closing(
          urllib2.urlopen(self._DEVICE_LIST_URL)) as device_list:
        json_urls = device_list.read()
        device_urls = json.loads(json_urls)
        if not device_urls:
          logging.debug('No iOS devices found. Will not try searching for iOS '
                        'browsers.')
          return []
    except urllib2.URLError as e:
      logging.debug('Error communicating with iOS device.')
      logging.debug(str(e))
      return []
    return device_urls

  def GetWebSocketDebuggerUrls(self, device_urls):
    """ Get a list of the websocket debugger URLs to communicate with
        all running UIWebViews.
    """
    data = []
    # Loop through all devices.
    for d in device_urls:
      def GetData():
        try:
          with contextlib.closing(
              # pylint: disable=cell-var-from-loop
              urllib2.urlopen('http://%s/json' % d['url'])) as f:
            json_result = f.read()
            data = json.loads(json_result)
            return data
        except urllib2.URLError as e:
          logging.debug('Error communicating with iOS device.')
          logging.debug(e)
          return False
      try:
        # Retry a few times since it can take a few seconds for this API to be
        # ready, if ios_webkit_debug_proxy is just launched.
        data = py_utils.WaitFor(GetData, 5)
      except py_utils.TimeoutException as e:
        logging.debug('Timeout retrieving data from iOS device')
        logging.debug(e)
        return []

    # Find all running UIWebViews.
    debug_urls = []
    for j in data:
      debug_urls.append(j['webSocketDebuggerUrl'])

    return debug_urls

  def GetSystemInfo(self):
    if self._system_info_backend is None:
      self._system_info_backend = system_info_backend.SystemInfoBackend(
          self._port, self._page)
    return self._system_info_backend.GetSystemInfo()

  def IsBrowserRunning(self):
    return bool(self._webviews)

  #TODO(baxley): The following were stubbed out to get the sunspider benchmark
  # running. These should be implemented.
  @property
  def browser_directory(self):
    logging.warn('Not implemented')
    return None

  @property
  def profile_directory(self):
    logging.warn('Not implemented')
    return None

  def Start(self):
    logging.warn('Not implemented')

  def extension_backend(self):
    logging.warn('Not implemented')
    return None

  def GetBrowserStartupArgs(self):
    logging.warn('Not implemented')
    return None

  def HasBrowserFinishedLaunching(self):
    logging.warn('Not implemented')
    return False

  def GetStandardOutput(self):
    raise NotImplementedError()

  def GetStackTrace(self):
    raise NotImplementedError()

  def GetMostRecentMinidumpPath(self):
    return None

  def GetAllMinidumpPaths(self):
    return None

  def GetAllUnsymbolizedMinidumpPaths(self):
    return None

  def SymbolizeMinidump(self, minidump_path):
    return None
