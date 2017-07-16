# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.platform import system_info
from telemetry.internal.util import camel_case


class SystemInfoBackend(object):
  def __init__(self, devtools_port, devtools_page=None):
    self._port = devtools_port
    self._page = devtools_page

  def GetSystemInfo(self, timeout=10):
    req = {'method': 'SystemInfo.getInfo'}
    websocket = inspector_websocket.InspectorWebsocket()
    try:
      if self._page:
        websocket.Connect('ws://127.0.0.1:%i/devtools/page/%i' %
                          (self._port, self._page), timeout)
      else:
        websocket.Connect('ws://127.0.0.1:%i/devtools/browser' % self._port,
                          timeout)
      res = websocket.SyncRequest(req, timeout)
    finally:
      websocket.Disconnect()
    if 'error' in res:
      return None
    return system_info.SystemInfo.FromDict(
        camel_case.ToUnderscore(res['result']))
