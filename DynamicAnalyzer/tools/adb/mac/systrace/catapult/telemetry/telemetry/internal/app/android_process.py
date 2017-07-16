# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.backends.chrome_inspector import devtools_client_backend
from telemetry.internal.browser import web_contents

try:
  from devil.android import ports
except ImportError:
  ports = None

class WebViewNotFoundException(Exception):
  pass

class AndroidProcess(object):
  """Represents a single android process."""

  def __init__(self, app_backend, pid, name):
    self._app_backend = app_backend
    self._pid = pid
    self._name = name
    self._local_port = ports.AllocateTestServerPort()
    self._devtools_client = None

  @property
  def pid(self):
    return self._pid

  @property
  def name(self):
    return self._name

  @property
  def _remote_devtools_port(self):
    return 'localabstract:webview_devtools_remote_%s' % str(self.pid)

  def _UpdateDevToolsClient(self):
    if self._devtools_client is None:
      self._app_backend.platform_backend.ForwardHostToDevice(
          self._local_port, self._remote_devtools_port)
      if devtools_client_backend.IsDevToolsAgentAvailable(
          self._local_port, self._app_backend):
        self._devtools_client = devtools_client_backend.DevToolsClientBackend(
            self._local_port, self._remote_devtools_port, self._app_backend)

  def GetWebViews(self):
    webviews = []
    self._UpdateDevToolsClient()
    if self._devtools_client is not None:
      devtools_context_map = (
          self._devtools_client.GetUpdatedInspectableContexts())
      for context in devtools_context_map.contexts:
        webviews.append(web_contents.WebContents(
            devtools_context_map.GetInspectorBackend(context['id'])))
    return webviews
