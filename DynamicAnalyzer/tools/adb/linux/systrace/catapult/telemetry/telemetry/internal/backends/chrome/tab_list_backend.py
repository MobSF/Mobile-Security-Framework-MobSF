# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from telemetry.core import exceptions
from telemetry.internal.backends.chrome_inspector import inspector_backend_list
from telemetry.internal.browser import tab

import py_utils


class TabUnexpectedResponseException(exceptions.DevtoolsTargetCrashException):
  pass


class TabListBackend(inspector_backend_list.InspectorBackendList):
  """A dynamic sequence of tab.Tabs in UI order."""

  def __init__(self, browser_backend):
    super(TabListBackend, self).__init__(browser_backend)

  def New(self, timeout):
    """Makes a new tab.

    Returns:
      A Tab object.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    if not self._browser_backend.supports_tab_control:
      raise NotImplementedError("Browser doesn't support tab control.")
    response = self._browser_backend.devtools_client.RequestNewTab(timeout)
    try:
      response = json.loads(response)
      context_id = response['id']
    except (KeyError, ValueError):
      raise TabUnexpectedResponseException(
          app=self._browser_backend.browser,
          msg='Received response: %s' % response)
    return self.GetBackendFromContextId(context_id)

  def CloseTab(self, tab_id, timeout=300):
    """Closes the tab with the given debugger_url.

    Raises:
      devtools_http.DevToolsClientConnectionError
      devtools_client_backend.TabNotFoundError
      TabUnexpectedResponseException
      py_utils.TimeoutException
    """
    assert self._browser_backend.supports_tab_control
    # TODO(dtu): crbug.com/160946, allow closing the last tab on some platforms.
    # For now, just create a new tab before closing the last tab.
    if len(self) <= 1:
      self.New(timeout)

    response = self._browser_backend.devtools_client.CloseTab(tab_id, timeout)

    if response != 'Target is closing':
      raise TabUnexpectedResponseException(
          app=self._browser_backend.browser,
          msg='Received response: %s' % response)

    py_utils.WaitFor(lambda: tab_id not in self.IterContextIds(), timeout=5)

  def ActivateTab(self, tab_id, timeout=30):
    """Activates the tab with the given debugger_url.

    Raises:
      devtools_http.DevToolsClientConnectionError
      devtools_client_backend.TabNotFoundError
      TabUnexpectedResponseException
    """
    assert self._browser_backend.supports_tab_control

    response = self._browser_backend.devtools_client.ActivateTab(tab_id,
                                                                 timeout)

    if response != 'Target activated':
      raise TabUnexpectedResponseException(
          app=self._browser_backend.browser,
          msg='Received response: %s' % response)

  def Get(self, index, ret):
    """Returns self[index] if it exists, or ret if index is out of bounds."""
    if len(self) <= index:
      return ret
    return self[index]

  def ShouldIncludeContext(self, context):
    if 'type' in context:
      return (context['type'] == 'page' or
              context['url'] == 'chrome://media-router/')
    # TODO: For compatibility with Chrome before r177683.
    # This check is not completely correct, see crbug.com/190592.
    return not context['url'].startswith('chrome-extension://')

  def CreateWrapper(self, inspector_backend):
    return tab.Tab(inspector_backend, self, self._browser_backend.browser)

  def _HandleDevToolsConnectionError(self, error):
    if not self._browser_backend.IsAppRunning():
      error.AddDebuggingMessage('The browser is not running. It probably '
                                'crashed.')
    elif not self._browser_backend.HasBrowserFinishedLaunching():
      error.AddDebuggingMessage('The browser exists but cannot be reached.')
    else:
      error.AddDebuggingMessage('The browser exists and can be reached. '
                                'The devtools target probably crashed.')
