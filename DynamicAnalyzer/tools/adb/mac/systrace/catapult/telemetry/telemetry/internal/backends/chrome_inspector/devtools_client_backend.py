# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import re
import socket
import sys

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.backends import browser_backend
from telemetry.internal.backends.chrome_inspector import devtools_http
from telemetry.internal.backends.chrome_inspector import inspector_backend
from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import memory_backend
from telemetry.internal.backends.chrome_inspector import tracing_backend
from telemetry.internal.backends.chrome_inspector import websocket
from telemetry.internal.platform.tracing_agent import chrome_tracing_agent
from telemetry.internal.platform.tracing_agent import (
    chrome_tracing_devtools_manager)
from tracing.trace_data import trace_data as trace_data_module


BROWSER_INSPECTOR_WEBSOCKET_URL = 'ws://127.0.0.1:%i/devtools/browser'


class TabNotFoundError(exceptions.Error):
  pass


def IsDevToolsAgentAvailable(port, app_backend):
  """Returns True if a DevTools agent is available on the given port."""
  if (isinstance(app_backend, browser_backend.BrowserBackend) and
      app_backend.supports_tracing):
    inspector_websocket_instance = inspector_websocket.InspectorWebsocket()
    try:
      if not _IsInspectorWebsocketAvailable(inspector_websocket_instance, port):
        return False
    finally:
      inspector_websocket_instance.Disconnect()

  devtools_http_instance = devtools_http.DevToolsHttp(port)
  try:
    return _IsDevToolsAgentAvailable(devtools_http_instance)
  finally:
    devtools_http_instance.Disconnect()


def _IsInspectorWebsocketAvailable(inspector_websocket_instance, port):
  try:
    inspector_websocket_instance.Connect(
        BROWSER_INSPECTOR_WEBSOCKET_URL % port, timeout=10)
  except websocket.WebSocketException:
    return False
  except socket.error:
    return False
  except Exception as e:
    sys.stderr.write('Unidentified exception while checking if wesocket is'
                     'available on port %i. Exception message: %s\n' %
                     (port, e.message))
    return False
  else:
    return True


# TODO(nednguyen): Find a more reliable way to check whether the devtool agent
# is still alive.
def _IsDevToolsAgentAvailable(devtools_http_instance):
  try:
    devtools_http_instance.Request('')
  except devtools_http.DevToolsClientConnectionError:
    return False
  else:
    return True


class DevToolsClientBackend(object):
  """An object that communicates with Chrome's devtools.

  This class owns a map of InspectorBackends. It is responsible for creating
  them and destroying them.
  """
  def __init__(self, devtools_port, remote_devtools_port, app_backend):
    """Creates a new DevToolsClientBackend.

    A DevTools agent must exist on the given devtools_port.

    Args:
      devtools_port: The port to use to connect to DevTools agent.
      remote_devtools_port: In some cases (e.g., app running on
          Android device, devtools_port is the forwarded port on the
          host platform. We also need to know the remote_devtools_port
          so that we can uniquely identify the DevTools agent.
      app_backend: For the app that contains the DevTools agent.
    """
    self._devtools_port = devtools_port
    self._remote_devtools_port = remote_devtools_port
    self._devtools_http = devtools_http.DevToolsHttp(devtools_port)
    self._browser_inspector_websocket = None
    self._tracing_backend = None
    self._memory_backend = None
    self._app_backend = app_backend
    self._devtools_context_map_backend = _DevToolsContextMapBackend(
        self._app_backend, self)

    self._tab_ids = None

    if not self.supports_tracing:
      return
    chrome_tracing_devtools_manager.RegisterDevToolsClient(
        self, self._app_backend.platform_backend)

    # Telemetry has started Chrome tracing if there is trace config, so start
    # tracing on this newly created devtools client if needed.
    trace_config = (self._app_backend.platform_backend
                    .tracing_controller_backend.GetChromeTraceConfig())
    if not trace_config:
      self._CreateTracingBackendIfNeeded(is_tracing_running=False)
      return

    if self.support_startup_tracing:
      self._CreateTracingBackendIfNeeded(is_tracing_running=True)
      return

    self._CreateTracingBackendIfNeeded(is_tracing_running=False)
    self.StartChromeTracing(trace_config)

  @property
  def remote_port(self):
    return self._remote_devtools_port

  @property
  def supports_tracing(self):
    if not isinstance(self._app_backend, browser_backend.BrowserBackend):
      return False
    return self._app_backend.supports_tracing

  @property
  def supports_overriding_memory_pressure_notifications(self):
    if not isinstance(self._app_backend, browser_backend.BrowserBackend):
      return False
    return self._app_backend.supports_overriding_memory_pressure_notifications


  @property
  def is_tracing_running(self):
    if not self.supports_tracing:
      return False
    if not self._tracing_backend:
      return False
    return self._tracing_backend.is_tracing_running

  @property
  def support_startup_tracing(self):
    # Startup tracing with --trace-config-file flag was not supported until
    # Chromium branch number 2512 (see crrev.com/1309243004 and
    # crrev.com/1353583002).
    if not chrome_tracing_agent.ChromeTracingAgent.IsStartupTracingSupported(
        self._app_backend.platform_backend):
      return False
    # TODO(zhenw): Remove this once stable Chrome and reference browser have
    # passed 2512.
    return self.GetChromeBranchNumber() >= 2512

  @property
  def support_modern_devtools_tracing_start_api(self):
    # Modern DevTools Tracing.start API (via 'traceConfig' parameter) was not
    # supported until Chromium branch number 2683 (see crrev.com/1808353002).
    # TODO(petrcermak): Remove this once stable Chrome and reference browser
    # have passed 2683.
    return self.GetChromeBranchNumber() >= 2683

  def IsAlive(self):
    """Whether the DevTools server is available and connectable."""
    return (self._devtools_http and
        _IsDevToolsAgentAvailable(self._devtools_http))

  def Close(self):
    if self._tracing_backend:
      self._tracing_backend.Close()
      self._tracing_backend = None
    if self._memory_backend:
      self._memory_backend.Close()
      self._memory_backend = None

    if self._devtools_context_map_backend:
      self._devtools_context_map_backend.Clear()

    # Close the browser inspector socket last (in case the backend needs to
    # interact with it before closing).
    if self._browser_inspector_websocket:
      self._browser_inspector_websocket.Disconnect()
      self._browser_inspector_websocket = None

    assert self._devtools_http
    self._devtools_http.Disconnect()
    self._devtools_http = None


  @decorators.Cache
  def GetChromeBranchNumber(self):
    # Detect version information.
    resp = self._devtools_http.RequestJson('version')
    if 'Protocol-Version' in resp:
      if 'Browser' in resp:
        branch_number_match = re.search(r'Chrome/\d+\.\d+\.(\d+)\.\d+',
                                        resp['Browser'])
      else:
        branch_number_match = re.search(
            r'Chrome/\d+\.\d+\.(\d+)\.\d+ (Mobile )?Safari',
            resp['User-Agent'])

      if branch_number_match:
        branch_number = int(branch_number_match.group(1))
        if branch_number:
          return branch_number

    # Branch number can't be determined, so fail any branch number checks.
    return 0

  def _ListInspectableContexts(self):
    return self._devtools_http.RequestJson('')

  def RequestNewTab(self, timeout):
    """Creates a new tab.

    Returns:
      A JSON string as returned by DevTools. Example:
      {
        "description": "",
        "devtoolsFrontendUrl":
            "/devtools/inspector.html?ws=host:port/devtools/page/id-string",
        "id": "id-string",
        "title": "Page Title",
        "type": "page",
        "url": "url",
        "webSocketDebuggerUrl": "ws://host:port/devtools/page/id-string"
      }

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    return self._devtools_http.Request('new', timeout=timeout)

  def CloseTab(self, tab_id, timeout):
    """Closes the tab with the given id.

    Raises:
      devtools_http.DevToolsClientConnectionError
      TabNotFoundError
    """
    try:
      return self._devtools_http.Request('close/%s' % tab_id,
                                         timeout=timeout)
    except devtools_http.DevToolsClientUrlError:
      error = TabNotFoundError(
          'Unable to close tab, tab id not found: %s' % tab_id)
      raise error, None, sys.exc_info()[2]

  def ActivateTab(self, tab_id, timeout):
    """Activates the tab with the given id.

    Raises:
      devtools_http.DevToolsClientConnectionError
      TabNotFoundError
    """
    try:
      return self._devtools_http.Request('activate/%s' % tab_id,
                                         timeout=timeout)
    except devtools_http.DevToolsClientUrlError:
      error = TabNotFoundError(
          'Unable to activate tab, tab id not found: %s' % tab_id)
      raise error, None, sys.exc_info()[2]

  def GetUrl(self, tab_id):
    """Returns the URL of the tab with |tab_id|, as reported by devtools.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    for c in self._ListInspectableContexts():
      if c['id'] == tab_id:
        return c['url']
    return None

  def IsInspectable(self, tab_id):
    """Whether the tab with |tab_id| is inspectable, as reported by devtools.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    contexts = self._ListInspectableContexts()
    return tab_id in [c['id'] for c in contexts]

  def GetUpdatedInspectableContexts(self):
    """Returns an updated instance of _DevToolsContextMapBackend."""
    contexts = self._ListInspectableContexts()
    self._devtools_context_map_backend._Update(contexts)
    return self._devtools_context_map_backend

  def _CreateTracingBackendIfNeeded(self, is_tracing_running=False):
    assert self.supports_tracing
    if not self._tracing_backend:
      self._CreateAndConnectBrowserInspectorWebsocketIfNeeded()
      self._tracing_backend = tracing_backend.TracingBackend(
          self._browser_inspector_websocket, is_tracing_running,
          self.support_modern_devtools_tracing_start_api)

  def _CreateMemoryBackendIfNeeded(self):
    assert self.supports_overriding_memory_pressure_notifications
    if not self._memory_backend:
      self._CreateAndConnectBrowserInspectorWebsocketIfNeeded()
      self._memory_backend = memory_backend.MemoryBackend(
          self._browser_inspector_websocket)

  def _CreateAndConnectBrowserInspectorWebsocketIfNeeded(self):
    if not self._browser_inspector_websocket:
      self._browser_inspector_websocket = (
          inspector_websocket.InspectorWebsocket())
      self._browser_inspector_websocket.Connect(
          BROWSER_INSPECTOR_WEBSOCKET_URL % self._devtools_port, timeout=10)

  def IsChromeTracingSupported(self):
    if not self.supports_tracing:
      return False
    self._CreateTracingBackendIfNeeded()
    return self._tracing_backend.IsTracingSupported()

  def StartChromeTracing(self, trace_config, timeout=10):
    """
    Args:
        trace_config: An tracing_config.TracingConfig instance.
    """
    assert trace_config and trace_config.enable_chrome_trace
    self._CreateTracingBackendIfNeeded()
    return self._tracing_backend.StartTracing(
        trace_config.chrome_trace_config, timeout)

  def RecordChromeClockSyncMarker(self, sync_id):
    assert self.is_tracing_running, 'Tracing must be running to clock sync.'
    self._tracing_backend.RecordClockSyncMarker(sync_id)

  def StopChromeTracing(self):
    assert self.is_tracing_running
    self._tab_ids = []
    try:
      context_map = self.GetUpdatedInspectableContexts()
      for context in context_map.contexts:
        if context['type'] not in ['iframe', 'page', 'webview']:
          continue
        context_id = context['id']
        backend = context_map.GetInspectorBackend(context_id)
        backend.EvaluateJavaScript("""
            console.time({{ backend_id }});
            console.timeEnd({{ backend_id }});
            console.time.toString().indexOf('[native code]') != -1;
            """,
            backend_id=backend.id)
        self._tab_ids.append(backend.id)
    finally:
      self._tracing_backend.StopTracing()

  def CollectChromeTracingData(self, trace_data_builder, timeout=60):
    try:
      trace_data_builder.AddTraceFor(
          trace_data_module.TAB_ID_PART, self._tab_ids[:])
      self._tab_ids = None
    finally:
      self._tracing_backend.CollectTraceData(trace_data_builder, timeout)

  def DumpMemory(self, timeout=30):
    """Dumps memory.

    Returns:
      GUID of the generated dump if successful, None otherwise.

    Raises:
      TracingTimeoutException: If more than |timeout| seconds has passed
      since the last time any data is received.
      TracingUnrecoverableException: If there is a websocket error.
      TracingUnexpectedResponseException: If the response contains an error
      or does not contain the expected result.
    """
    self._CreateTracingBackendIfNeeded()
    return self._tracing_backend.DumpMemory(timeout)

  def SetMemoryPressureNotificationsSuppressed(self, suppressed, timeout=30):
    """Enable/disable suppressing memory pressure notifications.

    Args:
      suppressed: If true, memory pressure notifications will be suppressed.
      timeout: The timeout in seconds.

    Raises:
      MemoryTimeoutException: If more than |timeout| seconds has passed
      since the last time any data is received.
      MemoryUnrecoverableException: If there is a websocket error.
      MemoryUnexpectedResponseException: If the response contains an error
      or does not contain the expected result.
    """
    self._CreateMemoryBackendIfNeeded()
    return self._memory_backend.SetMemoryPressureNotificationsSuppressed(
        suppressed, timeout)

  def SimulateMemoryPressureNotification(self, pressure_level, timeout=30):
    """Simulate a memory pressure notification.

    Args:
      pressure level: The memory pressure level of the notification ('moderate'
      or 'critical').
      timeout: The timeout in seconds.

    Raises:
      MemoryTimeoutException: If more than |timeout| seconds has passed
      since the last time any data is received.
      MemoryUnrecoverableException: If there is a websocket error.
      MemoryUnexpectedResponseException: If the response contains an error
      or does not contain the expected result.
    """
    self._CreateMemoryBackendIfNeeded()
    return self._memory_backend.SimulateMemoryPressureNotification(
        pressure_level, timeout)


class _DevToolsContextMapBackend(object):
  def __init__(self, app_backend, devtools_client):
    self._app_backend = app_backend
    self._devtools_client = devtools_client
    self._contexts = None
    self._inspector_backends_dict = {}

  @property
  def contexts(self):
    """The most up to date contexts data.

    Returned in the order returned by devtools agent."""
    return self._contexts

  def GetContextInfo(self, context_id):
    for context in self._contexts:
      if context['id'] == context_id:
        return context
    raise KeyError('Cannot find a context with id=%s' % context_id)

  def GetInspectorBackend(self, context_id):
    """Gets an InspectorBackend instance for the given context_id.

    This lazily creates InspectorBackend for the context_id if it does
    not exist yet. Otherwise, it will return the cached instance."""
    if context_id in self._inspector_backends_dict:
      return self._inspector_backends_dict[context_id]

    for context in self._contexts:
      if context['id'] == context_id:
        new_backend = inspector_backend.InspectorBackend(
            self._app_backend.app, self._devtools_client, context)
        self._inspector_backends_dict[context_id] = new_backend
        return new_backend

    raise KeyError('Cannot find a context with id=%s' % context_id)

  def _Update(self, contexts):
    # Remove InspectorBackend that is not in the current inspectable
    # contexts list.
    context_ids = [context['id'] for context in contexts]
    for context_id in self._inspector_backends_dict.keys():
      if context_id not in context_ids:
        backend = self._inspector_backends_dict[context_id]
        backend.Disconnect()
        del self._inspector_backends_dict[context_id]

    valid_contexts = []
    for context in contexts:
      # If the context does not have webSocketDebuggerUrl, skip it.
      # If an InspectorBackend is already created for the tab,
      # webSocketDebuggerUrl will be missing, and this is expected.
      context_id = context['id']
      if context_id not in self._inspector_backends_dict:
        if 'webSocketDebuggerUrl' not in context:
          logging.debug('webSocketDebuggerUrl missing, removing %s'
                        % context_id)
          continue
      valid_contexts.append(context)
    self._contexts = valid_contexts

  def Clear(self):
    for backend in self._inspector_backends_dict.values():
      backend.Disconnect()
    self._inspector_backends_dict = {}
    self._contexts = None
