# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno
import json
import logging
import socket
import time

from telemetry.core import exceptions
from telemetry.internal.backends.chrome_inspector import websocket

class WebSocketDisconnected(exceptions.Error):
  """An attempt was made to use a web socket after it had been disconnected."""
  pass


class InspectorWebsocket(object):

  # See http://www.jsonrpc.org/specification#error_object.
  METHOD_NOT_FOUND_CODE = -32601

  def __init__(self):
    """Create a websocket handler for communicating with Inspectors."""
    self._socket = None
    self._cur_socket_timeout = 0
    self._next_request_id = 0
    self._domain_handlers = {}
    self._pending_callbacks = dict()

  def RegisterDomain(self, domain_name, notification_handler):
    """Registers a given domain for handling notification methods.

    For example, given inspector_backend:
       def OnConsoleNotification(msg):
          if msg['method'] == 'Console.messageAdded':
             print msg['params']['message']
       inspector_backend.RegisterDomain('Console', OnConsoleNotification)

    Args:
      domain_name: The devtools domain name. E.g., 'Tracing', 'Memory', 'Page'.
      notification_handler: Handler for devtools notification. Will be
          called if a devtools notification with matching domain is received
          via DispatchNotifications. The handler accepts a single paramater:
          the JSON object representing the notification.
    """
    assert domain_name not in self._domain_handlers
    self._domain_handlers[domain_name] = notification_handler

  def UnregisterDomain(self, domain_name):
    """Unregisters a previously registered domain."""
    assert domain_name in self._domain_handlers
    del self._domain_handlers[domain_name]

  def Connect(self, url, timeout):
    """Connects the websocket.

    Raises:
      websocket.WebSocketException
      socket.error
    """
    assert not self._socket
    self._socket = websocket.create_connection(url, timeout=timeout)
    self._cur_socket_timeout = 0
    self._next_request_id = 0

  def Disconnect(self):
    """Disconnects the inspector websocket.

    Raises:
      websocket.WebSocketException
      socket.error
    """
    if self._socket:
      self._socket.close()
      self._socket = None

  def SendAndIgnoreResponse(self, req):
    """Sends a request without waiting for a response.

    Raises:
      websocket.WebSocketException: Error from websocket library.
      socket.error: Error from websocket library.
      exceptions.WebSocketDisconnected: The socket was disconnected.
    """
    self._SendRequest(req)

  def _SendRequest(self, req):
    if not self._socket:
      raise WebSocketDisconnected()
    req['id'] = self._next_request_id
    self._next_request_id += 1
    data = json.dumps(req)
    self._socket.send(data)
    if logging.getLogger().isEnabledFor(logging.DEBUG):
      logging.debug('sent [%s]', json.dumps(req, indent=2, sort_keys=True))

  def SyncRequest(self, req, timeout):
    """Sends a request and waits for a response.

    Raises:
      websocket.WebSocketException: Error from websocket library.
      socket.error: Error from websocket library.
      exceptions.WebSocketDisconnected: The socket was disconnected.
    """
    self._SendRequest(req)

    while True:
      res = self._Receive(timeout)
      if 'id' in res and res['id'] == req['id']:
        return res

  def AsyncRequest(self, req, callback):
    """Sends an async request and returns immediately.

    Response will be handled in the |callback| later when DispatchNotifications
    is invoked.

    Args:
      callback: a function that takes inspector's response as the argument.
    """
    self._SendRequest(req)
    self._pending_callbacks[req['id']] = callback

  def DispatchNotifications(self, timeout):
    """Waits for responses from the websocket, dispatching them as necessary.

    Raises:
      websocket.WebSocketException: Error from websocket library.
      socket.error: Error from websocket library.
      exceptions.WebSocketDisconnected: The socket was disconnected.
    """
    self._Receive(timeout)

  def _SetTimeout(self, timeout):
    if self._cur_socket_timeout != timeout:
      self._socket.settimeout(timeout)
      self._cur_socket_timeout = timeout

  def _Receive(self, timeout):
    if not self._socket:
      raise WebSocketDisconnected()

    self._SetTimeout(timeout)

    while True:
      try:
        data = self._socket.recv()
      except socket.error, e:
        if e.errno == errno.EAGAIN:
          # Resource is temporarily unavailable. Try again.
          # See https://code.google.com/p/chromium/issues/detail?id=545853#c3
          # for more details.
          time.sleep(0.1)
        else:
          raise
      else:
        break

    result = json.loads(data)
    if logging.getLogger().isEnabledFor(logging.DEBUG):
      logging.debug(
          'got [%s]', json.dumps(result, indent=2, sort_keys=True))
    if 'method' in result:
      self._HandleNotification(result)
    elif 'id' in result:
      self._HandleAsyncResponse(result)
    return result

  def _HandleNotification(self, result):
    mname = result['method']
    dot_pos = mname.find('.')
    domain_name = mname[:dot_pos]
    if not domain_name in self._domain_handlers:
      logging.warn('Unhandled inspector message: %s', result)
      return

    self._domain_handlers[domain_name](result)

  def _HandleAsyncResponse(self, result):
    callback = self._pending_callbacks.pop(result['id'], None)
    if callback:
      callback(result)
