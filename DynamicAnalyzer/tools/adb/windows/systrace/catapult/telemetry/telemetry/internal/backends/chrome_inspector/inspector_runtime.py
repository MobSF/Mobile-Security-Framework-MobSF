# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.core import exceptions


class InspectorRuntime(object):
  def __init__(self, inspector_websocket):
    self._inspector_websocket = inspector_websocket
    self._inspector_websocket.RegisterDomain('Runtime', self._OnNotification)
    self._contexts_enabled = False
    self._max_context_id = None

  def _OnNotification(self, msg):
    if (self._contexts_enabled and
        msg['method'] == 'Runtime.executionContextCreated'):
      self._max_context_id = max(self._max_context_id,
                                 msg['params']['context']['id'])

  def Execute(self, expr, context_id, timeout):
    self.Evaluate(expr + '; 0;', context_id, timeout)

  def Evaluate(self, expr, context_id, timeout):
    """Evaluates a javascript expression and returns the result.

    |context_id| can refer to an iframe. The main page has context_id=1, the
    first iframe context_id=2, etc.

    Raises:
      exceptions.EvaluateException
      exceptions.WebSocketDisconnected
      websocket.WebSocketException
      socket.error
    """
    request = {
      'method': 'Runtime.evaluate',
      'params': {
        'expression': expr,
        'returnByValue': True
        }
      }
    if context_id is not None:
      self.EnableAllContexts()
      request['params']['contextId'] = context_id
    res = self._inspector_websocket.SyncRequest(request, timeout)
    if 'error' in res:
      raise exceptions.EvaluateException(res['error']['message'])

    if 'exceptionDetails' in res['result']:
      details = res['result']['exceptionDetails']
      raise exceptions.EvaluateException(
          text=details['text'],
          class_name=details.get('exception', {}).get('className'),
          description=details.get('exception', {}).get('description'))

    if res['result']['result']['type'] == 'undefined':
      return None
    return res['result']['result']['value']

  def EnableAllContexts(self):
    """Allow access to iframes.

    Raises:
      exceptions.WebSocketDisconnected
      websocket.WebSocketException
      socket.error
    """
    if not self._contexts_enabled:
      self._contexts_enabled = True
      self._inspector_websocket.SyncRequest({'method': 'Runtime.enable'},
                                            timeout=30)
    return self._max_context_id

  def RunInspectorCommand(self, command, timeout):
    """Runs an inspector command.

    Raises:
      exceptions.WebSocketDisconnected
      websocket.WebSocketException
      socket.error
    """
    res = self._inspector_websocket.SyncRequest(command, timeout)
    return res
