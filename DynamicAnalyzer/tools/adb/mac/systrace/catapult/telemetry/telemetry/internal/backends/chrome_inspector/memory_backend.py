# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import logging
import socket
import traceback

from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import websocket


class MemoryTimeoutException(Exception):
  pass


class MemoryUnrecoverableException(Exception):
  pass


class MemoryUnexpectedResponseException(Exception):
  pass


class MemoryBackend(object):

  def __init__(self, inspector_socket):
    self._inspector_websocket = inspector_socket

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
    self._SendMemoryRequest('setPressureNotificationsSuppressed',
                            {'suppressed': suppressed}, timeout)

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
    self._SendMemoryRequest('simulatePressureNotification',
                            {'level': pressure_level}, timeout)

  def _SendMemoryRequest(self, command, params, timeout):
    method = 'Memory.%s' % command
    request = {
      'method': method,
      'params': params
    }
    try:
      response = self._inspector_websocket.SyncRequest(request, timeout)
    except websocket.WebSocketTimeoutException:
      raise MemoryTimeoutException(
          'Exception raised while sending a %s request:\n%s' %
              (method, traceback.format_exc()))
    except (socket.error, websocket.WebSocketException,
            inspector_websocket.WebSocketDisconnected):
      raise MemoryUnrecoverableException(
          'Exception raised while sending a %s request:\n%s' %
              (method, traceback.format_exc()))

    if 'error' in response:
      code = response['error']['code']
      if code == inspector_websocket.InspectorWebsocket.METHOD_NOT_FOUND_CODE:
        logging.warning(
            '%s DevTools method not supported by the browser' % method)
      else:
        raise MemoryUnexpectedResponseException(
            'Inspector returned unexpected response for %s:\n%s' %
                (method, json.dumps(response, indent=2)))

  def Close(self):
    self._inspector_websocket = None
