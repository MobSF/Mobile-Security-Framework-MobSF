# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno
import httplib
import json
import socket
import sys

from telemetry.core import exceptions


class DevToolsClientConnectionError(exceptions.Error):
  pass


class DevToolsClientUrlError(DevToolsClientConnectionError):
  pass


class DevToolsHttp(object):
  """A helper class to send and parse DevTools HTTP requests.

  This class maintains a persistent http connection to Chrome devtools.
  Ideally, owners of instances of this class should call Disconnect() before
  disposing of the instance. Otherwise, the connection will not be closed until
  the instance is garbage collected.
  """

  def __init__(self, devtools_port):
    self._devtools_port = devtools_port
    self._conn = None

  def __del__(self):
    self.Disconnect()

  def _Connect(self, timeout):
    """Attempts to establish a connection to Chrome devtools."""
    assert not self._conn
    try:
      host_port = '127.0.0.1:%i' % self._devtools_port
      self._conn = httplib.HTTPConnection(host_port, timeout=timeout)
    except (socket.error, httplib.HTTPException) as e:
      raise DevToolsClientConnectionError, (e,), sys.exc_info()[2]

  def Disconnect(self):
    """Closes the HTTP connection."""
    if not self._conn:
      return

    try:
      self._conn.close()
    except (socket.error, httplib.HTTPException) as e:
      raise DevToolsClientConnectionError, (e,), sys.exc_info()[2]
    finally:
      self._conn = None

  def Request(self, path, timeout=30):
    """Sends a request to Chrome devtools.

    This method lazily creates an HTTP connection, if one does not already
    exist.

    Args:
      path: The DevTools URL path, without the /json/ prefix.
      timeout: Timeout defaults to 30 seconds.

    Raises:
      DevToolsClientConnectionError: If the connection fails.
    """
    assert timeout

    if not self._conn:
      self._Connect(timeout)

    endpoint = '/json'
    if path:
      endpoint += '/' + path
    if self._conn.sock:
      self._conn.sock.settimeout(timeout)
    else:
      self._conn.timeout = timeout

    try:
      # By default, httplib avoids going through the default system proxy.
      self._conn.request('GET', endpoint)
      response = self._conn.getresponse()
      return response.read()
    except (socket.error, httplib.HTTPException) as e:
      self.Disconnect()
      if isinstance(e, socket.error) and e.errno == errno.ECONNREFUSED:
        raise DevToolsClientUrlError, (e,), sys.exc_info()[2]
      raise DevToolsClientConnectionError, (e,), sys.exc_info()[2]

  def RequestJson(self, path, timeout=30):
    """Sends a request and parse the response as JSON.

    Args:
      path: The DevTools URL path, without the /json/ prefix.
      timeout: Timeout defaults to 30 seconds.

    Raises:
      DevToolsClientConnectionError: If the connection fails.
      ValueError: If the response is not a valid JSON.
    """
    return json.loads(self.Request(path, timeout))
