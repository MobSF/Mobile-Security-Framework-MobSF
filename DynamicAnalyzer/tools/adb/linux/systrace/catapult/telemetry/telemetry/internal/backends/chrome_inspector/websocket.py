# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from __future__ import absolute_import

import socket

# pylint: disable=unused-import
from websocket import create_connection as _create_connection
from websocket import WebSocketConnectionClosedException
from websocket import WebSocketException
from websocket import WebSocketTimeoutException


def create_connection(*args, **kwargs):
  sockopt = kwargs.get('sockopt', [])

  # By default, we set SO_REUSEADDR on all websockets used by Telemetry.
  # This prevents spurious address in use errors on Windows.
  #
  # TODO(tonyg): We may want to set SO_NODELAY here as well.
  sockopt.append((socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))

  kwargs['sockopt'] = sockopt
  return _create_connection(*args, **kwargs)
