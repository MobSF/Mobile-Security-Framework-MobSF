# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import logging
import socket

from telemetry.internal import forwarders

import py_utils


class Error(Exception):
  """Base class for exceptions in this module."""
  pass


class PortsMismatchError(Error):
  """Raised when local and remote ports are not equal."""
  pass


class ConnectionError(Error):
  """Raised when unable to connect to local TCP ports."""
  pass


class DoNothingForwarderFactory(forwarders.ForwarderFactory):

  def Create(self, port_pair):
    return DoNothingForwarder(port_pair)


class DoNothingForwarder(forwarders.Forwarder):
  """Check that no forwarding is needed for the given port pairs.

  The local and remote ports must be equal. Otherwise, the "do nothing"
  forwarder does not make sense. (Raises PortsMismatchError.)

  Also, check that all TCP ports support connections.  (Raises ConnectionError.)
  """

  def __init__(self, port_pair):
    super(DoNothingForwarder, self).__init__(port_pair)
    self._CheckPortPair()

  def _CheckPortPair(self):
    if self._port_pair.local_port != self._port_pair.remote_port:
      raise PortsMismatchError('Local port forwarding is not supported')
    try:
      self._WaitForConnectionEstablished(
          (self.host_ip, self._port_pair.local_port), timeout=10)
      logging.debug(
          'Connection test succeeded for %s:%d',
          self.host_ip, self._port_pair.local_port)
    except py_utils.TimeoutException:
      raise ConnectionError(
          'Unable to connect to address: %s:%d',
          self.host_ip, self._port_pair.local_port)

  def _WaitForConnectionEstablished(self, address, timeout):
    def CanConnect():
      with contextlib.closing(socket.socket()) as s:
        return s.connect_ex(address) == 0
    py_utils.WaitFor(CanConnect, timeout)
