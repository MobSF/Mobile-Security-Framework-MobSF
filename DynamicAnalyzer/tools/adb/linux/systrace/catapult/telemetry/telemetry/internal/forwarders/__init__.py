# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections


PortPair = collections.namedtuple('PortPair', ['local_port', 'remote_port'])
PortSet = collections.namedtuple('PortSet', ['http', 'https', 'dns'])



class ForwarderFactory(object):

  def Create(self, port_pair):
    """Creates a forwarder that maps remote (device) <-> local (host) ports.

    Args:
      port_pair: A PortPairs instance that consists of a PortPair mapping
          for each protocol. http is required. https and dns may be None.
    """
    raise NotImplementedError()

  @property
  def host_ip(self):
    return '127.0.0.1'


class Forwarder(object):

  def __init__(self, port_pair):
    assert port_pair, 'Port mapping is required.'
    self._port_pair = port_pair
    self._forwarding = True

  @property
  def host_port(self):
    return self._port_pair.remote_port

  @property
  def host_ip(self):
    return '127.0.0.1'

  @property
  def port_pair(self):
    return self._port_pair

  @property
  def url(self):
    assert self.host_ip and self.host_port
    return 'http://%s:%i' % (self.host_ip, self.host_port)

  def Close(self):
    self._port_pair = None
    self._forwarding = False
