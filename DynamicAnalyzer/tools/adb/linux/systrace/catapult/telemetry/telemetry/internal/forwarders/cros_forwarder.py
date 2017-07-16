# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import subprocess

from telemetry.internal import forwarders
from telemetry.internal.forwarders import do_nothing_forwarder

import py_utils


class CrOsForwarderFactory(forwarders.ForwarderFactory):

  def __init__(self, cri):
    super(CrOsForwarderFactory, self).__init__()
    self._cri = cri

  # pylint: disable=arguments-differ
  def Create(self, port_pair, use_remote_port_forwarding=True):
    if self._cri.local:
      return do_nothing_forwarder.DoNothingForwarder(port_pair)
    return CrOsSshForwarder(self._cri, use_remote_port_forwarding, port_pair)


class CrOsSshForwarder(forwarders.Forwarder):

  def __init__(self, cri, use_remote_port_forwarding, port_pair):
    super(CrOsSshForwarder, self).__init__(port_pair)
    self._cri = cri
    self._proc = None
    forwarding_args = self._ForwardingArgs(
        use_remote_port_forwarding, self.host_ip, port_pair)
    self._proc = subprocess.Popen(
        self._cri.FormSSHCommandLine(['sleep', '999999999'], forwarding_args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        shell=False)
    py_utils.WaitFor(
        lambda: self._cri.IsHTTPServerRunningOnPort(self.host_port), 60)
    logging.debug('Server started on %s:%d', self.host_ip, self.host_port)

  # pylint: disable=unused-argument
  @staticmethod
  def _ForwardingArgs(use_remote_port_forwarding, host_ip, port_pair):
    if use_remote_port_forwarding:
      arg_format = '-R{remote_port}:{host_ip}:{local_port}'
    else:
      arg_format = '-L{local_port}:{host_ip}:{remote_port}'
    return [arg_format.format(host_ip=host_ip,
                              local_port=port_pair.local_port,
                              remote_port=port_pair.remote_port)]

  @property
  def host_port(self):
    return self._port_pair.remote_port

  def Close(self):
    if self._proc:
      self._proc.kill()
      self._proc = None
    super(CrOsSshForwarder, self).Close()
