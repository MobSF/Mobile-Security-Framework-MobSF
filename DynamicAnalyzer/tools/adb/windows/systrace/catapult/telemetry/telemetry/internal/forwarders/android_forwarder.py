# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.util import atexit_with_log
import logging
import subprocess

from telemetry.internal import forwarders

try:
  from devil.android import forwarder
except ImportError:
  forwarder = None


class AndroidForwarderFactory(forwarders.ForwarderFactory):

  def __init__(self, device):
    super(AndroidForwarderFactory, self).__init__()
    self._device = device

  def Create(self, port_pair):
    try:
      return AndroidForwarder(self._device, port_pair)
    except Exception:
      try:
        logging.warning('Failed to create forwarder. '
                        'Currently forwarded connections:')
        for line in self._device.adb.ForwardList().splitlines():
          logging.warning('  %s', line)
      except Exception:
        logging.warning('Exception raised while listing forwarded connections.')

      logging.warning('Relevant device tcp sockets in use:')
      try:
        proc_net_tcp_target = ':%s ' % hex(port_pair.remote_port)[2:]
        for line in self._device.ReadFile('/proc/net/tcp', as_root=True,
                                          force_pull=True).splitlines():
          if proc_net_tcp_target in line:
            logging.warning('  %s', line)
      except Exception:
        logging.warning('Exception raised while listing tcp sockets.')

      logging.warning('Possibly relevant lsof entries:')
      try:
        lsof_output = self._device.RunShellCommand(
            ['lsof'], as_root=True, check_return=True)
        lsof_target = str(port_pair.remote_port)
        for line in lsof_output:
          if lsof_target in line:
            logging.warning('  %s', line)
      except Exception:
        logging.warning('Exception raised running lsof.')

      logging.warning('Alive webpagereplay instances:')
      try:
        for line in subprocess.check_output(['ps', '-ef']).splitlines():
          if 'webpagereplay' in line:
            logging.warning('  %s', line)
      except Exception:
        logging.warning('Exception raised while listing WPR intances.')

      raise


class AndroidForwarder(forwarders.Forwarder):

  def __init__(self, device, port_pair):
    super(AndroidForwarder, self).__init__(port_pair)
    self._device = device
    forwarder.Forwarder.Map(
        [(port_pair.remote_port, port_pair.local_port)], self._device)
    self._port_pair = (
        forwarders.PortPair(
            port_pair.local_port,
            forwarder.Forwarder.DevicePortForHostPort(port_pair.local_port)))
    atexit_with_log.Register(self.Close)
    # TODO(tonyg): Verify that each port can connect to host.

  def Close(self):
    if self._forwarding:
      forwarder.Forwarder.UnmapDevicePort(
          self._port_pair.remote_port, self._device)
    super(AndroidForwarder, self).Close()
