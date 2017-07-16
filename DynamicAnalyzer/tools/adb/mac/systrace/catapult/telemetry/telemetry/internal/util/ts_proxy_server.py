# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Start and stop tsproxy."""

import logging
import os
import re
import subprocess
import sys

from telemetry.core import util
from telemetry.internal.util import atexit_with_log

import py_utils


_TSPROXY_PATH = os.path.join(
    util.GetTelemetryThirdPartyDir(), 'tsproxy', 'tsproxy.py')


def ParseTsProxyPortFromOutput(output_line):
  port_re = re.compile(
      r'Started Socks5 proxy server on '
      r'(?P<host>[^:]*):'
      r'(?P<port>\d+)')
  m = port_re.match(output_line.strip())
  if m:
    return int(m.group('port'))


class TsProxyServer(object):
  """Start and Stop Tsproxy.

  TsProxy provides basic latency, download and upload traffic shaping. This
  class provides a programming API to the tsproxy script in
  telemetry/third_party/tsproxy/tsproxy.py
  """

  def __init__(self, host_ip=None, http_port=None, https_port=None):
    """Initialize TsProxyServer.
    """
    self._proc = None
    self._port = None
    self._is_running = False
    self._host_ip = host_ip
    assert bool(http_port) == bool(https_port)
    self._http_port = http_port
    self._https_port = https_port

  @property
  def port(self):
    return self._port

  def StartServer(self, timeout=10):
    """Start TsProxy server and verify that it started.
    """
    cmd_line = [sys.executable, _TSPROXY_PATH]
    cmd_line.extend([
        '--port=0'])  # Use port 0 so tsproxy picks a random available port.
    if self._host_ip:
      cmd_line.append('--desthost=%s' % self._host_ip)
    if self._http_port:
      cmd_line.append(
        '--mapports=443:%s,*:%s' % (self._https_port, self._http_port))
    logging.info('Tsproxy commandline: %r' % cmd_line)
    self._proc = subprocess.Popen(
        cmd_line, stdout=subprocess.PIPE, stdin=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=1)
    atexit_with_log.Register(self.StopServer)
    try:
      py_utils.WaitFor(self._IsStarted, timeout)
      logging.info('TsProxy port: %s', self._port)
      self._is_running = True
    except py_utils.TimeoutException:
      err = self.StopServer()
      raise RuntimeError(
          'Error starting tsproxy: %s' % err)

  def _IsStarted(self):
    assert not self._is_running
    assert self._proc
    if self._proc.poll() is not None:
      return False
    self._proc.stdout.flush()
    self._port = ParseTsProxyPortFromOutput(
          output_line=self._proc.stdout.readline())
    return self._port != None


  def _IssueCommand(self, command_string, timeout):
    logging.info('Issuing command to ts_proxy_server: %s', command_string)
    command_output = []
    self._proc.stdin.write('%s\n' % command_string)
    self._proc.stdin.flush()
    self._proc.stdout.flush()
    def CommandStatusIsRead():
      command_output.append(self._proc.stdout.readline().strip())
      return (
          command_output[-1] == 'OK' or command_output[-1] == 'ERROR')
    py_utils.WaitFor(CommandStatusIsRead, timeout)
    if not 'OK' in command_output:
      raise RuntimeError('Failed to execute command %s:\n%s' %
                         (repr(command_string), '\n'.join(command_output)))


  def UpdateOutboundPorts(self, http_port, https_port, timeout=5):
    assert http_port and https_port
    assert http_port != https_port
    assert isinstance(http_port, int) and isinstance(https_port, int)
    assert 1 <= http_port <= 65535
    assert 1 <= https_port <= 65535
    self._IssueCommand('set mapports 443:%i,*:%i' % (https_port, http_port),
                       timeout)

  def UpdateTrafficSettings(self, round_trip_latency_ms=0,
      download_bandwidth_kbps=0, upload_bandwidth_kbps=0, timeout=5):
    self._IssueCommand('set rtt %s' % round_trip_latency_ms, timeout)
    self._IssueCommand('set inkbps %s' % download_bandwidth_kbps, timeout)
    self._IssueCommand('set outkbps %s' % upload_bandwidth_kbps, timeout)

  def StopServer(self):
    """Stop TsProxy Server."""
    if not self._is_running:
      logging.debug('Attempting to stop TsProxy server that is not running.')
      return
    if self._proc:
      self._proc.terminate()
      self._proc.wait()
    err = self._proc.stderr.read()
    self._proc = None
    self._port = None
    self._is_running = False
    return err

  def __enter__(self):
    """Add support for with-statement."""
    self.StartServer()
    return self

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    """Add support for with-statement."""
    self.StopServer()
