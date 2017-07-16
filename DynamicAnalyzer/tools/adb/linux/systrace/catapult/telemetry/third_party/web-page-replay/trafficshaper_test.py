#!/usr/bin/env python
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""System integration test for traffic shaping.

Usage:
$ sudo ./trafficshaper_test.py
"""

import daemonserver
import logging
import platformsettings
import socket
import SocketServer
import trafficshaper
import unittest

RESPONSE_SIZE_KEY = 'response-size:'
TEST_DNS_PORT = 5555
TEST_HTTP_PORT = 8888
TIMER = platformsettings.timer


def GetElapsedMs(start_time, end_time):
  """Return milliseconds elapsed between |start_time| and |end_time|.

  Args:
    start_time: seconds as a float (or string representation of float).
    end_time: seconds as a float (or string representation of float).
  Return:
    milliseconds elapsed as integer.
  """
  return int((float(end_time) - float(start_time)) * 1000)


class TrafficShaperTest(unittest.TestCase):

  def testBadBandwidthRaises(self):
    self.assertRaises(trafficshaper.BandwidthValueError,
                      trafficshaper.TrafficShaper,
                      down_bandwidth='1KBit/s')


class TimedUdpHandler(SocketServer.DatagramRequestHandler):
  """UDP handler that returns the time when the request was handled."""

  def handle(self):
    data = self.rfile.read()
    read_time = self.server.timer()
    self.wfile.write(str(read_time))


class TimedTcpHandler(SocketServer.StreamRequestHandler):
  """Tcp handler that returns the time when the request was read.

  It can respond with the number of bytes specified in the request.
  The request looks like:
    request_data -> RESPONSE_SIZE_KEY num_response_bytes '\n' ANY_DATA
  """

  def handle(self):
    data = self.rfile.read()
    read_time = self.server.timer()
    contents = str(read_time)
    if data.startswith(RESPONSE_SIZE_KEY):
      num_response_bytes = int(data[len(RESPONSE_SIZE_KEY):data.index('\n')])
      contents = '%s\n%s' % (contents,
                             '\x00' * (num_response_bytes - len(contents) - 1))
    self.wfile.write(contents)


class TimedUdpServer(SocketServer.ThreadingUDPServer,
                     daemonserver.DaemonServer):
  """A simple UDP server similar to dnsproxy."""

  # Override SocketServer.TcpServer setting to avoid intermittent errors.
  allow_reuse_address = True

  def __init__(self, host, port, timer=TIMER):
    SocketServer.ThreadingUDPServer.__init__(
        self, (host, port), TimedUdpHandler)
    self.timer = timer

  def cleanup(self):
    pass


class TimedTcpServer(SocketServer.ThreadingTCPServer,
                     daemonserver.DaemonServer):
  """A simple TCP server similar to httpproxy."""

  # Override SocketServer.TcpServer setting to avoid intermittent errors.
  allow_reuse_address = True

  def __init__(self, host, port, timer=TIMER):
    SocketServer.ThreadingTCPServer.__init__(
        self, (host, port), TimedTcpHandler)
    self.timer = timer

  def cleanup(self):
    try:
      self.shutdown()
    except KeyboardInterrupt, e:
      pass


class TcpTestSocketCreator(object):
  """A TCP socket creator suitable for with-statement."""

  def __init__(self, host, port, timeout=1.0):
    self.address = (host, port)
    self.timeout = timeout

  def __enter__(self):
    self.socket = socket.create_connection(self.address, timeout=self.timeout)
    return self.socket

  def __exit__(self, *args):
    self.socket.close()


class TimedTestCase(unittest.TestCase):
  def assertValuesAlmostEqual(self, expected, actual, tolerance=0.05):
    """Like the following with nicer default message:
           assertTrue(expected <= actual + tolerance &&
                      expected >= actual - tolerance)
    """
    delta = tolerance * expected
    if actual > expected + delta or actual < expected - delta:
      self.fail('%s is not equal to expected %s +/- %s%%' % (
              actual, expected, 100 * tolerance))


class TcpTrafficShaperTest(TimedTestCase):

  def setUp(self):
    self.host = platformsettings.get_server_ip_address()
    self.port = TEST_HTTP_PORT
    self.tcp_socket_creator = TcpTestSocketCreator(self.host, self.port)
    self.timer = TIMER

  def TrafficShaper(self, **kwargs):
    return trafficshaper.TrafficShaper(
        host=self.host, ports=(self.port,), **kwargs)

  def GetTcpSendTimeMs(self, num_bytes):
    """Return time in milliseconds to send |num_bytes|."""

    with self.tcp_socket_creator as s:
      start_time = self.timer()
      request_data = '\x00' * num_bytes

      s.sendall(request_data)
      # TODO(slamm): Figure out why partial is shutdown needed to make it work.
      s.shutdown(socket.SHUT_WR)
      read_time = s.recv(1024)
    return GetElapsedMs(start_time, read_time)

  def GetTcpReceiveTimeMs(self, num_bytes):
    """Return time in milliseconds to receive |num_bytes|."""

    with self.tcp_socket_creator as s:
      s.sendall('%s%s\n' % (RESPONSE_SIZE_KEY, num_bytes))
      # TODO(slamm): Figure out why partial is shutdown needed to make it work.
      s.shutdown(socket.SHUT_WR)
      num_remaining_bytes = num_bytes
      read_time = None
      while num_remaining_bytes > 0:
        response_data = s.recv(4096)
        num_remaining_bytes -= len(response_data)
        if not read_time:
          read_time, padding = response_data.split('\n')
    return GetElapsedMs(read_time, self.timer())

  def testTcpConnectToIp(self):
    """Verify that it takes |delay_ms| to establish a TCP connection."""
    if not platformsettings.has_ipfw():
      logging.warning('ipfw is not available in path. Skip the test')
      return
    with TimedTcpServer(self.host, self.port):
      for delay_ms in (100, 175):
        with self.TrafficShaper(delay_ms=delay_ms):
          start_time = self.timer()
          with self.tcp_socket_creator:
            connect_time = GetElapsedMs(start_time, self.timer())
        self.assertValuesAlmostEqual(delay_ms, connect_time, tolerance=0.12)

  def testTcpUploadShaping(self):
    """Verify that 'up' bandwidth is shaped on TCP connections."""
    if not platformsettings.has_ipfw():
      logging.warning('ipfw is not available in path. Skip the test')
      return
    num_bytes = 1024 * 100
    bandwidth_kbits = 2000
    expected_ms = 8.0 * num_bytes / bandwidth_kbits
    with TimedTcpServer(self.host, self.port):
      with self.TrafficShaper(up_bandwidth='%sKbit/s' % bandwidth_kbits):
        self.assertValuesAlmostEqual(expected_ms, self.GetTcpSendTimeMs(num_bytes))

  def testTcpDownloadShaping(self):
    """Verify that 'down' bandwidth is shaped on TCP connections."""
    if not platformsettings.has_ipfw():
      logging.warning('ipfw is not available in path. Skip the test')
      return
    num_bytes = 1024 * 100
    bandwidth_kbits = 2000
    expected_ms = 8.0 * num_bytes / bandwidth_kbits
    with TimedTcpServer(self.host, self.port):
      with self.TrafficShaper(down_bandwidth='%sKbit/s' % bandwidth_kbits):
        self.assertValuesAlmostEqual(expected_ms, self.GetTcpReceiveTimeMs(num_bytes))

  def testTcpInterleavedDownloads(self):
    # TODO(slamm): write tcp interleaved downloads test
    pass


class UdpTrafficShaperTest(TimedTestCase):

  def setUp(self):
    self.host = platformsettings.get_server_ip_address()
    self.dns_port = TEST_DNS_PORT
    self.timer = TIMER

  def TrafficShaper(self, **kwargs):
    return trafficshaper.TrafficShaper(
        host=self.host, ports=(self.dns_port,), **kwargs)

  def GetUdpSendReceiveTimesMs(self):
    """Return time in milliseconds to send |num_bytes|."""
    start_time = self.timer()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.sendto('test data\n', (self.host, self.dns_port))
    read_time = udp_socket.recv(1024)
    return (GetElapsedMs(start_time, read_time),
            GetElapsedMs(read_time, self.timer()))

  def testUdpDelay(self):
    if not platformsettings.has_ipfw():
      logging.warning('ipfw is not available in path. Skip the test')
      return
    for delay_ms in (100, 170):
      expected_ms = delay_ms / 2
      with TimedUdpServer(self.host, self.dns_port):
        with self.TrafficShaper(delay_ms=delay_ms):
          send_ms, receive_ms = self.GetUdpSendReceiveTimesMs()
          self.assertValuesAlmostEqual(expected_ms, send_ms, tolerance=0.10)
          self.assertValuesAlmostEqual(expected_ms, receive_ms, tolerance=0.10)


  def testUdpInterleavedDelay(self):
    # TODO(slamm): write udp interleaved udp delay test
    pass


class TcpAndUdpTrafficShaperTest(TimedTestCase):
  # TODO(slamm): Test concurrent TCP and UDP traffic
  pass


# TODO(slamm): Packet loss rate (try different ports)


if __name__ == '__main__':
  #logging.getLogger().setLevel(logging.DEBUG)
  unittest.main()
