# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.util import ts_proxy_server

class TsProxyServerTest(unittest.TestCase):
  def testParseTsProxyPort(self):
    self.assertEquals(
      ts_proxy_server.ParseTsProxyPortFromOutput(
          'Started Socks5 proxy server on 127.0.0.1:54430 \n'),
      54430)
    self.assertEquals(
      ts_proxy_server.ParseTsProxyPortFromOutput(
          'Started Socks5 proxy server on foo.bar.com:430 \n'),
      430)
    self.assertEquals(
      ts_proxy_server.ParseTsProxyPortFromOutput(
          'Failed to start sock5 proxy.'),
      None)

  def testSmokeStartingTsProxyServer(self):
    with ts_proxy_server.TsProxyServer() as server:
      self.assertIsNotNone(server.port)
    with ts_proxy_server.TsProxyServer(None, 37124, 37125) as server:
      self.assertIsNotNone(server.port)

  def testSmokeUpdatingOutboundPorts(self):
    with ts_proxy_server.TsProxyServer() as server:
      self.assertIsNotNone(server.port)
      server.UpdateOutboundPorts(31242, 14220)

  def testSmokeUpdateOutboundPortsInvalid(self):
    with ts_proxy_server.TsProxyServer() as server:
      self.assertIsNotNone(server.port)
      with self.assertRaises(AssertionError):
        server.UpdateOutboundPorts(31242, 'abcde')

  def testSmokeUpdateTrafficSettings(self):
    with ts_proxy_server.TsProxyServer() as server:
      server.UpdateTrafficSettings(round_trip_latency_ms=100)
      server.UpdateTrafficSettings(download_bandwidth_kbps=5000)
      server.UpdateTrafficSettings(upload_bandwidth_kbps=2000)
      server.UpdateTrafficSettings(
          round_trip_latency_ms=200, download_bandwidth_kbps=500,
          upload_bandwidth_kbps=2000)
