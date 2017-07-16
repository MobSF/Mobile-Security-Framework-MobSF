# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import sys
import unittest

from telemetry.internal.util import wpr_server


# pylint: disable=protected-access
class CreateCommandTest(unittest.TestCase):
  def testHasDnsGivesDnsPort(self):
    expected_cmd_line = [
        sys.executable, 'replay.py', '--host=127.0.0.1',
        '--port=2', '--ssl_port=1', '--dns_port=0',
        '--use_closest_match', '--log_level=warning', '--extra_arg', 'foo.wpr']
    cmd_line = wpr_server.ReplayServer._GetCommandLine(
        'replay.py', '127.0.0.1', 2, 1, 0, ['--extra_arg'], 'foo.wpr',
        log_level=logging.WARNING)
    self.assertEqual(expected_cmd_line, cmd_line)

  def testNoDnsGivesNoDnsForwarding(self):
    expected_cmd_line = [
        sys.executable, 'replay.py', '--host=127.0.0.1',
        '--port=8080', '--ssl_port=8443', '--no-dns_forwarding',
        '--use_closest_match', '--log_level=warning', 'bar.wpr']
    cmd_line = wpr_server.ReplayServer._GetCommandLine(
        'replay.py', '127.0.0.1', 8080, 8443, None, [], 'bar.wpr',
        log_level=logging.WARNING)
    self.assertEqual(expected_cmd_line, cmd_line)


# pylint: disable=protected-access
class ParseLogFilePortsTest(unittest.TestCase):
  def testEmptyLinesGivesEmptyDict(self):
    log_lines = iter([])
    self.assertEqual(
      {},
      wpr_server.ReplayServer._ParseLogFilePorts(log_lines))

  def testSingleMatchGivesSingleElementDict(self):
    log_lines = iter([
        'extra stuff',
        '2014-09-27 17:04:27,11 WARNING HTTP server started on 127.0.0.1:5167',
        'extra stuff',
        ])
    self.assertEqual(
        {'http': 5167},
        wpr_server.ReplayServer._ParseLogFilePorts(log_lines))

  def testUnknownProtocolSkipped(self):
    log_lines = iter([
        '2014-09-27 17:04:27,11 WARNING FOO server started on 127.0.0.1:1111',
        '2014-09-27 17:04:27,12 WARNING HTTP server started on 127.0.0.1:5167',
        ])
    self.assertEqual(
        {'http': 5167},
        wpr_server.ReplayServer._ParseLogFilePorts(log_lines))

  def testTypicalLogLinesGiveFullDict(self):
    log_lines = iter([
        'extra',
        '2014-09-27 17:04:27,11 WARNING DNS server started on 127.0.0.1:2345',
        '2014-09-27 17:04:27,12 WARNING HTTP server started on 127.0.0.1:3456',
        '2014-09-27 17:04:27,13 WARNING HTTPS server started on 127.0.0.1:4567',
        ])
    self.assertEqual(
        {'dns': 2345, 'http': 3456, 'https': 4567},
        wpr_server.ReplayServer._ParseLogFilePorts(log_lines))
