# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import errno
import socket
import unittest

from telemetry import decorators
from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import websocket
from telemetry.testing import fakes


class FakeSocket(object):
  """A fake websocket that allows test to send random data."""
  def __init__(self, fake_timer):
    self._fake_timer = fake_timer
    self._responses = []
    self._timeout = None

  def AddResponse(self, response, time):
    if self._responses:
      assert self._responses[-1][1] < time, (
          'Current response is scheduled earlier than previous response.')
    self._responses.append((response, time))

  def send(self, data):
    pass

  def recv(self):
    if not self._responses:
      raise Exception('No more recorded responses.')

    response, time = self._responses.pop(0)
    current_time = self._fake_timer.time()
    if self._timeout is not None and time - current_time > self._timeout:
      self._fake_timer.SetTime(current_time + self._timeout + 1)
      raise websocket.WebSocketTimeoutException()

    self._fake_timer.SetTime(time)
    if isinstance(response, Exception):
      raise response
    return response

  def settimeout(self, timeout):
    self._timeout = timeout


def _DoNothingHandler(elapsed_time):
  del elapsed_time  # unused


class InspectorWebsocketUnittest(unittest.TestCase):

  def setUp(self):
    self._fake_timer = fakes.FakeTimer()

  def tearDown(self):
    self._fake_timer.Restore()

  @decorators.Disabled('chromeos', 'mac')  # crbug.com/483212, crbug.com/498950
  def testDispatchNotification(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket

    results = []
    def OnTestEvent(result):
      results.append(result)

    inspector.RegisterDomain('Test', OnTestEvent)
    fake_socket.AddResponse('{"method": "Test.foo"}', 5)
    inspector.DispatchNotifications(10)
    self.assertEqual(1, len(results))
    self.assertEqual('Test.foo', results[0]['method'])

  @decorators.Disabled('chromeos')  # crbug.com/483212
  def testDispatchNotificationTimedOut(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket

    results = []
    def OnTestEvent(result):
      results.append(result)

    inspector.RegisterDomain('Test', OnTestEvent)
    fake_socket.AddResponse('{"method": "Test.foo"}', 11)
    with self.assertRaises(
        websocket.WebSocketTimeoutException):
      inspector.DispatchNotifications(timeout=10)
    self.assertEqual(0, len(results))

  @decorators.Disabled('chromeos')  # crbug.com/483212
  def testUnregisterDomain(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket

    results = []
    def OnTestEvent(result):
      results.append(result)

    inspector.RegisterDomain('Test', OnTestEvent)
    inspector.RegisterDomain('Test2', OnTestEvent)
    inspector.UnregisterDomain('Test')

    fake_socket.AddResponse('{"method": "Test.foo"}', 5)
    fake_socket.AddResponse('{"method": "Test2.foo"}', 10)

    inspector.DispatchNotifications(10)
    self.assertEqual(0, len(results))

    inspector.DispatchNotifications(10)
    self.assertEqual(1, len(results))
    self.assertEqual('Test2.foo', results[0]['method'])

  @decorators.Disabled('chromeos')  # crbug.com/483212
  def testUnregisterDomainWithUnregisteredDomain(self):
    inspector = inspector_websocket.InspectorWebsocket()
    with self.assertRaises(AssertionError):
      inspector.UnregisterDomain('Test')

  def testAsyncRequest(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket
    response_count = [0]

    def callback0(response):
      response_count[0] += 1
      self.assertEqual(2, response_count[0])
      self.assertEqual('response1', response['result']['data'])

    def callback1(response):
      response_count[0] += 1
      self.assertEqual(1, response_count[0])
      self.assertEqual('response2', response['result']['data'])

    request1 = {'method': 'Test.foo'}
    inspector.AsyncRequest(request1, callback0)
    request2 = {'method': 'Test.foo'}
    inspector.AsyncRequest(request2, callback1)
    fake_socket.AddResponse('{"id": 5555555, "result": {}}', 1)
    inspector.DispatchNotifications(10)
    self.assertEqual(0, response_count[0])
    fake_socket.AddResponse(
        '{"id": %d, "result": {"data": "response2"}}' % request2['id'], 1)
    fake_socket.AddResponse(
        '{"id": %d, "result": {"data": "response1"}}' % request1['id'], 2)
    inspector.DispatchNotifications(10)
    inspector.DispatchNotifications(10)
    self.assertEqual(2, response_count[0])
    fake_socket.AddResponse('{"id": 6666666, "result": {}}', 1)
    inspector.DispatchNotifications(10)
    self.assertEqual(2, response_count[0])

  def testEAGAIN(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket

    error = socket.error(errno.EAGAIN, "error string")
    fake_socket.AddResponse(error, 4)
    fake_socket.AddResponse('{"asdf": "qwer"}', 5)

    result = inspector._Receive(10)
    self.assertEqual(result, {"asdf" : "qwer"})

  def testSocketErrorOtherThanEAGAIN(self):
    inspector = inspector_websocket.InspectorWebsocket()
    fake_socket = FakeSocket(self._fake_timer)
    # pylint: disable=protected-access
    inspector._socket = fake_socket

    error = socket.error(errno.EPIPE, "error string")
    fake_socket.AddResponse(error, 4)

    with self.assertRaises(socket.error):
      inspector._Receive(10)
