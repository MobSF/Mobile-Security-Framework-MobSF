# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import mock
import unittest


from telemetry.internal.backends.chrome_inspector import inspector_websocket
from telemetry.internal.backends.chrome_inspector import memory_backend
from telemetry.testing import fakes
from telemetry.testing import tab_test_case


class MemoryBackendTest(tab_test_case.TabTestCase):

  def setUp(self):
    super(MemoryBackendTest, self).setUp()
    if not self._browser.supports_overriding_memory_pressure_notifications:
      self.skipTest('Browser does not support overriding memory pressure '
                    'notification signals, skipping test.')

  def testSetMemoryPressureNotificationsSuppressed(self):
    def PerformCheck(suppressed):
      # Check that the method sends the correct DevTools request.
      with mock.patch.object(inspector_websocket.InspectorWebsocket,
                             'SyncRequest') as mock_method:
        self._browser.SetMemoryPressureNotificationsSuppressed(suppressed)
        self.assertEqual(1, mock_method.call_count)
        request = mock_method.call_args[0][0]
        self.assertEqual('Memory.setPressureNotificationsSuppressed',
                         request['method'])
        self.assertEqual(suppressed, request['params']['suppressed'])

      # Check that the request and the response from the browser are handled
      # properly.
      self._browser.SetMemoryPressureNotificationsSuppressed(suppressed)

    PerformCheck(True)
    PerformCheck(False)

  def testSimulateMemoryPressureNotification(self):
    def PerformCheck(pressure_level):
      # Check that the method sends the correct DevTools request.
      with mock.patch.object(inspector_websocket.InspectorWebsocket,
                             'SyncRequest') as mock_method:
        self._browser.SimulateMemoryPressureNotification(pressure_level)
        self.assertEqual(1, mock_method.call_count)
        request = mock_method.call_args[0][0]
        self.assertEqual('Memory.simulatePressureNotification',
                         request['method'])
        self.assertEqual(pressure_level, request['params']['level'])

      # Check that the request and the response from the browser are handled
      # properly.
      self._browser.SimulateMemoryPressureNotification(pressure_level)

    PerformCheck('moderate')
    PerformCheck('critical')


class MemoryBackendUnitTest(unittest.TestCase):

  def setUp(self):
    self._fake_timer = fakes.FakeTimer()
    self._inspector_socket = fakes.FakeInspectorWebsocket(self._fake_timer)

  def tearDown(self):
    self._fake_timer.Restore()

  def testSetMemoryPressureNotificationsSuppressedSuccess(self):
    response_handler = mock.Mock(return_value={'result': {}})
    self._inspector_socket.AddResponseHandler(
        'Memory.setPressureNotificationsSuppressed', response_handler)
    backend = memory_backend.MemoryBackend(self._inspector_socket)

    backend.SetMemoryPressureNotificationsSuppressed(True)
    self.assertEqual(1, response_handler.call_count)
    self.assertTrue(response_handler.call_args[0][0]['params']['suppressed'])

    backend.SetMemoryPressureNotificationsSuppressed(False)
    self.assertEqual(2, response_handler.call_count)
    self.assertFalse(response_handler.call_args[0][0]['params']['suppressed'])

  def testSetMemoryPressureNotificationsSuppressedFailure(self):
    response_handler = mock.Mock()
    backend = memory_backend.MemoryBackend(self._inspector_socket)
    self._inspector_socket.AddResponseHandler(
        'Memory.setPressureNotificationsSuppressed', response_handler)

    # If the DevTools method is missing, the backend should fail silently.
    response_handler.return_value = {
      'result': {},
      'error': {
        'code': -32601  # Method does not exist.
      }
    }
    backend.SetMemoryPressureNotificationsSuppressed(True)
    self.assertEqual(1, response_handler.call_count)

    # All other errors should raise an exception.
    response_handler.return_value = {
      'result': {},
      'error': {
        'code': -32602  # Invalid method params.
      }
    }
    self.assertRaises(memory_backend.MemoryUnexpectedResponseException,
                      backend.SetMemoryPressureNotificationsSuppressed, True)

  def testSimulateMemoryPressureNotificationSuccess(self):
    response_handler = mock.Mock(return_value={'result': {}})
    self._inspector_socket.AddResponseHandler(
        'Memory.simulatePressureNotification', response_handler)
    backend = memory_backend.MemoryBackend(self._inspector_socket)

    backend.SimulateMemoryPressureNotification('critical')
    self.assertEqual(1, response_handler.call_count)
    self.assertEqual('critical',
                     response_handler.call_args[0][0]['params']['level'])

    backend.SimulateMemoryPressureNotification('moderate')
    self.assertEqual(2, response_handler.call_count)
    self.assertEqual('moderate',
                     response_handler.call_args[0][0]['params']['level'])

  def testSimulateMemoryPressureNotificationFailure(self):
    response_handler = mock.Mock()
    backend = memory_backend.MemoryBackend(self._inspector_socket)
    self._inspector_socket.AddResponseHandler(
        'Memory.simulatePressureNotification', response_handler)

    # If the DevTools method is missing, the backend should fail silently.
    response_handler.return_value = {
      'result': {},
      'error': {
        'code': -32601  # Method does not exist.
      }
    }
    backend.SimulateMemoryPressureNotification('critical')
    self.assertEqual(1, response_handler.call_count)

    # All other errors should raise an exception.
    response_handler.return_value = {
      'result': {},
      'error': {
        'code': -32602  # Invalid method params.
      }
    }
    self.assertRaises(memory_backend.MemoryUnexpectedResponseException,
                      backend.SimulateMemoryPressureNotification, 'critical')
