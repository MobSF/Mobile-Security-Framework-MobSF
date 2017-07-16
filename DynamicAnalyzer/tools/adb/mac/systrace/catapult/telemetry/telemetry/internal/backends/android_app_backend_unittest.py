# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import collections
import mock
import unittest

from telemetry.internal.backends import android_app_backend
from devil.android.sdk import intent as intent_module


_FakeAndroidProcess = collections.namedtuple(
    'AndroidProcess', ['app_backend', 'pid', 'name'])


class AndroidAppBackendUnittest(unittest.TestCase):

  def setUp(self):
    self.platform_backend = mock.Mock()
    self.start_intent = intent_module.Intent(
        package='com.example.my_app',
        activity='com.example.my_app.LaunchMyApp')
    self.app_backend = android_app_backend.AndroidAppBackend(
        self.platform_backend, self.start_intent)

  @mock.patch('telemetry.internal.backends.android_app_backend'
              '.android_process.AndroidProcess', _FakeAndroidProcess)
  def testGetProcesses(self):
    # Only processes belonging to 'com.example.my_app' should match.
    self.platform_backend.GetPsOutput.return_value = [
      ['1111', 'com.example.my_app'],
      ['2222', 'com.example.my_appointments_helper'],
      ['3333', 'com.example.my_app:service'],
      ['4444', 'com.example.some_other_app'],
      ['5555', 'com_example_my_app'],
    ]
    process_pids = set(p.pid for p in self.app_backend.GetProcesses())
    self.assertEquals(process_pids, set(['1111', '3333']))
