# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.core import exceptions
from telemetry.internal.util import binary_manager
import mock


class BinaryManagerTest(unittest.TestCase):
  def setUp(self):
    # We need to preserve the real initialized dependecny_manager.
    self.actual_binary_manager = binary_manager._binary_manager
    binary_manager._binary_manager = None

  def tearDown(self):
    binary_manager._binary_manager = self.actual_binary_manager

  def testReinitialization(self):
    binary_manager.InitDependencyManager(None)
    self.assertRaises(exceptions.InitializationError,
                      binary_manager.InitDependencyManager, None)

  @mock.patch('py_utils.binary_manager.BinaryManager')
  def testFetchPathInitialized(self, binary_manager_mock):
    expected = [mock.call.binary_manager.BinaryManager(
                   ['base_config_object']),
                mock.call.binary_manager.BinaryManager().FetchPath(
                    'dep', 'plat_arch')]
    binary_manager.InitDependencyManager(None)
    binary_manager.FetchPath('dep', 'plat', 'arch')
    binary_manager_mock.assert_call_args(expected)

  def testFetchPathUninitialized(self):
    self.assertRaises(exceptions.InitializationError,
                      binary_manager.FetchPath, 'dep', 'plat', 'arch')

  @mock.patch('py_utils.binary_manager.BinaryManager')
  def testLocalPathInitialized(self, binary_manager_mock):
    expected = [mock.call.binary_manager.BinaryManager(
                   ['base_config_object']),
                mock.call.binary_manager.BinaryManager().LocalPath(
                    'dep', 'plat_arch')]
    binary_manager.InitDependencyManager(None)
    binary_manager.LocalPath('dep', 'plat', 'arch')
    binary_manager_mock.assert_call_args(expected)

  def testLocalPathUninitialized(self):
    self.assertRaises(exceptions.InitializationError,
                      binary_manager.LocalPath, 'dep', 'plat', 'arch')
