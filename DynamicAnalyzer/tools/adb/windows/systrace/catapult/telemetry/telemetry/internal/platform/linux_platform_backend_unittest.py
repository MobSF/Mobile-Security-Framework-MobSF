# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry import decorators
from telemetry.core import util
from telemetry.internal.platform import linux_platform_backend
import mock


class LinuxPlatformBackendTest(unittest.TestCase):
  @decorators.Enabled('linux')
  def testGetOSVersionNameSaucy(self):
    path = os.path.join(util.GetUnittestDataDir(), 'ubuntu-saucy-lsb-release')
    with open(path) as f:
      unbuntu_saucy_lsb_release_content = f.read()

    with mock.patch.object(
        linux_platform_backend.LinuxPlatformBackend, 'GetFileContents',
        return_value=unbuntu_saucy_lsb_release_content) as mock_method:
      backend = linux_platform_backend.LinuxPlatformBackend()
      self.assertEqual(backend.GetOSVersionName(), 'saucy')
      mock_method.assert_called_once_with('/etc/lsb-release')

  @decorators.Enabled('linux')
  def testGetOSVersionNameArch(self):
    path = os.path.join(util.GetUnittestDataDir(), 'arch-lsb-release')
    with open(path) as f:
      arch_lsb_release_content = f.read()

    with mock.patch.object(
        linux_platform_backend.LinuxPlatformBackend, 'GetFileContents',
        return_value=arch_lsb_release_content) as mock_method:
      backend = linux_platform_backend.LinuxPlatformBackend()
      # a distribution may not have a codename or a release number. We just
      # check that GetOSVersionName doesn't raise an exception
      backend.GetOSVersionName()
      mock_method.assert_called_once_with('/etc/lsb-release')
