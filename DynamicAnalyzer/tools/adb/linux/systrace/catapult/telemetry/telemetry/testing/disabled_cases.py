# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import decorators


# These are not real unittests.
# They are merely to test our Enable/Disable annotations.
class DisabledCases(unittest.TestCase):

  def testAllEnabled(self):
    pass

  @decorators.Disabled('all')
  def testAllDisabled(self):
    pass

  @decorators.Enabled('mavericks')
  def testMavericksOnly(self):
    pass

  @decorators.Disabled('mavericks')
  def testNoMavericks(self):
    pass

  @decorators.Enabled('mac')
  def testMacOnly(self):
    pass

  @decorators.Disabled('mac')
  def testNoMac(self):
    pass

  @decorators.Enabled('chromeos')
  def testChromeOSOnly(self):
    pass

  @decorators.Disabled('chromeos')
  def testNoChromeOS(self):
    pass

  @decorators.Enabled('win', 'linux')
  def testWinOrLinuxOnly(self):
    pass

  @decorators.Disabled('win', 'linux')
  def testNoWinLinux(self):
    pass

  @decorators.Enabled('system')
  def testSystemOnly(self):
    pass

  @decorators.Disabled('system')
  def testNoSystem(self):
    pass

  @decorators.Enabled('has tabs')
  def testHasTabs(self):
    pass
