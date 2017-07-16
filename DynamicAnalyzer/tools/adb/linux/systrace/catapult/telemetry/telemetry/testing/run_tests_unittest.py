# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.core import util
from telemetry.testing import run_tests


class MockArgs(object):
  def __init__(self):
    self.positional_args = []
    self.exact_test_filter = True
    self.run_disabled_tests = False
    self.skip = []


class MockPossibleBrowser(object):
  def __init__(self, browser_type, os_name, os_version_name,
               supports_tab_control):
    self.browser_type = browser_type
    self.platform = MockPlatform(os_name, os_version_name)
    self.supports_tab_control = supports_tab_control


class MockPlatform(object):
  def __init__(self, os_name, os_version_name):
    self.os_name = os_name
    self.os_version_name = os_version_name

  def GetOSName(self):
    return self.os_name

  def GetOSVersionName(self):
    return self.os_version_name


class RunTestsUnitTest(unittest.TestCase):

  def _GetEnabledTests(self, browser_type, os_name, os_version_name,
                       supports_tab_control, args=None):
    if not args:
      args = MockArgs()
    runner = run_tests.typ.Runner()
    host = runner.host
    runner.top_level_dir = util.GetTelemetryDir()
    runner.args.tests = [host.join(util.GetTelemetryDir(),
        'telemetry', 'testing', 'disabled_cases.py')]
    possible_browser = MockPossibleBrowser(
        browser_type, os_name, os_version_name, supports_tab_control)
    runner.classifier = run_tests.GetClassifier(args, possible_browser)
    _, test_set = runner.find_tests(runner.args)
    return set(test.name.split('.')[-1] for test in test_set.parallel_tests)

  def testSystemMacMavericks(self):
    self.assertEquals(
        set(['testAllEnabled',
             'testMacOnly',
             'testMavericksOnly',
             'testNoChromeOS',
             'testNoWinLinux',
             'testSystemOnly',
             'testHasTabs']),
        self._GetEnabledTests('system', 'mac', 'mavericks', True))

  def testSystemMacLion(self):
    self.assertEquals(
        set(['testAllEnabled',
             'testMacOnly',
             'testNoChromeOS',
             'testNoMavericks',
             'testNoWinLinux',
             'testSystemOnly',
             'testHasTabs']),
        self._GetEnabledTests('system', 'mac', 'lion', True))

  def testCrosGuestChromeOS(self):
    self.assertEquals(
        set(['testAllEnabled',
             'testChromeOSOnly',
             'testNoMac',
             'testNoMavericks',
             'testNoSystem',
             'testNoWinLinux',
             'testHasTabs']),
        self._GetEnabledTests('cros-guest', 'chromeos', '', True))

  def testCanaryWindowsWin7(self):
    self.assertEquals(
        set(['testAllEnabled',
             'testNoChromeOS',
             'testNoMac',
             'testNoMavericks',
             'testNoSystem',
             'testWinOrLinuxOnly',
             'testHasTabs']),
        self._GetEnabledTests('canary', 'win', 'win7', True))

  def testDoesntHaveTabs(self):
    self.assertEquals(
        set(['testAllEnabled',
             'testNoChromeOS',
             'testNoMac',
             'testNoMavericks',
             'testNoSystem',
             'testWinOrLinuxOnly']),
        self._GetEnabledTests('canary', 'win', 'win7', False))

  def testSkip(self):
    args = MockArgs()
    args.skip = ['telemetry.*testNoMac', '*NoMavericks',
                 'telemetry.testing.disabled_cases.DisabledCases.testNoSystem']
    self.assertEquals(
        set(['testAllEnabled',
             'testNoChromeOS',
             'testWinOrLinuxOnly',
             'testHasTabs']),
        self._GetEnabledTests('canary', 'win', 'win7', True, args))
