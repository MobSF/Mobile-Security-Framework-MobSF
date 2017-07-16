# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import unittest

from telemetry import decorators
from telemetry.internal.util import path


class PathTest(unittest.TestCase):
  def testIsExecutable(self):
    self.assertFalse(path.IsExecutable('nonexistent_file'))
    self.assertTrue(path.IsExecutable(sys.executable))

  @decorators.Enabled('win')
  def testFindInstalledWindowsApplication(self):
    self.assertTrue(path.FindInstalledWindowsApplication(os.path.join(
        'Internet Explorer', 'iexplore.exe')))

  @decorators.Enabled('win')
  def testFindInstalledWindowsApplicationWithWildcards(self):
    self.assertTrue(path.FindInstalledWindowsApplication(os.path.join(
        '*', 'iexplore.exe')))
