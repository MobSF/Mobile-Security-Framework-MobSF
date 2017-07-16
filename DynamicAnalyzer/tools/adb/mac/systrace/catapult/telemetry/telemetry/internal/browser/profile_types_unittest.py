# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.internal.browser import profile_types


class ProfileTypesTest(unittest.TestCase):
  def testGetProfileTypes(self):
    types = profile_types.GetProfileTypes()

    self.assertTrue('clean' in types)
    self.assertTrue(len(types) > 0)

  def testGetProfileDir(self):
    self.assertFalse(profile_types.GetProfileDir('typical_user') is None)
