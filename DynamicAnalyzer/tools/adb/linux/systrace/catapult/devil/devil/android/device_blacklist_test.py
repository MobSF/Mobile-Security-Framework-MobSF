#! /usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import tempfile
import unittest

from devil.android import device_blacklist


class DeviceBlacklistTest(unittest.TestCase):

  def testBlacklistFileDoesNotExist(self):
    with tempfile.NamedTemporaryFile() as blacklist_file:
      # Allow the temporary file to be deleted.
      pass

    test_blacklist = device_blacklist.Blacklist(blacklist_file.name)
    self.assertEquals({}, test_blacklist.Read())

  def testBlacklistFileIsEmpty(self):
    try:
      with tempfile.NamedTemporaryFile(delete=False) as blacklist_file:
        # Allow the temporary file to be closed.
        pass

      test_blacklist = device_blacklist.Blacklist(blacklist_file.name)
      self.assertEquals({}, test_blacklist.Read())

    finally:
      if os.path.exists(blacklist_file.name):
        os.remove(blacklist_file.name)


if __name__ == '__main__':
  unittest.main()
