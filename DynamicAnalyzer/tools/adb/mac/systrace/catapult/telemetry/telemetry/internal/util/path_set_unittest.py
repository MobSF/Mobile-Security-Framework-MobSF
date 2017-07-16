#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry.internal.util import path_set


class PathSetTest(unittest.TestCase):
  def testCreate(self):
    ps = path_set.PathSet()
    self.assertEqual(len(ps), 0)  # Check __len__.
    self.assertFalse(__file__ in ps)
    for _ in ps:  # Check __iter__.
      self.fail('New set is not empty.')

    ps = path_set.PathSet([__file__])
    self.assertEqual(len(ps), 1)
    self.assertTrue(__file__ in ps)
    self.assertEqual(ps.pop(), os.path.realpath(__file__))

  def testAdd(self):
    ps = path_set.PathSet()
    ps.add(__file__)
    self.assertEqual(len(ps), 1)
    self.assertTrue(__file__ in ps)
    self.assertEqual(ps.pop(), os.path.realpath(__file__))

  def testDiscard(self):
    ps = path_set.PathSet([__file__])
    ps.discard(__file__)
    self.assertEqual(len(ps), 0)
    self.assertFalse(__file__ in ps)


if __name__ == '__main__':
  unittest.main()
