# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for the geometry module."""

import unittest

from devil.utils import geometry as g


class PointTest(unittest.TestCase):

  def testStr(self):
    p = g.Point(1, 2)
    self.assertEquals(str(p), '(1, 2)')

  def testAdd(self):
    p = g.Point(1, 2)
    q = g.Point(3, 4)
    r = g.Point(4, 6)
    self.assertEquals(p + q, r)

  def testAdd_TypeErrorWithInvalidOperands(self):
    # pylint: disable=pointless-statement
    p = g.Point(1, 2)
    with self.assertRaises(TypeError):
      p + 4  # Can't add point and scalar.
    with self.assertRaises(TypeError):
      4 + p  # Can't add scalar and point.

  def testMult(self):
    p = g.Point(1, 2)
    r = g.Point(2, 4)
    self.assertEquals(2 * p, r)  # Multiply by scalar on the left.

  def testMult_TypeErrorWithInvalidOperands(self):
    # pylint: disable=pointless-statement
    p = g.Point(1, 2)
    q = g.Point(2, 4)
    with self.assertRaises(TypeError):
      p * q  # Can't multiply points.
    with self.assertRaises(TypeError):
      p * 4  # Can't multiply by a scalar on the right.


class RectangleTest(unittest.TestCase):

  def testStr(self):
    r = g.Rectangle(g.Point(0, 1), g.Point(2, 3))
    self.assertEquals(str(r), '[(0, 1), (2, 3)]')

  def testCenter(self):
    r = g.Rectangle(g.Point(0, 1), g.Point(2, 3))
    c = g.Point(1, 2)
    self.assertEquals(r.center, c)

  def testFromJson(self):
    r1 = g.Rectangle(g.Point(0, 1), g.Point(2, 3))
    r2 = g.Rectangle.FromDict({'top': 1, 'left': 0, 'bottom': 3, 'right': 2})
    self.assertEquals(r1, r2)
