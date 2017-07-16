# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

class RgbaColor(collections.namedtuple('RgbaColor', ['r', 'g', 'b', 'a'])):
  """Encapsulates an RGBA color retrieved from an image."""
  def __new__(cls, r, g, b, a=255):
    return super(RgbaColor, cls).__new__(cls, r, g, b, a)

  def __int__(self):
    return (self.r << 16) | (self.g << 8) | self.b

  def IsEqual(self, expected_color, tolerance=0):
    """Verifies that the color is within a given tolerance of
    the expected color."""
    r_diff = abs(self.r - expected_color.r)
    g_diff = abs(self.g - expected_color.g)
    b_diff = abs(self.b - expected_color.b)
    a_diff = abs(self.a - expected_color.a)
    return (r_diff <= tolerance and g_diff <= tolerance
        and b_diff <= tolerance and a_diff <= tolerance)

  def AssertIsRGB(self, r, g, b, tolerance=0):
    assert self.IsEqual(RgbaColor(r, g, b), tolerance)

  def AssertIsRGBA(self, r, g, b, a, tolerance=0):
    assert self.IsEqual(RgbaColor(r, g, b, a), tolerance)


WEB_PAGE_TEST_ORANGE = RgbaColor(222, 100, 13)
WHITE = RgbaColor(255, 255, 255)
