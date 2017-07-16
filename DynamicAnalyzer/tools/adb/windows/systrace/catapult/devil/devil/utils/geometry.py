# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Objects for convenient manipulation of points and other surface areas."""

import collections


class Point(collections.namedtuple('Point', ['x', 'y'])):
  """Object to represent an (x, y) point on a surface.

  Args:
    x, y: Two numeric coordinates that define the point.
  """
  __slots__ = ()

  def __str__(self):
    """Get a useful string representation of the object."""
    return '(%s, %s)' % (self.x, self.y)

  def __add__(self, other):
    """Sum of two points, e.g. p + q."""
    if isinstance(other, Point):
      return Point(self.x + other.x, self.y + other.y)
    else:
      return NotImplemented

  def __mul__(self, factor):
    """Multiplication on the right is not implemented."""
    # This overrides the default behaviour of a tuple multiplied by a constant
    # on the right, which does not make sense for a Point.
    return NotImplemented

  def __rmul__(self, factor):
    """Multiply a point by a scalar factor on the left, e.g. 2 * p."""
    return Point(factor * self.x, factor * self.y)


class Rectangle(
    collections.namedtuple('Rectangle', ['top_left', 'bottom_right'])):
  """Object to represent a rectangle on a surface.

  Args:
    top_left: A pair of (left, top) coordinates. Might be given as a Point
      or as a two-element sequence (list, tuple, etc.).
    bottom_right: A pair (right, bottom) coordinates.
  """
  __slots__ = ()

  def __new__(cls, top_left, bottom_right):
    if not isinstance(top_left, Point):
      top_left = Point(*top_left)
    if not isinstance(bottom_right, Point):
      bottom_right = Point(*bottom_right)
    return super(Rectangle, cls).__new__(cls, top_left, bottom_right)

  def __str__(self):
    """Get a useful string representation of the object."""
    return '[%s, %s]' % (self.top_left, self.bottom_right)

  @property
  def center(self):
    """Get the point at the center of the rectangle."""
    return 0.5 * (self.top_left + self.bottom_right)

  @classmethod
  def FromDict(cls, d):
    """Create a rectangle object from a dictionary.

    Args:
      d: A dictionary (or mapping) of the form, e.g., {'top': 0, 'left': 0,
         'bottom': 1, 'right': 1}.
    """
    return cls(Point(d['left'], d['top']), Point(d['right'], d['bottom']))
