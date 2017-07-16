# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

class Bounds(object):
  """Represents a min-max bounds."""
  def __init__(self):
    self.is_empty_ = True
    self.min_ = None
    self.max_ = None

  @staticmethod
  def CreateFromEvent(event):
    bounds = Bounds()
    bounds.AddEvent(event)
    return bounds

  def __repr__(self):
    if self.is_empty_:
      return "Bounds()"
    else:
      return "Bounds(min=%s,max=%s)" % (self.min_, self.max_)

  @property
  def is_empty(self):
    return self.is_empty_

  @property
  def min(self):
    if self.is_empty_:
      return None
    return self.min_

  @property
  def max(self):
    if self.is_empty_:
      return None
    return self.max_

  @property
  def bounds(self):
    if self.is_empty_:
      return None
    return self.max_ - self.min_

  @property
  def center(self):
    return (self.min_ + self.max_) * 0.5

  def Contains(self, other):
    if self.is_empty or other.is_empty:
      return False
    return self.min <= other.min and self.max >= other.max

  def ContainsInterval(self, start, end):
    return self.min <= start and self.max >= end

  def Intersects(self, other):
    if self.is_empty or other.is_empty:
      return False
    return not (other.max < self.min or other.min > self.max)

  def Reset(self):
    self.is_empty_ = True
    self.min_ = None
    self.max_ = None

  def AddBounds(self, bounds):
    if bounds.is_empty:
      return
    self.AddValue(bounds.min_)
    self.AddValue(bounds.max_)

  def AddValue(self, value):
    if self.is_empty_:
      self.max_ = value
      self.min_ = value
      self.is_empty_ = False
      return

    self.max_ = max(self.max_, value)
    self.min_ = min(self.min_, value)

  def AddEvent(self, event):
    self.AddValue(event.start)
    self.AddValue(event.start + event.duration)

  @staticmethod
  def CompareByMinTimes(a, b):
    if not a.is_empty and not b.is_empty:
      return a.min_ - b.min_

    if a.is_empty and not b.is_empty:
      return -1

    if not a.is_empty and b.is_empty:
      return 1

    return 0

  @staticmethod
  def GetOverlapBetweenBounds(first_bounds, second_bounds):
    """Compute the overlap duration between first_bounds and second_bounds."""
    return Bounds.GetOverlap(first_bounds.min_, first_bounds.max_,
                             second_bounds.min_, second_bounds.max_)

  @staticmethod
  def GetOverlap(first_bounds_min, first_bounds_max,
                 second_bounds_min, second_bounds_max):
    assert first_bounds_min <= first_bounds_max
    assert second_bounds_min <= second_bounds_max
    overlapped_range_start = max(first_bounds_min, second_bounds_min)
    overlapped_range_end = min(first_bounds_max, second_bounds_max)
    return max(overlapped_range_end - overlapped_range_start, 0)
