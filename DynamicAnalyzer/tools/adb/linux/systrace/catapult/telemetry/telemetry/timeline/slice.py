# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import telemetry.timeline.event as timeline_event


class Slice(timeline_event.TimelineEvent):
  """A Slice represents an interval of time plus parameters associated
  with that interval.

  NOTE: The Sample class implements the same interface as
  Slice. These must be kept in sync.

  All time units are stored in milliseconds.
  """
  def __init__(self, parent_thread, category, name, timestamp, duration=0,
               thread_timestamp=None, thread_duration=None, args=None):
    super(Slice, self).__init__(
        category, name, timestamp, duration, thread_timestamp, thread_duration,
        args)
    self.parent_thread = parent_thread
    self.parent_slice = None
    self.sub_slices = []
    self.did_not_finish = False

  def AddSubSlice(self, sub_slice):
    assert sub_slice.parent_slice == self
    self.sub_slices.append(sub_slice)

  def IterEventsInThisContainerRecrusively(self, stack=None):
    # This looks awkward, but it lets us create only a single iterator instead
    # of having to create one iterator for every subslice found.
    if stack == None:
      stack = []
    else:
      assert len(stack) == 0
    stack.extend(reversed(self.sub_slices))
    while len(stack):
      s = stack.pop()
      yield s
      stack.extend(reversed(s.sub_slices))

  @property
  def self_time(self):
    """Time spent in this function less any time spent in child events."""
    child_total = sum(
      [e.duration for e in self.sub_slices])
    return self.duration - child_total

  @property
  def self_thread_time(self):
    """Thread (scheduled) time spent in this function less any thread time spent
    in child events. Returns None if the slice or any of its children does not
    have a thread_duration value.
    """
    if not self.thread_duration:
      return None

    child_total = 0
    for e in self.sub_slices:
      if e.thread_duration == None:
        return None
      child_total += e.thread_duration

    return self.thread_duration - child_total

  def _GetSubSlicesRecursive(self):
    for sub_slice in self.sub_slices:
      for s in sub_slice.GetAllSubSlices():
        yield s
      yield sub_slice

  def GetAllSubSlices(self):
    return list(self._GetSubSlicesRecursive())

  def GetAllSubSlicesOfName(self, name):
    return [e for e in self.GetAllSubSlices() if e.name == name]
