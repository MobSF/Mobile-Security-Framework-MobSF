# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import telemetry.timeline.event as event


class AsyncSlice(event.TimelineEvent):
  """An AsyncSlice represents an interval of time during which an
  asynchronous operation is in progress. An AsyncSlice consumes no CPU time
  itself and so is only associated with Threads at its start and end point.
  """
  def __init__(self, category, name, timestamp, args=None,
               duration=0, start_thread=None, end_thread=None,
               thread_start=None, thread_duration=None):
    super(AsyncSlice, self).__init__(
        category, name, timestamp, duration, thread_start, thread_duration,
        args)
    self.parent_slice = None
    self.start_thread = start_thread
    self.end_thread = end_thread
    self.sub_slices = []
    self.id = None

  def AddSubSlice(self, sub_slice):
    assert sub_slice.parent_slice == self
    self.sub_slices.append(sub_slice)

  def IterEventsInThisContainerRecrusively(self):
    for sub_slice in self.sub_slices:
      yield sub_slice
