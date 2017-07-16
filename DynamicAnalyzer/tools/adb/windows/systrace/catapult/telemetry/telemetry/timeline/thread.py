# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import telemetry.timeline.async_slice as async_slice_module
import telemetry.timeline.event_container as event_container
import telemetry.timeline.flow_event as flow_event_module
import telemetry.timeline.sample as sample_module
import telemetry.timeline.slice as slice_module


class Thread(event_container.TimelineEventContainer):
  """A Thread stores all the trace events collected for a particular
  thread. We organize the synchronous slices on a thread by "subrows," where
  subrow 0 has all the root slices, subrow 1 those nested 1 deep, and so on.
  The asynchronous slices are stored in an AsyncSliceGroup object.
  """
  def __init__(self, process, tid):
    super(Thread, self).__init__('thread %s' % tid, parent=process)
    self.tid = tid
    self._async_slices = []
    self._flow_events = []
    self._samples = []
    self._toplevel_slices = []
    self._all_slices = []

    # State only valid during import.
    self._open_slices = []
    self._newly_added_slices = []

  @property
  def toplevel_slices(self):
    return self._toplevel_slices

  @property
  def all_slices(self):
    return self._all_slices

  @property
  def samples(self):
    return self._samples

  @property
  def async_slices(self):
    return self._async_slices

  @property
  def open_slice_count(self):
    return len(self._open_slices)

  def IterChildContainers(self):
    return
    yield # pylint: disable=unreachable

  def IterEventsInThisContainer(self, event_type_predicate, event_predicate):
    if event_type_predicate(slice_module.Slice):
      for s in self._newly_added_slices:
        if event_predicate(s):
          yield s
      for s in self._all_slices:
        if event_predicate(s):
          yield s

    if event_type_predicate(async_slice_module.AsyncSlice):
      for async_slice in self._async_slices:
        if event_predicate(async_slice):
          yield async_slice
        for sub_slice in async_slice.IterEventsInThisContainerRecrusively():
          if event_predicate(sub_slice):
            yield sub_slice

    if event_type_predicate(flow_event_module.FlowEvent):
      for flow_event in self._flow_events:
        if event_predicate(flow_event):
          yield flow_event

    if event_type_predicate(sample_module.Sample):
      for sample in self._samples:
        if event_predicate(sample):
          yield sample

  def AddSample(self, category, name, timestamp, args=None):
    if len(self._samples) and timestamp < self._samples[-1].start:
      raise ValueError(
          'Samples must be added in increasing timestamp order')
    sample = sample_module.Sample(self,
        category, name, timestamp, args=args)
    self._samples.append(sample)

  def AddAsyncSlice(self, async_slice):
    self._async_slices.append(async_slice)

  def AddFlowEvent(self, flow_event):
    self._flow_events.append(flow_event)

  def BeginSlice(self, category, name, timestamp, thread_timestamp=None,
                 args=None):
    """Opens a new slice for the thread.
    Calls to beginSlice and endSlice must be made with
    non-monotonically-decreasing timestamps.

    * category: Category to which the slice belongs.
    * name: Name of the slice to add.
    * timestamp: The timetsamp of the slice, in milliseconds.
    * thread_timestamp: Thread specific clock (scheduled) timestamp of the
                        slice, in milliseconds.
    * args: Arguments associated with

    Returns newly opened slice
    """
    if len(self._open_slices) > 0 and timestamp < self._open_slices[-1].start:
      raise ValueError(
          'Slices must be added in increasing timestamp order')
    new_slice = slice_module.Slice(self, category, name, timestamp,
                                    thread_timestamp=thread_timestamp,
                                    args=args)
    self._open_slices.append(new_slice)
    new_slice.did_not_finish = True
    self.PushSlice(new_slice)
    return new_slice

  def EndSlice(self, end_timestamp, end_thread_timestamp=None):
    """ Ends the last begun slice in this group and pushes it onto the slice
    array.

    * end_timestamp: Timestamp when the slice ended in milliseconds
    * end_thread_timestamp: Timestamp when the scheduled time of the slice ended
                            in milliseconds

    returns completed slice.
    """
    if not len(self._open_slices):
      raise ValueError(
          'EndSlice called without an open slice')
    curr_slice = self._open_slices.pop()
    if end_timestamp < curr_slice.start:
      raise ValueError(
          'Slice %s end time is before its start.' % curr_slice.name)
    curr_slice.duration = end_timestamp - curr_slice.start
    # On Windows, it is possible to have a value for |end_thread_timestamp|
    # but not for |curr_slice.thread_start|, because it takes some time to
    # initialize the thread time timer.
    if curr_slice.thread_start != None and end_thread_timestamp != None:
      curr_slice.thread_duration = (end_thread_timestamp -
                                    curr_slice.thread_start)
    curr_slice.did_not_finish = False
    return curr_slice

  def PushCompleteSlice(self, category, name, timestamp, duration,
                        thread_timestamp, thread_duration, args=None):
    new_slice = slice_module.Slice(self, category, name, timestamp,
                                   thread_timestamp=thread_timestamp,
                                   args=args)
    if duration == None:
      new_slice.did_not_finish = True
    else:
      new_slice.duration = duration
      new_slice.thread_duration = thread_duration
    self.PushSlice(new_slice)
    return new_slice

  def PushMarkSlice(self, category, name, timestamp, thread_timestamp,
        args=None):
    new_slice = slice_module.Slice(self, category, name, timestamp,
                                   thread_timestamp=thread_timestamp,
                                   args=args)
    self.PushSlice(new_slice)
    return new_slice

  def PushSlice(self, new_slice):
    self._newly_added_slices.append(new_slice)
    return new_slice

  def AutoCloseOpenSlices(self, max_timestamp, max_thread_timestamp):
    for s in self._newly_added_slices:
      if s.did_not_finish:
        s.duration = max_timestamp - s.start
        assert s.duration >= 0
        if s.thread_start != None:
          s.thread_duration = max_thread_timestamp - s.thread_start
          assert s.thread_duration >= 0
    self._open_slices = []

  def IsTimestampValidForBeginOrEnd(self, timestamp):
    if not len(self._open_slices):
      return True
    return timestamp >= self._open_slices[-1].start

  def FinalizeImport(self):
    self._BuildSliceSubRows()

  def _BuildSliceSubRows(self):
    """This function works by walking through slices by start time.

     The basic idea here is to insert each slice as deep into the subrow
     list as it can go such that every subslice is fully contained by its
     parent slice.

     Visually, if we start with this:
      0:  [    a       ]
      1:    [  b  ]
      2:    [c][d]

     To place this slice:
                   [e]
     We first check row 2's last item, [d]. [e] wont fit into [d] (they dont
     even intersect). So we go to row 1. That gives us [b], and [d] wont fit
     into that either. So, we go to row 0 and its last slice, [a]. That can
     completely contain [e], so that means we should add [e] as a subslice
     of [a]. That puts it on row 1, yielding:
      0:  [    a       ]
      1:    [  b  ][e]
      2:    [c][d]

     If we then get this slice:
                          [f]
     We do the same deepest-to-shallowest walk of the subrows trying to fit
     it. This time, it doesn't fit in any open slice. So, we simply append
     it to row 0 (a root slice):
      0:  [    a       ]  [f]
      1:    [  b  ][e]
    """
    def CompareSlices(s1, s2):
      if s1.start == s2.start:
        # Break ties by having the slice with the greatest
        # end timestamp come first.
        return cmp(s2.end, s1.end)
      return cmp(s1.start, s2.start)

    assert len(self._toplevel_slices) == 0
    assert len(self._all_slices) == 0
    if not len(self._newly_added_slices):
      return

    self._all_slices.extend(self._newly_added_slices)

    sorted_slices = sorted(self._newly_added_slices, cmp=CompareSlices)
    root_slice = sorted_slices[0]
    self._toplevel_slices.append(root_slice)
    for s in sorted_slices[1:]:
      if not self._AddSliceIfBounds(root_slice, s):
        root_slice = s
        self._toplevel_slices.append(root_slice)
    self._newly_added_slices = []


  def _AddSliceIfBounds(self, root, child):
    """Adds a child slice to a root slice its proper row.
    Return False if the child slice is not in the bounds
    of the root slice.

    Because we know that the start time of child is >= the start time
    of all other slices seen so far, we can just check the last slice
    of each row for bounding.
    """
    # The source trace data is in microseconds but we store it as milliseconds
    # in floating-point. Since we can't represent micros as millis perfectly,
    # two end=start+duration combos that should be the same will be slightly
    # different. Round back to micros to ensure equality below.
    child_end_micros = round(child.end * 1000)
    root_end_micros = round(root.end * 1000)
    if child.start >= root.start and child_end_micros <= root_end_micros:
      if len(root.sub_slices) > 0:
        if self._AddSliceIfBounds(root.sub_slices[-1], child):
          return True
      child.parent_slice = root
      root.AddSubSlice(child)
      return True
    return False
