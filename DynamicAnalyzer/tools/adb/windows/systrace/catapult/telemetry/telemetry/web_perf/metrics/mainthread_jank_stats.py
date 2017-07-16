# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


# A top level slice of a main thread can cause the webapp to behave
# unresponsively if its thread duration is greater than or equals to
# USER_PERCEIVABLE_DELAY_THRESHOLD_MS. Human eyes can perceive delay at low as
# 100ms, but since we use thread time instead of wall-time, we reduce the
# threshold further to 50ms to make room for other OS's activities.
USER_PERCEIVABLE_DELAY_THRESHOLD_MS = 50


class _MainthreadJankStat(object):
  """A small wrapper class for storing mainthread jank stats computed for
  single record.
  """

  def __init__(self):
    self.sum_big_top_slices_thread_time = 0
    self.biggest_top_slice_thread_time = 0


def _ComputeMainthreadJankStatsForRecord(renderer_thread, record):
  """Computes the mainthread jank stat on a record range.

  Returns:
      An instance of _MainthreadJankStat, which has:

      sum_big_top_slices_thread_time is the total thread duration of all top
      slices whose thread time ranges overlapped with (thread_start, thread_end)
      and the overlapped thread duration is greater than or equal
      USER_PERCEIVABLE_DELAY_THRESHOLD_MS.

      biggest_top_slice_thread_time is the biggest thread duration of all
      top slices whose thread time ranges overlapped with
      (thread_start, thread_end).

      Note: thread duration of each slices is computed using overlapped range
      with (thread_start, thread_end).
  """
  stat = _MainthreadJankStat()
  for s in renderer_thread.toplevel_slices:
    jank_thread_duration = record.GetOverlappedThreadTimeForSlice(s)
    stat.biggest_top_slice_thread_time = max(
        stat.biggest_top_slice_thread_time, jank_thread_duration)
    if jank_thread_duration >= USER_PERCEIVABLE_DELAY_THRESHOLD_MS:
      stat.sum_big_top_slices_thread_time += jank_thread_duration
  return stat


class MainthreadJankStats(object):
  """
    Utility class for extracting main thread jank statistics from the timeline
    (or other loggin facilities), and providing them in a common format to
    classes that compute benchmark metrics from this data.

      total_big_jank_thread_time is the total thread duration of all top
      slices whose thread time ranges overlapped with any thread time ranges of
      the records and the overlapped thread duration is greater than or equal
      USER_PERCEIVABLE_DELAY_THRESHOLD_MS.

      biggest_jank_thread_time is the biggest thread duration of all
      top slices whose thread time ranges overlapped with any of records' thread
      time ranges.
  """

  def __init__(self, renderer_thread, interaction_records):
    self._renderer_thread = renderer_thread
    self._interaction_records = interaction_records
    self._total_big_jank_thread_time = 0
    self._biggest_jank_thread_time = 0
    self._ComputeMainthreadJankStats()

  @property
  def total_big_jank_thread_time(self):
    return self._total_big_jank_thread_time

  @property
  def biggest_jank_thread_time(self):
    return self._biggest_jank_thread_time

  def _ComputeMainthreadJankStats(self):
    for record in self._interaction_records:
      record_jank_stat = _ComputeMainthreadJankStatsForRecord(
          self._renderer_thread, record)
      self._total_big_jank_thread_time += (
          record_jank_stat.sum_big_top_slices_thread_time)
      self._biggest_jank_thread_time = (
          max(self._biggest_jank_thread_time,
              record_jank_stat.biggest_top_slice_thread_time))
