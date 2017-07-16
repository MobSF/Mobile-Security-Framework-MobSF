# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

class TimelineEvent(object):
  """Represents a timeline event.

  thread_start, thread_duration and thread_end are the start time, duration
  and end time of this event as measured by the thread-specific CPU clock
  (ticking when the thread is actually scheduled). Thread time is optional
  on trace events and the corresponding attributes in TimelineEvent will be
  set to None (not 0) if not present. Users of this class need to properly
  handle this case.
  """
  def __init__(self, category, name, start, duration, thread_start=None,
               thread_duration=None, args=None):
    self.category = category
    self.name = name
    self.start = start
    self.duration = duration
    self.thread_start = thread_start
    self.thread_duration = thread_duration
    self.args = args

  @property
  def end(self):
    return self.start + self.duration

  @property
  def has_thread_timestamps(self):
    return self.thread_start is not None and self.thread_duration is not None

  @property
  def thread_end(self):
    """Thread-specific CPU time when this event ended.

    May be None if the trace event didn't have thread time data.
    """
    if self.thread_start == None or self.thread_duration == None:
      return None
    return self.thread_start + self.thread_duration

  def __repr__(self):
    if self.args:
      args_str = ', ' + repr(self.args)
    else:
      args_str = ''

    return ("TimelineEvent(name='%s', start=%f, duration=%s, " +
            "thread_start=%s, thread_duration=%s%s)") % (
                self.name,
                self.start,
                self.duration,
                self.thread_start,
                self.thread_duration,
                args_str)
