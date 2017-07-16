# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry import decorators
import telemetry.timeline.bounds as timeline_bounds

# Allows multiple duplicate interactions of the same type
REPEATABLE = 'repeatable'

FLAGS = [REPEATABLE]


class ThreadTimeRangeOverlappedException(Exception):
  """Exception that can be thrown when computing overlapped thread time range
  with other events.
  """

class NoThreadTimeDataException(ThreadTimeRangeOverlappedException):
  """Exception that can be thrown if there is not sufficient thread time data
  to compute the overlapped thread time range."""

def IsTimelineInteractionRecord(event_name):
  return event_name.startswith('Interaction.')

def _AssertFlagsAreValid(flags):
  assert isinstance(flags, list)
  for f in flags:
    if f not in FLAGS:
      raise AssertionError(
          'Unrecognized flag for a timeline interaction record: %s' % f)

def GetJavaScriptMarker(label, flags):
  """Computes the marker string of an interaction record.

  This marker string can be used with JavaScript API console.time()
  and console.timeEnd() to mark the beginning and end of the
  interaction record..

  Args:
    label: The label used to identify the interaction record.
    flags: the flags for the interaction record see FLAGS above.

  Returns:
    The interaction record marker string (e.g., Interaction.Label/flag1,flag2).

  Raises:
    AssertionError: If one or more of the flags is unrecognized.
  """
  _AssertFlagsAreValid(flags)
  marker = 'Interaction.%s' % label
  if flags:
    marker += '/%s' % (','.join(flags))
  return marker

class TimelineInteractionRecord(object):
  """Represents an interaction that took place during a timeline recording.

  As a page runs, typically a number of different (simulated) user interactions
  take place. For instance, a user might click a button in a mail app causing a
  popup to animate in. Then they might press another button that sends data to a
  server and simultaneously closes the popup without an animation. These are two
  interactions.

  From the point of view of the page, each interaction might have a different
  label: ClickComposeButton and SendEmail, for instance. From the point
  of view of the benchmarking harness, the labels aren't so interesting as what
  the performance expectations are for that interaction: was it loading
  resources from the network? was there an animation?

  Determining these things is hard to do, simply by observing the state given to
  a page from javascript. There are hints, for instance if network requests are
  sent, or if a CSS animation is pending. But this is by no means a complete
  story.

  Instead, we expect pages to mark up the timeline what they are doing, with
  label and flags indicating the semantics of that interaction. This
  is currently done by pushing markers into the console.time/timeEnd API: this
  for instance can be issued in JS:

     var str = 'Interaction.SendEmail';
     console.time(str);
     setTimeout(function() {
       console.timeEnd(str);
     }, 1000);

  When run with perf.measurements.timeline_based_measurement running, this will
  then cause a TimelineInteractionRecord to be created for this range with
  all metrics reported for the marked up 1000ms time-range.

  The valid interaction flags are:
     * repeatable: Allows other interactions to use the same label
  """

  def __init__(self, label, start, end, async_event=None, flags=None):
    assert label
    self._label = label
    self._start = start
    self._end = end
    self._async_event = async_event
    self._flags = flags if flags is not None else []
    _AssertFlagsAreValid(self._flags)

  @property
  def label(self):
    return self._label

  @property
  def start(self):
    return self._start

  @property
  def end(self):
    return self._end

  @property
  def repeatable(self):
    return REPEATABLE in self._flags

  # TODO(nednguyen): After crbug.com/367175 is marked fixed, we should be able
  # to get rid of perf.measurements.smooth_gesture_util and make this the only
  # constructor method for TimelineInteractionRecord.
  @classmethod
  def FromAsyncEvent(cls, async_event):
    """Construct an timeline_interaction_record from an async event.
    Args:
      async_event: An instance of
        telemetry.timeline.async_slices.AsyncSlice
    """
    assert async_event.start_thread == async_event.end_thread, (
        'Start thread of this record\'s async event is not the same as its '
        'end thread')
    m = re.match(r'Interaction\.(?P<label>.+?)(/(?P<flags>[^/]+))?$',
                 async_event.name)
    assert m, "Async event is not an interaction record."
    label = m.group('label')
    flags = m.group('flags').split(',') if m.group('flags') is not None else []
    return cls(label, async_event.start, async_event.end, async_event, flags)

  @decorators.Cache
  def GetBounds(self):
    bounds = timeline_bounds.Bounds()
    bounds.AddValue(self.start)
    bounds.AddValue(self.end)
    return bounds

  def GetOverlappedThreadTimeForSlice(self, timeline_slice):
    """Get the thread duration of timeline_slice that overlaps with this record.

    There are two cases :

    Case 1: timeline_slice runs in the same thread as the record.

                  |    [       timeline_slice         ]
      THREAD 1    |                  |                              |
                  |            record starts                    record ends

                      (relative order in thread time)

      As the thread timestamps in timeline_slice and record are consistent, we
      simply use them to compute the overlap.

    Case 2: timeline_slice runs in a different thread from the record's.

                  |
      THREAD 2    |    [       timeline_slice         ]
                  |

                  |
      THREAD 1    |               |                               |
                  |          record starts                      record ends

                      (relative order in wall-time)

      Unlike case 1, thread timestamps of a thread are measured by its
      thread-specific clock, which is inconsistent with that of the other
      thread, and thus can't be used to compute the overlapped thread duration.
      Hence, we use a heuristic to compute the overlap (see
      _GetOverlappedThreadTimeForSliceInDifferentThread for more details)

    Args:
      timeline_slice: An instance of telemetry.timeline.slice.Slice
    """
    if not self._async_event:
      raise ThreadTimeRangeOverlappedException(
          'This record was not constructed from async event')
    if not self._async_event.has_thread_timestamps:
      raise NoThreadTimeDataException(
          'This record\'s async_event does not contain thread time data. '
          'Event data: %s' % repr(self._async_event))
    if not timeline_slice.has_thread_timestamps:
      raise NoThreadTimeDataException(
          'slice does not contain thread time data')

    if timeline_slice.parent_thread == self._async_event.start_thread:
      return self._GetOverlappedThreadTimeForSliceInSameThread(
          timeline_slice)
    else:
      return self._GetOverlappedThreadTimeForSliceInDifferentThread(
          timeline_slice)

  def _GetOverlappedThreadTimeForSliceInSameThread(self, timeline_slice):
    return timeline_bounds.Bounds.GetOverlap(
        timeline_slice.thread_start, timeline_slice.thread_end,
        self._async_event.thread_start, self._async_event.thread_end)

  def _GetOverlappedThreadTimeForSliceInDifferentThread(self, timeline_slice):
    # In case timeline_slice's parent thread is not the parent thread of the
    # async slice that issues this record, we assume that events are descheduled
    # uniformly. The overlap duration in thread time is then computed by
    # multiplying the overlap wall-time duration of timeline_slice and the
    # record's async slice with their thread_duration/duration ratios.
    overlapped_walltime_duration = timeline_bounds.Bounds.GetOverlap(
        timeline_slice.start, timeline_slice.end,
        self.start, self.end)
    if timeline_slice.duration == 0 or self._async_event.duration == 0:
      return 0
    timeline_slice_scheduled_ratio = (
        timeline_slice.thread_duration / float(timeline_slice.duration))
    record_scheduled_ratio = (
        self._async_event.thread_duration / float(self._async_event.duration))
    return (overlapped_walltime_duration * timeline_slice_scheduled_ratio *
            record_scheduled_ratio)

  def __repr__(self):
    flags_str = ','.join(self._flags)
    return ('TimelineInteractionRecord(label=\'%s\', start=%f, end=%f,' +
            ' flags=%s, async_event=%s)') % (
                self.label,
                self.start,
                self.end,
                flags_str,
                repr(self._async_event))
