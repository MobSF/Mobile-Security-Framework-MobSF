# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import copy

from telemetry.web_perf import timeline_interaction_record as tir_module


def GetAdjustedInteractionIfContainGesture(timeline, interaction_record):
  """ Returns a new interaction record if interaction_record contains geture
  whose time range that overlaps with interaction_record's range. If not,
  returns a clone of original interaction_record.
  The synthetic gesture controller inserts a trace marker to precisely
  demarcate when the gesture was running. We check for overlap, not inclusion,
  because gesture_actions can start/end slightly outside the telemetry markers
  on Windows. This problem is probably caused by a race condition between
  the browser and renderer process submitting the trace events for the
  markers.
  """
  # Only adjust the range for gestures.
  if not interaction_record.label.startswith('Gesture_'):
    return copy.copy(interaction_record)
  gesture_events = [
    ev for ev
    in timeline.IterAllAsyncSlicesOfName('SyntheticGestureController::running')
    if ev.parent_slice is None and
    ev.start <= interaction_record.end and
    ev.end >= interaction_record.start]
  if len(gesture_events) == 0:
    return copy.copy(interaction_record)
  if len(gesture_events) > 1:
    raise Exception('More than one possible synthetic gesture marker found in '
                    'interaction_record %s.' % interaction_record.label)
  return tir_module.TimelineInteractionRecord(
    interaction_record.label, gesture_events[0].start,
    gesture_events[0].end, gesture_events[0],
    interaction_record._flags)  # pylint: disable=protected-access
