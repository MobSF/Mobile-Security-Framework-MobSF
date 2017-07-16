# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


class TimelineBasedMetricException(Exception):
  """Exception that can be thrown from metrics that implements
     TimelineBasedMetric to indicate a problem arose when computing the metric.
     """


def _TimeRangesHasOverlap(iterable_time_ranges):
  """ Returns True if there is are overlapped ranges in time ranges.
  iterable_time_ranges: an iterable of time ranges. Each time range is a
  tuple (start time, end time).
  """
  # Sort the ranges by the start time
  sorted_time_ranges = sorted(iterable_time_ranges)
  last_range = sorted_time_ranges[0]
  for current_range in sorted_time_ranges[1:]:
    start_current_range = current_range[0]
    end_last_range = last_range[1]
    if start_current_range < end_last_range:
      return True
    last_range = current_range
  return False


def IsEventInInteractions(event, interaction_records):
  """ Return True if event is in any of the interaction records' time range.

  Args:
    event: an instance of telemetry.timeline.event.TimelineEvent.
    interaction_records: a list of interaction records, whereas each record is
      an instance of
      telemetry.web_perf.timeline_interaction_record.TimelineInteractionRecord.

  Returns:
    True if |event|'s start & end time is in any of the |interaction_records|'s
    time range.
  """
  return any(ir.start <= event.start and ir.end >= event.end for ir
             in interaction_records)


class TimelineBasedMetric(object):

  def __init__(self):
    """Computes metrics from a telemetry.timeline Model and a range

    """
    super(TimelineBasedMetric, self).__init__()

  def AddResults(self, model, renderer_thread, interaction_records, results):
    """Computes and adds metrics for the interaction_records' time ranges.

    The override of this method should compute results on the data **only**
    within the interaction_records' start and end time ranges.

    Args:
      model: An instance of telemetry.timeline.model.TimelineModel.
      interaction_records: A list of instances of TimelineInteractionRecord. If
        the override of this method doesn't support overlapped ranges, use
        VerifyNonOverlappedRecords to check that no records are overlapped.
      results: An instance of page.PageTestResults.

    """
    raise NotImplementedError()

  def AddWholeTraceResults(self, model, results):
    """Computes and adds metrics corresponding to the entire trace.

    Override this method to compute results that correspond to the whole trace.

    Args:
      model: An instance of telemetry.timeline.model.TimelineModel.
      results: An instance of page.PageTestResults.
    """
    pass

  def VerifyNonOverlappedRecords(self, interaction_records):
    """This raises exceptions if interaction_records contain overlapped ranges.
    """
    if _TimeRangesHasOverlap(((r.start, r.end) for r in interaction_records)):
      raise TimelineBasedMetricException(
          'This metric does not support interaction records with overlapped '
          'time range.')
