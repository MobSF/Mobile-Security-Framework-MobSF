# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.web_perf.metrics import timeline_based_metric


class _SingleEventMetric(timeline_based_metric.TimelineBasedMetric):
  """Reports directly durations of specific trace events that start during the
  user interaction.
  """

  def __init__(self, trace_event_name, metric_name, metric_description=None):
    super(_SingleEventMetric, self).__init__()
    self._TRACE_EVENT_NAME = trace_event_name
    self._metric_name = metric_name
    self._metric_description = metric_description

  def AddResults(self, model, renderer_thread, interactions, results):
    del model  # unused
    assert interactions
    self._AddResultsInternal(renderer_thread.parent.IterAllSlices(),
                             interactions, results)

  def _AddResultsInternal(self, events, interactions, results):
    events_found = []
    for event in events:
      if (event.name == self._TRACE_EVENT_NAME) and any(
              interaction.start <= event.start <= interaction.end
              for interaction in interactions):
        if event.has_thread_timestamps:
          events_found.append(event.thread_duration)
        else:
          events_found.append(event.duration)
    if not events_found:
      return
    results.AddValue(list_of_scalar_values.ListOfScalarValues(
      page=results.current_page,
      tir_label=interactions[0].label,
      name=self._metric_name,
      units='ms',
      values=events_found,
      description=self._metric_description,
      improvement_direction=improvement_direction.DOWN))
