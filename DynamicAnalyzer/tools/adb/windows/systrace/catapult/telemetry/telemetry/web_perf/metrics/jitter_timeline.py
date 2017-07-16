# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.web_perf.metrics import timeline_based_metric


JITTER_EVENT_NAME = 'jitter'


class JitterTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """JitterTimelineMetric reports jitter in composited layers.

  This jitter is due to the main thread attempting to fix the position of a
  scrolling composited layer. 'jitter-amount' is the metric added to the
  results.
  """

  def __init__(self):
    super(JitterTimelineMetric, self).__init__()

  @staticmethod
  def IsJitterEvent(event):
    return event.name == JITTER_EVENT_NAME

  def AddResults(self, model, renderer_thread, interactions, results):
    assert interactions

    jitter_events = []
    for event in model.IterAllEvents(
        event_predicate=self.IsJitterEvent):
      jitter_events.append(event)

    self._AddJitterResultsInternal(jitter_events, interactions, results)

  def _AddJitterResultsInternal(self, events, interactions, results):
    jitters = []
    for event in events:
      if timeline_based_metric.IsEventInInteractions(event, interactions):
        jitters.append(event.args['value'])
    if jitters:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page=results.current_page,
          tir_label=interactions[0].label,
          name='jitter-amount',
          units='score',
          values=jitters,
          description='Jitter each frame',
          improvement_direction=improvement_direction.DOWN))
