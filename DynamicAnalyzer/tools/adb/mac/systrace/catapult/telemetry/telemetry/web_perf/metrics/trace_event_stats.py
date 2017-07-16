# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections

from telemetry.value import list_of_scalar_values
from telemetry.value import scalar


class TraceEventStatsInput(object):
  """Input for the TraceEventStats.
  Using this object with TraceEventStats will include two metrics, one with a
  list of times of the given event, and one for the count of the events, named
  `metric_name + '-count'`.
  Args:
    event_category: The category of the event to track.
    event_name: The name of the event to track.
    metric_name: The name of the metric name, which accumulates all of the
                 times of the events.
    metric_description: Description of the metric.
    units: Units for the metric.
    process_name: (optional) The name of the process to inspect for the trace
                  events. Defaults to 'Renderer'.
  """
  def __init__(self, event_category, event_name, metric_name,
               metric_description, units, process_name='Renderer'):
    self.event_category = event_category
    self.event_name = event_name
    self.metric_name = metric_name
    self.metric_description = metric_description
    self.units = units
    self.process_name = process_name
    self.event_id = TraceEventStatsInput.GetEventId(event_category, event_name)
    assert process_name is not None

  @staticmethod
  def GetEventId(event_category, event_name):
    return event_category + '^SERIALIZE-DELIM^' + event_name

class TraceEventStats(object):
  """Reports durations and counts of given trace events.
  """

  def __init__(self, trace_event_aggregator_inputs=None):
    self._inputs_by_process_name = collections.defaultdict(list)
    self._metrics = set()
    self._IndexNewInputs(trace_event_aggregator_inputs)

  def AddInput(self, trace_event_aggregator_input):
    self._IndexNewInputs([trace_event_aggregator_input])

  def _IndexNewInputs(self, input_list):
    if not input_list:
      return
    for input_obj in input_list:
      name = input_obj.metric_name
      # We check here to make sure we don't have a duplicate metric
      assert name not in self._metrics
      assert (name + '-count') not in self._metrics
      self._metrics.add(name)
      self._metrics.add(name + '-count')

      self._inputs_by_process_name[input_obj.process_name].append(input_obj)

  @staticmethod
  def ThreadDurationIfPresent(event):
    if event.thread_duration:
      return event.thread_duration
    else:
      return event.duration

  def AddResults(self, model, renderer_process, interactions, results):
    del renderer_process  # unused
    assert interactions
    for p in model.GetAllProcesses():
      if p.name not in self._inputs_by_process_name:
        continue

      inputs = self._inputs_by_process_name[p.name]
      input_ids = {i.event_id for i in inputs}

      def InputIdPredicate(e, ids):
        return TraceEventStatsInput.GetEventId(e.category, e.name) in ids

      self._AddResultsInternal(
          p.IterAllEvents(
              recursive=True,
              event_type_predicate=lambda t: True,
              event_predicate=
                  lambda e, ids=input_ids: InputIdPredicate(e, ids)),
          interactions,
          results,
          inputs)

  # We assume events have been filtered already. 'events' is an iterator.
  def _AddResultsInternal(self, events, interactions, results, inputs):
    times_by_event_id = collections.defaultdict(list)

    for event in events:
      if not any(interaction.start <= event.start <= interaction.end
                 for interaction in interactions):
        continue
      event_id = TraceEventStatsInput.GetEventId(event.category, event.name)
      times_by_event_id[event_id].append(self.ThreadDurationIfPresent(event))

    if not times_by_event_id:
      return

    inputs_by_event_id = dict([[input_obj.event_id, input_obj]
                                for input_obj in inputs])

    for (event_name, times) in times_by_event_id.iteritems():
      input_for_event = inputs_by_event_id[event_name]
      name = input_for_event.metric_name
      results.AddValue(scalar.ScalarValue(
        page=results.current_page,
        tir_label=interactions[0].label,
        name=name + '-count',
        units='count',
        value=len(times),
        description='The number of times ' + name + ' was recorded.'))
      if len(times) == 0:
        continue
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
        page=results.current_page,
        tir_label=interactions[0].label,
        name=name,
        units=input_for_event.units,
        values=times,
        description=input_for_event.metric_description))
