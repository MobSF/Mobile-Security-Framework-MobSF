# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.util import statistics
from telemetry.value import improvement_direction
from telemetry.value import scalar
from telemetry.web_perf.metrics import timeline_based_metric

import logging

class V8EventStat(object):

  def __init__(self, src_event_name, result_name, result_description):
    self.src_event_name = src_event_name
    self.result_name = result_name
    self.result_description = result_description
    self.thread_duration = 0.0
    self.thread_duration_inside_idle = 0.0
    self.idle_task_overrun_duration = 0.0
    self.max_thread_duration = 0.0
    self.count = 0

  @property
  def thread_duration_outside_idle(self):
    return self.thread_duration - self.thread_duration_inside_idle

  @property
  def percentage_thread_duration_during_idle(self):
    return statistics.DivideIfPossibleOrZero(
        100 * self.thread_duration_inside_idle, self.thread_duration)

class V8GCLatency(timeline_based_metric.TimelineBasedMetric):
  _RENDERER_MAIN_THREAD = 'CrRendererMain'
  _IDLE_TASK_PARENT = 'SingleThreadIdleTaskRunner::RunTask'

  def __init__(self):
    super(V8GCLatency, self).__init__()

  def AddResults(self, model, renderer_thread, interaction_records, results):
    self.VerifyNonOverlappedRecords(interaction_records)
    self._AddV8MetricsToResults(model, interaction_records, results)

  def _AddV8MetricsToResults(self, model,
                             interaction_records, results):
    self._AddV8EventStatsToResults(model, interaction_records, results)

  def _AddV8EventStatsToResults(self, model, interactions, results):
    v8_event_stats = [
        V8EventStat('V8.GCIncrementalMarking',
                    'v8_gc_incremental_marking',
                    'incremental marking steps'),
        V8EventStat('V8.GCScavenger',
                    'v8_gc_scavenger',
                    'scavenges'),
        V8EventStat('V8.GCCompactor',
                    'v8_gc_mark_compactor',
                    'mark-sweep-compactor'),
        V8EventStat('V8.GCFinalizeMC',
                    'v8_gc_finalize_incremental',
                    'finalization of incremental marking'),
        V8EventStat('V8.GCFinalizeMCReduceMemory',
                    'v8_gc_finalize_incremental_reduce_memory',
                    'finalization of incremental marking with memory reducer')]
    label = interactions[0].label
    name_to_v8_stat = {x.src_event_name : x for x in v8_event_stats}
    thread_time_not_available = False
    for event in model.IterAllSlices():
      if (not timeline_based_metric.IsEventInInteractions(event, interactions)
          or not event.name in name_to_v8_stat):
        continue
      event_stat = name_to_v8_stat[event.name]
      if event.thread_duration is None:
        thread_time_not_available = True
        event_duration = event.duration
      else:
        event_duration = event.thread_duration
      event_stat.thread_duration += event_duration
      event_stat.max_thread_duration = max(event_stat.max_thread_duration,
                                           event_duration)
      event_stat.count += 1

      parent_idle_task = self._ParentIdleTask(event)
      if parent_idle_task:
        allotted_idle_time = parent_idle_task.args['allotted_time_ms']
        idle_task_wall_overrun = 0
        if event.duration > allotted_idle_time:
          idle_task_wall_overrun = event.duration - allotted_idle_time
        # Don't count time over the deadline as being inside idle time.
        # Since the deadline should be relative to wall clock we compare
        # allotted_time_ms with wall duration instead of thread duration, and
        # then assume the thread duration was inside idle for the same
        # percentage of time.
        inside_idle = event_duration * statistics.DivideIfPossibleOrZero(
            event.duration - idle_task_wall_overrun, event.duration)
        event_stat.thread_duration_inside_idle += inside_idle
        event_stat.idle_task_overrun_duration += idle_task_wall_overrun

    if thread_time_not_available:
      logging.warning(
          'thread time is not available in trace data, switch to walltime')

    for v8_event_stat in v8_event_stats:
      results.AddValue(scalar.ScalarValue(
          results.current_page, v8_event_stat.result_name, 'ms',
          v8_event_stat.thread_duration,
          description=('Total thread duration spent in %s' %
                       v8_event_stat.result_description),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
      results.AddValue(scalar.ScalarValue(
          results.current_page, '%s_max' % v8_event_stat.result_name, 'ms',
          v8_event_stat.max_thread_duration,
          description=('Max thread duration spent in %s' %
                       v8_event_stat.result_description),
          tir_label=label))
      results.AddValue(scalar.ScalarValue(
          results.current_page, '%s_count' % v8_event_stat.result_name, 'count',
          v8_event_stat.count,
          description=('Number of %s' %
                       v8_event_stat.result_description),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
      average_thread_duration = statistics.DivideIfPossibleOrZero(
          v8_event_stat.thread_duration, v8_event_stat.count)
      results.AddValue(scalar.ScalarValue(
          results.current_page, '%s_average' % v8_event_stat.result_name, 'ms',
          average_thread_duration,
          description=('Average thread duration spent in %s' %
                       v8_event_stat.result_description),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
      results.AddValue(scalar.ScalarValue(results.current_page,
          '%s_outside_idle' % v8_event_stat.result_name, 'ms',
          v8_event_stat.thread_duration_outside_idle,
          description=(
              'Total thread duration spent in %s outside of idle tasks' %
              v8_event_stat.result_description),
          tir_label=label))
      results.AddValue(scalar.ScalarValue(results.current_page,
          '%s_idle_deadline_overrun' % v8_event_stat.result_name, 'ms',
          v8_event_stat.idle_task_overrun_duration,
          description=('Total idle task deadline overrun for %s idle tasks'
                       % v8_event_stat.result_description),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
      results.AddValue(scalar.ScalarValue(results.current_page,
          '%s_percentage_idle' % v8_event_stat.result_name, 'idle%',
          v8_event_stat.percentage_thread_duration_during_idle,
          description=('Percentage of %s spent in idle time' %
                       v8_event_stat.result_description),
          tir_label=label,
          improvement_direction=improvement_direction.UP))

    # Add total metrics.
    gc_total = sum(x.thread_duration for x in v8_event_stats)
    gc_total_outside_idle = sum(
        x.thread_duration_outside_idle for x in v8_event_stats)
    gc_total_idle_deadline_overrun = sum(
        x.idle_task_overrun_duration for x in v8_event_stats)
    gc_total_percentage_idle = statistics.DivideIfPossibleOrZero(
        100 * (gc_total - gc_total_outside_idle), gc_total)

    results.AddValue(scalar.ScalarValue(results.current_page,
        'v8_gc_total', 'ms', gc_total,
        description='Total thread duration of all garbage collection events',
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(results.current_page,
        'v8_gc_total_outside_idle', 'ms', gc_total_outside_idle,
        description=(
            'Total thread duration of all garbage collection events outside of '
            'idle tasks'),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(results.current_page,
        'v8_gc_total_idle_deadline_overrun', 'ms',
        gc_total_idle_deadline_overrun,
        description=(
            'Total idle task deadline overrun for all idle tasks garbage '
            'collection events'),
          tir_label=label,
          improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(results.current_page,
        'v8_gc_total_percentage_idle', 'idle%', gc_total_percentage_idle,
        description=(
            'Percentage of the thread duration of all garbage collection '
            'events spent inside of idle tasks'),
          tir_label=label,
          improvement_direction=improvement_direction.UP))

  def _ParentIdleTask(self, event):
    parent = event.parent_slice
    while parent:
      if parent.name == self._IDLE_TASK_PARENT:
        return parent
      parent = parent.parent_slice
    return None

