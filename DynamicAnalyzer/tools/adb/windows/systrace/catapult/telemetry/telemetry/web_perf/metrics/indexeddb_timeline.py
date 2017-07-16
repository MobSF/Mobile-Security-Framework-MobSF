# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


from telemetry.web_perf.metrics import timeline_based_metric
from telemetry.web_perf.metrics.trace_event_stats import TraceEventStats
from telemetry.web_perf.metrics.trace_event_stats import TraceEventStatsInput


class IndexedDBTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """Metrics for IndexedDB operations.
  """

  def __init__(self):
    super(IndexedDBTimelineMetric, self).__init__()
    self._stats = TraceEventStats()

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBDatabase::GetOperation',
      metric_name='idb-gets',
      metric_description='The duration of all "get" ops in IndexedDB',
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBDatabase::PutOperation',
      metric_name='idb-puts',
      metric_description='The duration of all "put" ops in IndexedDB',
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBFactoryImpl::Open',
      metric_name='idb-opens',
      metric_description='The duration of all "open" ops in IndexedDB',
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBTransaction::Commit',
      metric_name='idb-transaction-commits',
      metric_description=('The duration of all "commit" ops of ' +
                               'transactions in IndexedDB.'),
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBFactoryImpl::DeleteDatabase',
      metric_name='idb-database-deletes',
      metric_description=('The duration of all "delete" ops of ' +
                               'IndexedDB databases.'),
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBDatabase::OpenCursorOperation',
      metric_name='idb-cursor-opens',
      metric_description=('The duration of all "open" ops of ' +
                               'IndexedDB cursors.'),
      units='ms',
      process_name='Browser'))

    self._stats.AddInput(TraceEventStatsInput(
      event_category='IndexedDB',
      event_name='IndexedDBCursor::CursorIterationOperation',
      metric_name='idb-cursor-iterations',
      metric_description=('The duration of all "iteration" ops of ' +
                               'IndexedDB cursors.'),
      units='ms',
      process_name='Browser'))

  def AddResults(self, model, renderer_process, interactions, results):
    self._stats.AddResults(model, renderer_process, interactions, results)
