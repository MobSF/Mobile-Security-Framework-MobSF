# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from telemetry import story
from telemetry.internal.results import page_test_results
from telemetry.page import page as page_module
from telemetry.timeline import async_slice
from telemetry.timeline import model as model_module
from telemetry.value import improvement_direction
from telemetry.value import scalar
from telemetry.web_perf.metrics import timeline_based_metric
from telemetry.web_perf import timeline_based_measurement as tbm_module


class FakeSmoothMetric(timeline_based_metric.TimelineBasedMetric):

  def AddResults(self, model, renderer_thread, interaction_records, results):
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'FakeSmoothMetric', 'ms', 1,
        improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'SmoothMetricRecords', 'count',
        len(interaction_records),
        improvement_direction=improvement_direction.DOWN))


class FakeLoadingMetric(timeline_based_metric.TimelineBasedMetric):

  def AddResults(self, model, renderer_thread, interaction_records, results):
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'FakeLoadingMetric', 'ms', 2,
        improvement_direction=improvement_direction.DOWN))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'LoadingMetricRecords', 'count',
        len(interaction_records),
        improvement_direction=improvement_direction.DOWN))


class FakeStartupMetric(timeline_based_metric.TimelineBasedMetric):

  def AddResults(self, model, renderer_thread, interaction_records, results):
    pass

  def AddWholeTraceResults(self, model, results):
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'FakeStartupMetric', 'ms', 3,
        improvement_direction=improvement_direction.DOWN))


class TimelineBasedMetricTestData(object):

  def __init__(self, options):
    self._model = model_module.TimelineModel()
    renderer_process = self._model.GetOrCreateProcess(1)
    self._renderer_thread = renderer_process.GetOrCreateThread(2)
    self._renderer_thread.name = 'CrRendererMain'
    self._foo_thread = renderer_process.GetOrCreateThread(3)
    self._foo_thread.name = 'CrFoo'

    self._results_wrapper = tbm_module._TBMResultWrapper()
    self._results = page_test_results.PageTestResults()
    self._story_set = None
    self._threads_to_records_map = None
    self._tbm_options = options

  @property
  def model(self):
    return self._model

  @property
  def renderer_thread(self):
    return self._renderer_thread

  @property
  def foo_thread(self):
    return self._foo_thread

  @property
  def threads_to_records_map(self):
    return self._threads_to_records_map

  @property
  def results(self):
    return self._results

  def AddInteraction(self, thread, marker='', ts=0, duration=5):
    assert thread in (self._renderer_thread, self._foo_thread)
    thread.async_slices.append(async_slice.AsyncSlice(
        'category', marker, timestamp=ts, duration=duration,
        start_thread=self._renderer_thread, end_thread=self._renderer_thread,
        thread_start=ts, thread_duration=duration))

  def FinalizeImport(self):
    self._model.FinalizeImport()
    self._threads_to_records_map = (
      tbm_module._GetRendererThreadsToInteractionRecordsMap(self._model))
    self._story_set = story.StorySet(base_dir=os.path.dirname(__file__))
    self._story_set.AddStory(page_module.Page(
        'http://www.bar.com/', self._story_set, self._story_set.base_dir))
    self._results.WillRunPage(self._story_set.stories[0])

  def AddResults(self):
    all_metrics = self._tbm_options.GetLegacyTimelineBasedMetrics()

    for thread, records in self._threads_to_records_map.iteritems():
      # pylint: disable=protected-access
      metric = tbm_module._TimelineBasedMetrics(
          self._model, thread, records, self._results_wrapper, all_metrics)
      metric.AddResults(self._results)

    for metric in all_metrics:
      metric.AddWholeTraceResults(self._model, self._results)

    self._results.DidRunPage(self._story_set.stories[0])


class TimelineBasedMetricsTests(unittest.TestCase):

  def setUp(self):
    self.actual_get_all_tbm_metrics = (
        tbm_module._GetAllLegacyTimelineBasedMetrics)
    self._options = tbm_module.Options()
    self._options.SetLegacyTimelineBasedMetrics(
        (FakeSmoothMetric(), FakeLoadingMetric(), FakeStartupMetric()))

  def tearDown(self):
    tbm_module._GetAllLegacyTimelineBasedMetrics = (
        self.actual_get_all_tbm_metrics)

  def testGetRendererThreadsToInteractionRecordsMap(self):
    d = TimelineBasedMetricTestData(self._options)
    # Insert 2 interaction records to renderer_thread and 1 to foo_thread
    d.AddInteraction(d.renderer_thread, ts=0, duration=20,
                     marker='Interaction.LogicalName1')
    d.AddInteraction(d.renderer_thread, ts=25, duration=5,
                     marker='Interaction.LogicalName2')
    d.AddInteraction(d.foo_thread, ts=50, duration=15,
                     marker='Interaction.LogicalName3')
    d.FinalizeImport()

    self.assertEquals(2, len(d.threads_to_records_map))

    # Assert the 2 interaction records of renderer_thread are in the map.
    self.assertIn(d.renderer_thread, d.threads_to_records_map)
    interactions = d.threads_to_records_map[d.renderer_thread]
    self.assertEquals(2, len(interactions))
    self.assertEquals(0, interactions[0].start)
    self.assertEquals(20, interactions[0].end)

    self.assertEquals(25, interactions[1].start)
    self.assertEquals(30, interactions[1].end)

    # Assert the 1 interaction records of foo_thread is in the map.
    self.assertIn(d.foo_thread, d.threads_to_records_map)
    interactions = d.threads_to_records_map[d.foo_thread]
    self.assertEquals(1, len(interactions))
    self.assertEquals(50, interactions[0].start)
    self.assertEquals(65, interactions[0].end)

  def testAddResults(self):
    d = TimelineBasedMetricTestData(self._options)
    d.AddInteraction(d.renderer_thread, ts=0, duration=20,
                     marker='Interaction.LogicalName1')
    d.AddInteraction(d.foo_thread, ts=25, duration=5,
                     marker='Interaction.LogicalName2')
    d.FinalizeImport()
    d.AddResults()
    self.assertEquals(1, len(d.results.FindAllPageSpecificValuesFromIRNamed(
        'LogicalName1', 'FakeSmoothMetric')))
    self.assertEquals(1, len(d.results.FindAllPageSpecificValuesFromIRNamed(
        'LogicalName2', 'FakeLoadingMetric')))
    self.assertEquals(1, len(d.results.FindAllPageSpecificValuesNamed(
        'FakeStartupMetric')))

  def testDuplicateInteractionsInDifferentThreads(self):
    d = TimelineBasedMetricTestData(self._options)
    d.AddInteraction(d.renderer_thread, ts=10, duration=5,
                     marker='Interaction.LogicalName/repeatable')
    d.AddInteraction(d.foo_thread, ts=20, duration=5,
                     marker='Interaction.LogicalName')
    self.assertRaises(tbm_module.InvalidInteractions, d.FinalizeImport)

  def testDuplicateRepeatableInteractionsInDifferentThreads(self):
    d = TimelineBasedMetricTestData(self._options)
    d.AddInteraction(d.renderer_thread, ts=10, duration=5,
                     marker='Interaction.LogicalName/repeatable')
    d.AddInteraction(d.foo_thread, ts=20, duration=5,
                     marker='Interaction.LogicalName/repeatable')
    self.assertRaises(tbm_module.InvalidInteractions, d.FinalizeImport)

  def testDuplicateUnrepeatableInteractionsInSameThread(self):
    d = TimelineBasedMetricTestData(self._options)
    d.AddInteraction(d.renderer_thread, ts=10, duration=5,
                     marker='Interaction.LogicalName')
    d.AddInteraction(d.renderer_thread, ts=20, duration=5,
                     marker='Interaction.LogicalName')
    d.FinalizeImport()
    self.assertRaises(tbm_module.InvalidInteractions, d.AddResults)

  def testDuplicateRepeatableInteractions(self):
    d = TimelineBasedMetricTestData(self._options)
    d.AddInteraction(d.renderer_thread, ts=10, duration=5,
                     marker='Interaction.LogicalName/repeatable')
    d.AddInteraction(d.renderer_thread, ts=20, duration=5,
                     marker='Interaction.LogicalName/repeatable')
    d.FinalizeImport()
    d.AddResults()
    self.assertEquals(1, len(d.results.pages_that_succeeded))
