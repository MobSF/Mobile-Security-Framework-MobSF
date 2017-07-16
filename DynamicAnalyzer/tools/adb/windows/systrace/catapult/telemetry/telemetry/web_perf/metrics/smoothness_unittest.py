# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.results import page_test_results
from telemetry.page import page as page_module
from telemetry.web_perf.metrics import rendering_stats
from telemetry.web_perf.metrics import smoothness


class _MockRenderingStats(object):

  stats = ['refresh_period', 'frame_timestamps', 'frame_times', 'paint_times',
           'painted_pixel_counts', 'record_times',
           'recorded_pixel_counts', 'approximated_pixel_percentages',
           'checkerboarded_pixel_percentages', 'input_event_latency',
           'frame_queueing_durations', 'main_thread_scroll_latency',
           'gesture_scroll_update_latency']

  def __init__(self, **kwargs):
    self.input_event_latency = None  # to avoid pylint no-member error
    self.errors = {}
    for stat in self.stats:
      value = kwargs[stat] if stat in kwargs else None
      setattr(self, stat, value)


#pylint: disable=protected-access
class SmoothnessMetricUnitTest(unittest.TestCase):

  def setUp(self):
    self.metric = smoothness.SmoothnessMetric()
    self.page = page_module.Page('file://blank.html')
    self.good_timestamps = [[10, 20], [30, 40, 50]]
    self.not_enough_frames_timestamps = [[10], [20, 30, 40]]

  def testPopulateResultsFromStats(self):
    stats = _MockRenderingStats()
    for stat in _MockRenderingStats.stats:
      # Just set fake data for all of the relevant arrays of stats typically
      # found in a RenderingStats object.
      setattr(stats, stat, [[10, 20], [30, 40, 50]])
    results = page_test_results.PageTestResults()
    results.WillRunPage(self.page)
    self.metric._PopulateResultsFromStats(results, stats, False)
    current_page_run = results.current_page_run
    self.assertTrue(current_page_run.ok)
    expected_values_count = 12
    self.assertEquals(expected_values_count, len(current_page_run.values))

  def testHasEnoughFrames(self):
    # This list will pass since every sub-array has at least 2 frames.
    has_enough_frames = self.metric._HasEnoughFrames(self.good_timestamps)
    self.assertTrue(has_enough_frames)

  def testHasEnoughFramesWithNotEnoughFrames(self):
    # This list will fail since the first sub-array only has a single frame.
    has_enough_frames = self.metric._HasEnoughFrames(
        self.not_enough_frames_timestamps)
    self.assertFalse(has_enough_frames)

  def testComputeSurfaceFlingerMetricNoJank(self):
    stats = _MockRenderingStats(refresh_period=10,
                                frame_timestamps=[[10, 20], [130, 140, 150]],
                                frame_times=[[10], [10, 10]])
    avg_surface_fps, jank_count, max_frame_delay, frame_lengths = (
        self.metric._ComputeSurfaceFlingerMetric(self.page, stats))
    self.assertEquals([1, 1, 1], frame_lengths.values)
    self.assertEquals(1, max_frame_delay.value)
    self.assertEquals(0, jank_count.value)
    self.assertEquals(100, avg_surface_fps.value)

  def testComputeSurfaceFlingerMetricJank(self):
    stats = _MockRenderingStats(
        refresh_period=10,
        frame_timestamps=[[10, 20, 50], [130, 140, 150, 170, 180]],
        frame_times=[[10, 30], [10, 10, 20, 10]])
    avg_surface_fps, jank_count, max_frame_delay, frame_lengths = (
        self.metric._ComputeSurfaceFlingerMetric(self.page, stats))
    self.assertEquals([1, 3, 1, 1, 2, 1], frame_lengths.values)
    self.assertEquals(3, max_frame_delay.value)
    self.assertEquals(2, jank_count.value)
    self.assertEquals(67, avg_surface_fps.value)

  def testComputeFrameTimeMetricWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        refresh_period=10,
        frame_timestamps=self.not_enough_frames_timestamps,
        frame_times=[[10, 20], [30, 40, 50]])
    avg_surface_fps, jank_count, max_frame_delay, frame_lengths = (
        self.metric._ComputeSurfaceFlingerMetric(self.page, stats))
    self.assertEquals(None, avg_surface_fps.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      avg_surface_fps.none_value_reason)
    self.assertEquals(None, jank_count.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      jank_count.none_value_reason)
    self.assertEquals(None, max_frame_delay.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      max_frame_delay.none_value_reason)
    self.assertEquals(None, frame_lengths.values)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      frame_lengths.none_value_reason)

  def testComputeLatencyMetric(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               input_event_latency=[[10, 20], [30, 40, 50]])
    # pylint: disable=unbalanced-tuple-unpacking
    mean_value, discrepancy_value = self.metric._ComputeLatencyMetric(
        self.page, stats, 'input_event_latency', stats.input_event_latency)
    self.assertEquals(30, mean_value.value)
    self.assertEquals(60, discrepancy_value.value)

  def testComputeLatencyMetricWithMissingData(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               input_event_latency=[[], []])
    value = self.metric._ComputeLatencyMetric(
        self.page, stats, 'input_event_latency', stats.input_event_latency)
    self.assertEquals((), value)

  def testComputeLatencyMetricWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        input_event_latency=[[], []])
    # pylint: disable=unbalanced-tuple-unpacking
    mean_value, discrepancy_value = self.metric._ComputeLatencyMetric(
        self.page, stats, 'input_event_latency', stats.input_event_latency)
    self.assertEquals(None, mean_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      mean_value.none_value_reason)
    self.assertEquals(None, discrepancy_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      discrepancy_value.none_value_reason)

  def testComputeGestureScrollUpdateLatencies(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.good_timestamps,
        gesture_scroll_update_latency=[[10, 20], [30, 40, 50]])
    gesture_value = self.metric._ComputeFirstGestureScrollUpdateLatencies(
        self.page, stats)
    self.assertEquals([10, 30], gesture_value.values)

  def testComputeGestureScrollUpdateLatenciesWithMissingData(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.good_timestamps,
        gesture_scroll_update_latency=[[], []])
    value = self.metric._ComputeFirstGestureScrollUpdateLatencies(
        self.page, stats)
    self.assertEquals(None, value.values)

  def testComputeGestureScrollUpdateLatenciesWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        gesture_scroll_update_latency=[[10, 20], [30, 40, 50]])
    gesture_value = self.metric._ComputeFirstGestureScrollUpdateLatencies(
        self.page, stats)
    self.assertEquals(None, gesture_value.values)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      gesture_value.none_value_reason)

  def testComputeQueueingDuration(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               frame_queueing_durations=[[10, 20], [30, 40]])
    list_of_scalar_values = self.metric._ComputeQueueingDuration(self.page,
                                                                stats)
    self.assertEquals([10, 20, 30, 40], list_of_scalar_values.values)

  def testComputeQueueingDurationWithMissingData(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               frame_queueing_durations=[[], []])
    list_of_scalar_values = self.metric._ComputeQueueingDuration(
        self.page, stats)
    self.assertEquals(None, list_of_scalar_values.values)
    self.assertEquals('No frame queueing durations recorded.',
                      list_of_scalar_values.none_value_reason)

  def testComputeQueueingDurationWithMissingDataAndErrorValue(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               frame_queueing_durations=[[], []])
    stats.errors['frame_queueing_durations'] = (
        'Current chrome version does not support the queueing delay metric.')
    list_of_scalar_values = self.metric._ComputeQueueingDuration(
        self.page, stats)
    self.assertEquals(None, list_of_scalar_values.values)
    self.assertEquals(
        'Current chrome version does not support the queueing delay metric.',
        list_of_scalar_values.none_value_reason)

  def testComputeQueueingDurationWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        frame_queueing_durations=[[10, 20], [30, 40, 50]])
    list_of_scalar_values = self.metric._ComputeQueueingDuration(self.page,
                                                                stats)
    self.assertEquals(None, list_of_scalar_values.values)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      list_of_scalar_values.none_value_reason)

  def testComputeFrameTimeMetric(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps,
                               frame_times=[[10, 20], [30, 40, 50]])
    frame_times_value, mean_frame_time_value, percentage_smooth_value = (
        self.metric._ComputeFrameTimeMetric(self.page, stats))
    self.assertEquals([10, 20, 30, 40, 50], frame_times_value.values)
    self.assertEquals(30, mean_frame_time_value.value)
    self.assertEquals(20, percentage_smooth_value.value)

  def testComputeFrameTimeMetricWithNotEnoughFrames2(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        frame_times=[[10, 20], [30, 40, 50]])
    frame_times_value, mean_frame_time_value, percentage_smooth_value = (
        self.metric._ComputeFrameTimeMetric(self.page, stats))
    self.assertEquals(None, frame_times_value.values)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      frame_times_value.none_value_reason)
    self.assertEquals(None, mean_frame_time_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      mean_frame_time_value.none_value_reason)
    self.assertEquals(None, percentage_smooth_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      percentage_smooth_value.none_value_reason)

  def testComputeFrameTimeDiscrepancy(self):
    stats = _MockRenderingStats(frame_timestamps=self.good_timestamps)
    frame_time_discrepancy_value = self.metric._ComputeFrameTimeDiscrepancy(
        self.page, stats)
    self.assertEquals(10, frame_time_discrepancy_value.value)

  def testComputeFrameTimeDiscrepancyWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps)
    frame_time_discrepancy_value = self.metric._ComputeFrameTimeDiscrepancy(
        self.page, stats)
    self.assertEquals(None, frame_time_discrepancy_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      frame_time_discrepancy_value.none_value_reason)

  def testComputeMeanPixelsApproximated(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.good_timestamps,
        approximated_pixel_percentages=[[10, 20], [30, 40, 50]])
    mean_pixels_value = self.metric._ComputeMeanPixelsApproximated(
        self.page, stats)
    self.assertEquals(30, mean_pixels_value.value)

  def testComputeMeanPixelsApproximatedWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        approximated_pixel_percentages=[[10, 20], [30, 40, 50]])
    mean_pixels_value = self.metric._ComputeMeanPixelsApproximated(
        self.page, stats)
    self.assertEquals(None, mean_pixels_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      mean_pixels_value.none_value_reason)

  def testComputeMeanPixelsCheckerboarded(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.good_timestamps,
        checkerboarded_pixel_percentages=[[10, 20], [30, 40, 50]])
    mean_pixels_value = self.metric._ComputeMeanPixelsCheckerboarded(
        self.page, stats)
    self.assertEquals(30, mean_pixels_value.value)

  def testComputeMeanPixelsCheckerboardedWithNotEnoughFrames(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.not_enough_frames_timestamps,
        checkerboarded_pixel_percentages=[[10, 20], [30, 40, 50]])
    mean_pixels_value = self.metric._ComputeMeanPixelsCheckerboarded(
        self.page, stats)
    self.assertEquals(None, mean_pixels_value.value)
    self.assertEquals(smoothness.NOT_ENOUGH_FRAMES_MESSAGE,
                      mean_pixels_value.none_value_reason)

  def testComputeMeanPixelsCheckerboardedWithNoData(self):
    stats = _MockRenderingStats(
        frame_timestamps=self.good_timestamps,
        checkerboarded_pixel_percentages=None)
    stats.errors[rendering_stats.CHECKERBOARDED_PIXEL_ERROR] = 'test error'
    mean_pixels_value = self.metric._ComputeMeanPixelsCheckerboarded(
        self.page, stats)
    self.assertEquals(None, mean_pixels_value.value)
    self.assertEquals('test error',
                      mean_pixels_value.none_value_reason)
