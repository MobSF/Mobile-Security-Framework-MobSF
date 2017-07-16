# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.util import perf_tests_helper
from telemetry.util import statistics
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.web_perf.metrics import rendering_stats
from telemetry.web_perf.metrics import timeline_based_metric


NOT_ENOUGH_FRAMES_MESSAGE = (
  'Not enough frames for smoothness metrics (at least two are required).\n'
  'Issues that have caused this in the past:\n'
  '- Browser bugs that prevents the page from redrawing\n'
  '- Bugs in the synthetic gesture code\n'
  '- Page and benchmark out of sync (e.g. clicked element was renamed)\n'
  '- Pages that render extremely slow\n'
  '- Pages that can\'t be scrolled')


class SmoothnessMetric(timeline_based_metric.TimelineBasedMetric):
  """Computes metrics that measure smoothness of animations over given ranges.

  Animations are typically considered smooth if the frame rates are close to
  60 frames per second (fps) and uniformly distributed over the sequence. To
  determine if a timeline range contains a smooth animation, we update the
  results object with several representative metrics:

    frame_times: A list of raw frame times
    mean_frame_time: The arithmetic mean of frame times
    percentage_smooth: Percentage of frames that were hitting 60 FPS.
    frame_time_discrepancy: The absolute discrepancy of frame timestamps
    mean_pixels_approximated: The mean percentage of pixels approximated
    queueing_durations: The queueing delay between compositor & main threads

  Note that if any of the interaction records provided to AddResults have less
  than 2 frames, we will return telemetry values with None values for each of
  the smoothness metrics. Similarly, older browsers without support for
  tracking the BeginMainFrame events will report a ListOfScalarValues with a
  None value for the queueing duration metric.
  """

  def __init__(self):
    super(SmoothnessMetric, self).__init__()

  def AddResults(self, model, renderer_thread, interaction_records, results):
    self.VerifyNonOverlappedRecords(interaction_records)
    renderer_process = renderer_thread.parent
    stats = rendering_stats.RenderingStats(
      renderer_process, model.browser_process, model.surface_flinger_process,
      model.gpu_process, [r.GetBounds() for r in interaction_records])
    has_surface_flinger_stats = model.surface_flinger_process is not None
    self._PopulateResultsFromStats(results, stats, has_surface_flinger_stats)

  def _PopulateResultsFromStats(self, results, stats,
                                has_surface_flinger_stats):
    page = results.current_page
    values = [
        self._ComputeQueueingDuration(page, stats),
        self._ComputeFrameTimeDiscrepancy(page, stats),
        self._ComputeMeanPixelsApproximated(page, stats),
        self._ComputeMeanPixelsCheckerboarded(page, stats)
    ]
    values += self._ComputeLatencyMetric(page, stats, 'input_event_latency',
                                         stats.input_event_latency)
    values += self._ComputeLatencyMetric(page, stats,
                                         'main_thread_scroll_latency',
                                         stats.main_thread_scroll_latency)
    values.append(self._ComputeFirstGestureScrollUpdateLatencies(page, stats))
    values += self._ComputeFrameTimeMetric(page, stats)
    if has_surface_flinger_stats:
      values += self._ComputeSurfaceFlingerMetric(page, stats)

    for v in values:
      results.AddValue(v)

  def _HasEnoughFrames(self, list_of_frame_timestamp_lists):
    """Whether we have collected at least two frames in every timestamp list."""
    return all(len(s) >= 2 for s in list_of_frame_timestamp_lists)

  @staticmethod
  def _GetNormalizedDeltas(data, refresh_period, min_normalized_delta=None):
    deltas = [t2 - t1 for t1, t2 in zip(data, data[1:])]
    if min_normalized_delta != None:
      deltas = [d for d in deltas
                if d / refresh_period >= min_normalized_delta]
    return (deltas, [delta / refresh_period for delta in deltas])

  @staticmethod
  def _JoinTimestampRanges(frame_timestamps):
    """Joins ranges of timestamps, adjusting timestamps to remove deltas
    between the start of a range and the end of the prior range.
    """
    timestamps = []
    for timestamp_range in frame_timestamps:
      if len(timestamps) == 0:
        timestamps.extend(timestamp_range)
      else:
        for i in range(1, len(timestamp_range)):
          timestamps.append(timestamps[-1] +
              timestamp_range[i] - timestamp_range[i-1])
    return timestamps

  def _ComputeSurfaceFlingerMetric(self, page, stats):
    jank_count = None
    avg_surface_fps = None
    max_frame_delay = None
    frame_lengths = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      timestamps = self._JoinTimestampRanges(stats.frame_timestamps)
      frame_count = len(timestamps)
      milliseconds = timestamps[-1] - timestamps[0]
      min_normalized_frame_length = 0.5

      frame_lengths, normalized_frame_lengths = \
          self._GetNormalizedDeltas(timestamps, stats.refresh_period,
                                    min_normalized_frame_length)
      if len(frame_lengths) < frame_count - 1:
        logging.warning('Skipping frame lengths that are too short.')
        frame_count = len(frame_lengths) + 1
      if len(frame_lengths) == 0:
        raise Exception('No valid frames lengths found.')
      _, normalized_changes = \
          self._GetNormalizedDeltas(frame_lengths, stats.refresh_period)
      jankiness = [max(0, round(change)) for change in normalized_changes]
      pause_threshold = 20
      jank_count = sum(1 for change in jankiness
                       if change > 0 and change < pause_threshold)
      avg_surface_fps = int(round((frame_count - 1) * 1000.0 / milliseconds))
      max_frame_delay = round(max(normalized_frame_lengths))
      frame_lengths = normalized_frame_lengths
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE

    return (
        scalar.ScalarValue(
            page, 'avg_surface_fps', 'fps', avg_surface_fps,
            description='Average frames per second as measured by the '
                        'platform\'s SurfaceFlinger.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.UP),
        scalar.ScalarValue(
            page, 'jank_count', 'janks', jank_count,
            description='Number of changes in frame rate as measured by the '
                        'platform\'s SurfaceFlinger.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.DOWN),
        scalar.ScalarValue(
            page, 'max_frame_delay', 'vsyncs', max_frame_delay,
            description='Largest frame time as measured by the platform\'s '
                        'SurfaceFlinger.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.DOWN),
        list_of_scalar_values.ListOfScalarValues(
            page, 'frame_lengths', 'vsyncs', frame_lengths,
            description='Frame time in vsyncs as measured by the platform\'s '
                        'SurfaceFlinger.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.DOWN)
    )

  def _ComputeLatencyMetric(self, page, stats, name, list_of_latency_lists):
    """Returns Values for the mean and discrepancy for given latency stats."""
    mean_latency = None
    latency_discrepancy = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      latency_list = perf_tests_helper.FlattenList(list_of_latency_lists)
      if len(latency_list) == 0:
        return ()
      mean_latency = round(statistics.ArithmeticMean(latency_list), 3)
      latency_discrepancy = (
          round(statistics.DurationsDiscrepancy(latency_list), 4))
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return (
      scalar.ScalarValue(
          page, 'mean_%s' % name, 'ms', mean_latency,
          description='Arithmetic mean of the raw %s values' % name,
          none_value_reason=none_value_reason,
          improvement_direction=improvement_direction.DOWN),
      scalar.ScalarValue(
          page, '%s_discrepancy' % name, 'ms', latency_discrepancy,
          description='Discrepancy of the raw %s values' % name,
          none_value_reason=none_value_reason,
          improvement_direction=improvement_direction.DOWN)
    )

  def _ComputeFirstGestureScrollUpdateLatencies(self, page, stats):
    """Returns a ListOfScalarValuesValues of gesture scroll update latencies.

    Returns a Value for the first gesture scroll update latency for each
    interaction record in |stats|.
    """
    none_value_reason = None
    first_gesture_scroll_update_latencies = [round(latencies[0], 4)
        for latencies in stats.gesture_scroll_update_latency
        if len(latencies)]
    if (not self._HasEnoughFrames(stats.frame_timestamps) or
        not first_gesture_scroll_update_latencies):
      first_gesture_scroll_update_latencies = None
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return list_of_scalar_values.ListOfScalarValues(
        page, 'first_gesture_scroll_update_latency', 'ms',
        first_gesture_scroll_update_latencies,
        description='First gesture scroll update latency measures the time it '
                    'takes to process the very first gesture scroll update '
                    'input event. The first scroll gesture can often get '
                    'delayed by work related to page loading.',
        none_value_reason=none_value_reason,
        improvement_direction=improvement_direction.DOWN)

  def _ComputeQueueingDuration(self, page, stats):
    """Returns a Value for the frame queueing durations."""
    queueing_durations = None
    none_value_reason = None
    if 'frame_queueing_durations' in stats.errors:
      none_value_reason = stats.errors['frame_queueing_durations']
    elif self._HasEnoughFrames(stats.frame_timestamps):
      queueing_durations = perf_tests_helper.FlattenList(
          stats.frame_queueing_durations)
      if len(queueing_durations) == 0:
        queueing_durations = None
        none_value_reason = 'No frame queueing durations recorded.'
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return list_of_scalar_values.ListOfScalarValues(
        page, 'queueing_durations', 'ms', queueing_durations,
        description='The frame queueing duration quantifies how out of sync '
                    'the compositor and renderer threads are. It is the amount '
                    'of wall time that elapses between a '
                    'ScheduledActionSendBeginMainFrame event in the compositor '
                    'thread and the corresponding BeginMainFrame event in the '
                    'main thread.',
        none_value_reason=none_value_reason,
        improvement_direction=improvement_direction.DOWN)

  def _ComputeFrameTimeMetric(self, page, stats):
    """Returns Values for the frame time metrics.

    This includes the raw and mean frame times, as well as the percentage of
    frames that were hitting 60 fps.
    """
    frame_times = None
    mean_frame_time = None
    percentage_smooth = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      frame_times = perf_tests_helper.FlattenList(stats.frame_times)
      mean_frame_time = round(statistics.ArithmeticMean(frame_times), 3)
      # We use 17ms as a somewhat looser threshold, instead of 1000.0/60.0.
      smooth_threshold = 17.0
      smooth_count = sum(1 for t in frame_times if t < smooth_threshold)
      percentage_smooth = float(smooth_count) / len(frame_times) * 100.0
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return (
        list_of_scalar_values.ListOfScalarValues(
            page, 'frame_times', 'ms', frame_times,
            description='List of raw frame times, helpful to understand the '
                        'other metrics.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.DOWN),
        scalar.ScalarValue(
            page, 'mean_frame_time', 'ms', mean_frame_time,
            description='Arithmetic mean of frame times.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.DOWN),
        scalar.ScalarValue(
            page, 'percentage_smooth', 'score', percentage_smooth,
            description='Percentage of frames that were hitting 60 fps.',
            none_value_reason=none_value_reason,
            improvement_direction=improvement_direction.UP)
    )

  def _ComputeFrameTimeDiscrepancy(self, page, stats):
    """Returns a Value for the absolute discrepancy of frame time stamps."""

    frame_discrepancy = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      frame_discrepancy = round(statistics.TimestampsDiscrepancy(
          stats.frame_timestamps), 4)
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return scalar.ScalarValue(
        page, 'frame_time_discrepancy', 'ms', frame_discrepancy,
        description='Absolute discrepancy of frame time stamps, where '
                    'discrepancy is a measure of irregularity. It quantifies '
                    'the worst jank. For a single pause, discrepancy '
                    'corresponds to the length of this pause in milliseconds. '
                    'Consecutive pauses increase the discrepancy. This metric '
                    'is important because even if the mean and 95th '
                    'percentile are good, one long pause in the middle of an '
                    'interaction is still bad.',
        none_value_reason=none_value_reason,
        improvement_direction=improvement_direction.DOWN)

  def _ComputeMeanPixelsApproximated(self, page, stats):
    """Add the mean percentage of pixels approximated.

    This looks at tiles which are missing or of low or non-ideal resolution.
    """
    mean_pixels_approximated = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      mean_pixels_approximated = round(statistics.ArithmeticMean(
          perf_tests_helper.FlattenList(
              stats.approximated_pixel_percentages)), 3)
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return scalar.ScalarValue(
        page, 'mean_pixels_approximated', 'percent', mean_pixels_approximated,
        description='Percentage of pixels that were approximated '
                    '(checkerboarding, low-resolution tiles, etc.).',
        none_value_reason=none_value_reason,
        improvement_direction=improvement_direction.DOWN)

  def _ComputeMeanPixelsCheckerboarded(self, page, stats):
    """Add the mean percentage of pixels checkerboarded.

    This looks at tiles which are only missing.
    It does not take into consideration tiles which are of low or
    non-ideal resolution.
    """
    mean_pixels_checkerboarded = None
    none_value_reason = None
    if self._HasEnoughFrames(stats.frame_timestamps):
      if rendering_stats.CHECKERBOARDED_PIXEL_ERROR in stats.errors:
        none_value_reason = stats.errors[
            rendering_stats.CHECKERBOARDED_PIXEL_ERROR]
      else:
        mean_pixels_checkerboarded = round(statistics.ArithmeticMean(
            perf_tests_helper.FlattenList(
                stats.checkerboarded_pixel_percentages)), 3)
    else:
      none_value_reason = NOT_ENOUGH_FRAMES_MESSAGE
    return scalar.ScalarValue(
        page, 'mean_pixels_checkerboarded', 'percent',
        mean_pixels_checkerboarded,
        description='Percentage of pixels that were checkerboarded.',
        none_value_reason=none_value_reason,
        improvement_direction=improvement_direction.DOWN)
