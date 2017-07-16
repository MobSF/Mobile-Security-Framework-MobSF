# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.value import improvement_direction
from telemetry.web_perf.metrics import timeline_based_metric
from telemetry.web_perf.metrics import webrtc_rendering_stats as stats_helper

WEB_MEDIA_PLAYER_MS_EVENT = 'WebMediaPlayerMS::UpdateCurrentFrame'


class WebRtcRenderingTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """WebrtcRenderingTimelineMetric calculates metric for WebMediaPlayerMS.

  The following metrics are added to the results:
    WebRTCRendering_drift_time us
    WebRTCRendering_percent_badly_out_of_sync %
    WebRTCRendering_percent_out_of_sync %
    WebRTCRendering_fps FPS
    WebRTCRendering_smoothness_score %
    WebRTCRendering_freezing_score %
    WebRTCRendering_rendering_length_error %
  """

  def __init__(self):
    super(WebRtcRenderingTimelineMetric, self).__init__()

  @staticmethod
  def IsMediaPlayerMSEvent(event):
    """Verify that the event is a webmediaplayerMS event."""
    return event.name == WEB_MEDIA_PLAYER_MS_EVENT

  def AddResults(self, model, renderer_thread, interactions, results):
    """Adding metrics to the results."""
    assert interactions
    found_events = []
    for event in renderer_thread.parent.IterAllEvents(
        event_predicate=self.IsMediaPlayerMSEvent):
      if timeline_based_metric.IsEventInInteractions(event, interactions):
        found_events.append(event)
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats(found_events)
    rendering_stats = stats_parser.GetTimeStats()
    none_reason = None
    if not rendering_stats:
      # Create a TimeStats object whose members have None values.
      rendering_stats = stats_helper.TimeStats()
      none_reason = 'No WebMediaPlayerMS::UpdateCurrentFrame event found'
    elif rendering_stats.invalid_data:
      # Throw away the data.
      rendering_stats = stats_helper.TimeStats()
      none_reason = 'WebMediaPlayerMS data is corrupted.'
    results.AddValue(list_of_scalar_values.ListOfScalarValues(
        results.current_page,
        'WebRTCRendering_drift_time',
        'us',
        rendering_stats.drift_time,
        important=True,
        description='Drift time for a rendered frame',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.DOWN,
        none_value_reason=none_reason))

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_percent_badly_out_of_sync',
        '%',
        rendering_stats.percent_badly_out_of_sync,
        important=True,
        description='Percentage of frame which drifted more than 2 VSYNC',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.DOWN,
        none_value_reason=none_reason))

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_percent_out_of_sync',
        '%',
        rendering_stats.percent_out_of_sync,
        important=True,
        description='Percentage of frame which drifted more than 1 VSYNC',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.DOWN,
        none_value_reason=none_reason))

    # I removed the frame distribution list from stats as it is not a metric,
    # rather it is the underlying data. Also there is no sense of improvement
    # direction for frame distribution.

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_fps',
        'fps',
        rendering_stats.fps,
        important=True,
        description='Calculated Frame Rate of video rendering',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.UP,
        none_value_reason=none_reason))

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_smoothness_score',
        '%',
        rendering_stats.smoothness_score,
        important=True,
        description='Smoothness score of rendering',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.UP,
        none_value_reason=none_reason))

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_freezing_score',
        '%',
        rendering_stats.freezing_score,
        important=True,
        description='Freezing score of rendering',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.UP,
        none_value_reason=none_reason))

    results.AddValue(scalar.ScalarValue(
        results.current_page,
        'WebRTCRendering_rendering_length_error',
        '%',
        rendering_stats.rendering_length_error,
        important=True,
        description='Rendering length error rate',
        tir_label=interactions[0].label,
        improvement_direction=improvement_direction.DOWN,
        none_value_reason=none_reason))
