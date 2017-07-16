# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.web_perf.metrics import webrtc_rendering_stats as stats_helper


class FakeEvent(object):
  """Fake event class to mock rendering events."""

  def __init__(self, **kwargs):
    """Initializer for the fake WebMediaPlayerMS::UpdateCurrentFrame events.

    The WebMediaPlayerMsRenderingStats only cares about actual render begin,
    actual render end, ideal render instant and serial fields of the events.
    So we only define these four fields here in this fake event class.
    This method is written so as to take whatever valid parameters from the
    event definition. It can also be used to craft incomplete events.

    Args:
      kwargs::= dict('actual_begin', 'actual_end', 'ideal_instant', 'serial').
    """
    self.args = {}
    name_map = {
        'Actual Render Begin': 'actual_begin',
        'Actual Render End': 'actual_end',
        'Ideal Render Instant': 'ideal_instant',
        'Serial': 'serial'}
    for internal_name, external_name in name_map.iteritems():
      if external_name in kwargs:
        self.args[internal_name] = kwargs[external_name]


class WebMediaPlayerMsRenderingStatsTest(unittest.TestCase):

  def setUp(self):
    # A local stream id always has an even number.
    # A remote stream id always has an odd number.
    self.local_stream = 136390988
    self.remote_stream = 118626165

  def testInitialization(self):
    event_local_stream = FakeEvent(actual_begin=1655987203306,
        actual_end=1655987219972, ideal_instant=1655987154324,
        serial=self.local_stream)

    event_remote_stream = FakeEvent(actual_begin=1655987203306,
        actual_end=1655987219972, ideal_instant=1655987167999,
        serial=self.remote_stream)

    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats(
        [event_local_stream, event_remote_stream])

    self.assertEqual(2, len(stats_parser.stream_to_events))

    self.assertEqual(event_local_stream.args,
        stats_parser.stream_to_events[self.local_stream][0].args)

    self.assertEqual(event_remote_stream.args,
        stats_parser.stream_to_events[self.remote_stream][0].args)

  def testInvalidEvents(self):
    event_missing_serial = FakeEvent(actual_begin=1655987244074,
        actual_end=1655987260740, ideal_instant=1655987204839)

    event_missing_actual_begin = FakeEvent(actual_end=1655987260740,
        ideal_instant=1655987217999, serial=self.local_stream)

    event_missing_actual_end = FakeEvent(actual_end=1655987260740,
        ideal_instant=1655987217999, serial=self.remote_stream)

    event_missing_ideal_instant = FakeEvent(actual_begin=1655987260740,
        actual_end=1655987277406, serial=self.remote_stream)

    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats(
        [event_missing_serial, event_missing_actual_begin,
         event_missing_actual_end, event_missing_ideal_instant])

    self.assertEqual(0, len(stats_parser.stream_to_events))

  def _GetFakeEvents(self):
    fake_events = [
        FakeEvent(actual_begin=1663780195583, actual_end=1663780212249,
            ideal_instant=1663780179998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780212249, actual_end=1663780228915,
            ideal_instant=1663780179998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780228915, actual_end=1663780245581,
            ideal_instant=1663780197998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780245581, actual_end=1663780262247,
            ideal_instant=1663780215998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780262247, actual_end=1663780278913,
            ideal_instant=1663780215998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780278913, actual_end=1663780295579,
            ideal_instant=1663780254998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780295579, actual_end=1663780312245,
            ideal_instant=1663780254998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780312245, actual_end=1663780328911,
           ideal_instant=1663780254998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780328911, actual_end=1663780345577,
           ideal_instant=1663780310998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780345577, actual_end=1663780362243,
            ideal_instant=1663780310998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780362243, actual_end=1663780378909,
            ideal_instant=1663780310998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780378909, actual_end=1663780395575,
            ideal_instant=1663780361998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780395575, actual_end=1663780412241,
            ideal_instant=1663780361998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780412241, actual_end=1663780428907,
            ideal_instant=1663780361998, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780428907, actual_end=1663780445573,
            ideal_instant=1663780412998, serial=self.remote_stream)]

    return fake_events

  def _GetCorruptEvents(self):
    # The events below are corrupt data because the |ideal_instant|
    # parameter is zero, which makes all computation meaningless.
    # Indeed, the ideal_instant (aka Ideal Render Instant) indicates
    # when the frame should be rendered ideally.
    corrupt_events = [
        FakeEvent(actual_begin=1663780195583, actual_end=1663780212249,
            ideal_instant=0, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780212249, actual_end=1663780228915,
            ideal_instant=0, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780228915, actual_end=1663780245581,
            ideal_instant=0, serial=self.remote_stream),
        FakeEvent(actual_begin=1663780245581, actual_end=1663780262247,
            ideal_instant=0, serial=self.remote_stream)]
    return corrupt_events

  def testGetCadence(self):
    fake_events = self._GetFakeEvents()
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats(fake_events)
    # The events defined in _GetFakeEvents above show that the first source
    # framee of ideal_instant=1663780179998 is rendered twice, then
    # the second source frame of ideal_instant=1663780197998 is rendered once
    # the third source frame of  ideal_instant=1663780215998 is rendered twice
    # and so on. The expected cadence will therefore be [2 1 2 etc..]
    expected_cadence = [2, 1, 2, 3, 3, 3, 1]
    self.assertEqual(expected_cadence, stats_parser._GetCadence(fake_events))

  def testGetSourceToOutputDistribution(self):
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    cadence = [2, 1, 2, 3, 3, 3, 1]
    expected_frame_distribution = {1: 2, 2: 2, 3: 3}
    self.assertEqual(expected_frame_distribution,
        stats_parser._GetSourceToOutputDistribution(cadence))

  def testGetFpsFromCadence(self):
    frame_distribution = {1: 2, 2: 2, 3: 3}
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    expected_frame_rate = 28.0
    self.assertEqual(expected_frame_rate,
        stats_parser._GetFpsFromCadence(frame_distribution))

  def testGetFrozenFramesReports(self):
    frame_distribution = {1: 2, 2: 2, 3: 569, 6: 1}
    expected_frozen_reports = [{'frozen_frames': 5, 'occurrences': 1}]
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    self.assertEqual(expected_frozen_reports,
        stats_parser._GetFrozenFramesReports(frame_distribution))

  def testIsRemoteStream(self):
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    self.assertTrue(stats_parser._IsRemoteStream(self.remote_stream))

  def testGetDrifTimeStats(self):
    fake_events = self._GetFakeEvents()
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    cadence = stats_parser._GetCadence(fake_events)
    expected_drift_time = [15585, 30917, 29583, 23915, 17913, 16911, 15909]
    expected_rendering_length_error = 29.613733905579398

    self.assertEqual((expected_drift_time, expected_rendering_length_error),
        stats_parser._GetDrifTimeStats(fake_events, cadence))

  def testGetSmoothnessStats(self):
    norm_drift_time = [5948.2857142857138, 9383.7142857142862,
        8049.7142857142862, 2381.7142857142862, 3620.2857142857138,
        4622.2857142857138, 5624.2857142857138]
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    expected_percent_badly_oos = 0.0
    expected_percent_out_of_sync = 0.0
    expected_smoothness_score = 100.0
    expected_smoothness_stats = (expected_percent_badly_oos,
        expected_percent_out_of_sync, expected_smoothness_score)

    self.assertEqual(expected_smoothness_stats,
        stats_parser._GetSmoothnessStats(norm_drift_time))

  def testNegativeSmoothnessScoreChangedToZero(self):
    norm_drift_time = [15948.285714285714, 9383.714285714286,
        28049.714285714286, 72381.71428571429, 3620.2857142857138,
        4622.285714285714, 35624.28571428572]
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    expected_percent_badly_oos = 28.571428571428573
    expected_percent_out_of_sync = 42.857142857142854
    expected_smoothness_score = 0.0
    expected_smoothness_stats = (expected_percent_badly_oos,
        expected_percent_out_of_sync, expected_smoothness_score)

    self.assertEqual(expected_smoothness_stats,
        stats_parser._GetSmoothnessStats(norm_drift_time))

  def testGetFreezingScore(self):
    frame_distribution = {1: 2, 2: 2, 3: 569, 6: 1}
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    expected_freezing_score = 99.94182664339732
    self.assertEqual(expected_freezing_score,
        stats_parser._GetFreezingScore(frame_distribution))

  def testNegativeFrezingScoreChangedToZero(self):
    frame_distribution = {1: 2, 2: 2, 3: 2, 8:100}
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats([])
    self.assertEqual(0.0, stats_parser._GetFreezingScore(frame_distribution))

  def testGetTimeStats(self):
    fake_events = self._GetFakeEvents()
    expected_frame_dist = {1: 2, 2: 2, 3: 3}
    expected_frame_rate = 28.0
    expected_drift_time = [15585, 30917, 29583, 23915, 17913, 16911, 15909]
    expected_rendering_length_error = 29.613733905579398
    expected_percent_badly_oos = 0.0
    expected_percent_out_of_sync = 0.0
    expected_smoothness_score = 100.0
    expected_freezing_score = 100.0

    stats_cls = stats_helper.WebMediaPlayerMsRenderingStats

    stats_parser = stats_cls(fake_events)

    expected_stats = stats_helper.TimeStats(
        drift_time=expected_drift_time,
        percent_badly_out_of_sync=expected_percent_badly_oos,
        percent_out_of_sync=expected_percent_out_of_sync,
        smoothness_score=expected_smoothness_score,
        freezing_score=expected_freezing_score,
        rendering_length_error=expected_rendering_length_error,
        fps=expected_frame_rate,
        frame_distribution=expected_frame_dist)

    stats = stats_parser.GetTimeStats()

    self.assertEqual(expected_stats.drift_time, stats.drift_time)
    self.assertEqual(expected_stats.percent_badly_out_of_sync,
        stats.percent_badly_out_of_sync)
    self.assertEqual(expected_stats.percent_out_of_sync,
        stats.percent_out_of_sync)
    self.assertEqual(expected_stats.smoothness_score, stats.smoothness_score)
    self.assertEqual(expected_stats.freezing_score, stats.freezing_score)
    self.assertEqual(expected_stats.rendering_length_error,
        stats.rendering_length_error)
    self.assertEqual(expected_stats.fps, stats.fps)
    self.assertEqual(expected_stats.frame_distribution,
        stats.frame_distribution)

  def testCorruptData(self):
    corrupt_events = self._GetCorruptEvents()
    stats_parser = stats_helper.WebMediaPlayerMsRenderingStats(corrupt_events)
    stats = stats_parser.GetTimeStats()
    self.assertTrue(stats.invalid_data)
    self.assertIsNone(stats.drift_time)
    self.assertIsNone(stats.percent_badly_out_of_sync)
    self.assertIsNone(stats.percent_out_of_sync)
    self.assertIsNone(stats.smoothness_score)
    self.assertIsNone(stats.freezing_score)
    self.assertIsNone(stats.rendering_length_error)
    self.assertIsNone(stats.fps)
    self.assertIsNone(stats.frame_distribution)
