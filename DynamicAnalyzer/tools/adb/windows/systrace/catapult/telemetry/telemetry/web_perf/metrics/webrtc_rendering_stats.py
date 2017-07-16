# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.util import statistics

DISPLAY_HERTZ = 60.0
VSYNC_DURATION = 1e6 / DISPLAY_HERTZ
# When to consider a frame frozen (in VSYNC units): meaning 1 initial
# frame + 5 repeats of that frame.
FROZEN_THRESHOLD = 6
# Severity factor.
SEVERITY = 3

IDEAL_RENDER_INSTANT = 'Ideal Render Instant'
ACTUAL_RENDER_BEGIN = 'Actual Render Begin'
ACTUAL_RENDER_END = 'Actual Render End'
SERIAL = 'Serial'


class TimeStats(object):
  """Stats container for webrtc rendering metrics."""

  def __init__(self, drift_time=None, mean_drift_time=None,
    std_dev_drift_time=None, percent_badly_out_of_sync=None,
    percent_out_of_sync=None, smoothness_score=None, freezing_score=None,
    rendering_length_error=None, fps=None, frame_distribution=None):
    self.drift_time = drift_time
    self.mean_drift_time = mean_drift_time
    self.std_dev_drift_time = std_dev_drift_time
    self.percent_badly_out_of_sync = percent_badly_out_of_sync
    self.percent_out_of_sync = percent_out_of_sync
    self.smoothness_score = smoothness_score
    self.freezing_score = freezing_score
    self.rendering_length_error = rendering_length_error
    self.fps = fps
    self.frame_distribution = frame_distribution
    self.invalid_data = False



class WebMediaPlayerMsRenderingStats(object):
  """Analyzes events of WebMediaPlayerMs type."""

  def __init__(self, events):
    """Save relevant events according to their stream."""
    self.stream_to_events = self._MapEventsToStream(events)

  def _IsEventValid(self, event):
    """Check that the needed arguments are present in event.

    Args:
      event: event to check.

    Returns:
      True is event is valid, false otherwise."""
    if not event.args:
      return False
    mandatory = [ACTUAL_RENDER_BEGIN, ACTUAL_RENDER_END,
        IDEAL_RENDER_INSTANT, SERIAL]
    for parameter in mandatory:
      if not parameter in event.args:
        return False
    return True

  def _MapEventsToStream(self, events):
    """Build a dictionary of events indexed by stream.

    The events of interest have a 'Serial' argument which represents the
    stream ID. The 'Serial' argument identifies the local or remote nature of
    the stream with a least significant bit  of 0 or 1 as well as the hash
    value of the video track's URL. So stream::=hash(0|1} . The method will
    then list the events of the same stream in a frame_distribution on stream
    id. Practically speaking remote streams have an odd stream id and local
    streams have a even stream id.
    Args:
      events: Telemetry WebMediaPlayerMs events.

    Returns:
      A dict of stream IDs mapped to events on that stream.
    """
    stream_to_events = {}
    for event in events:
      if not self._IsEventValid(event):
        # This is not a render event, skip it.
        continue
      stream = event.args[SERIAL]
      events_for_stream = stream_to_events.setdefault(stream, [])
      events_for_stream.append(event)

    return stream_to_events

  def _GetCadence(self, relevant_events):
    """Calculate the apparent cadence of the rendering.

    In this paragraph I will be using regex notation. What is intended by the
    word cadence is a sort of extended instantaneous 'Cadence' (thus not
    necessarily periodic). Just as an example, a normal 'Cadence' could be
    something like [2 3] which means possibly an observed frame persistence
    progression of [{2 3}+] for an ideal 20FPS video source. So what we are
    calculating here is the list of frame persistence, kind of a
    'Proto-Cadence', but cadence is shorter so we abuse the word.

    Args:
      relevant_events: list of Telemetry events.

    Returns:
      a list of frame persistence values.
    """
    cadence = []
    frame_persistence = 0
    old_ideal_render = 0
    for event in relevant_events:
      if not self._IsEventValid(event):
        # This event is not a render event so skip it.
        continue
      if event.args[IDEAL_RENDER_INSTANT] == old_ideal_render:
        frame_persistence += 1
      else:
        cadence.append(frame_persistence)
        frame_persistence = 1
        old_ideal_render = event.args[IDEAL_RENDER_INSTANT]
    cadence.append(frame_persistence)
    cadence.pop(0)
    return cadence

  def _GetSourceToOutputDistribution(self, cadence):
    """Create distribution for the cadence frame display values.

    If the overall display distribution is A1:A2:..:An, this will tell us how
    many times a frame stays displayed during Ak*VSYNC_DURATION, also known as
    'source to output' distribution. Or in other terms:
    a distribution B::= let C be the cadence, B[k]=p with k in Unique(C)
    and p=Card(k in C).

    Args:
      cadence: list of frame persistence values.

    Returns:
      a dictionary containing the distribution
    """
    frame_distribution = {}
    for ticks in cadence:
      ticks_so_far = frame_distribution.setdefault(ticks, 0)
      frame_distribution[ticks] = ticks_so_far + 1
    return frame_distribution

  def _GetFpsFromCadence(self, frame_distribution):
    """Calculate the apparent FPS from frame distribution.

    Knowing the display frequency and the frame distribution, it is possible to
    calculate the video apparent frame rate as played by WebMediaPlayerMs
    module.

    Args:
      frame_distribution: the source to output distribution.

    Returns:
      the video apparent frame rate.
    """
    number_frames = sum(frame_distribution.values())
    number_vsyncs = sum([ticks * frame_distribution[ticks]
       for ticks in frame_distribution])
    mean_ratio = float(number_vsyncs) / number_frames
    return DISPLAY_HERTZ / mean_ratio

  def _GetFrozenFramesReports(self, frame_distribution):
    """Find evidence of frozen frames in distribution.

    For simplicity we count as freezing the frames that appear at least five
    times in a row counted from 'Ideal Render Instant' perspective. So let's
    say for 1 source frame, we rendered 6 frames, then we consider 5 of these
    rendered frames as frozen. But we mitigate this by saying anything under
    5 frozen frames will not be counted as frozen.

    Args:
      frame_distribution: the source to output distribution.

    Returns:
      a list of dicts whose keys are ('frozen_frames', 'occurrences').
    """
    frozen_frames = []
    frozen_frame_vsyncs = [ticks for ticks in frame_distribution if ticks >=
        FROZEN_THRESHOLD]
    for frozen_frames_vsync in frozen_frame_vsyncs:
      logging.debug('%s frames not updated after %s vsyncs',
          frame_distribution[frozen_frames_vsync], frozen_frames_vsync)
      frozen_frames.append(
          {'frozen_frames': frozen_frames_vsync - 1,
           'occurrences': frame_distribution[frozen_frames_vsync]})
    return frozen_frames

  def _FrozenPenaltyWeight(self, number_frozen_frames):
    """Returns the weighted penalty for a number of frozen frames.

    As mentioned earlier, we count for frozen anything above 6 vsync display
    duration for the same 'Initial Render Instant', which is five frozen
    frames.

    Args:
      number_frozen_frames: number of frozen frames.

    Returns:
      the penalty weight (int) for that number of frozen frames.
    """

    penalty = {
      0: 0,
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 1,
      6: 5,
      7: 15,
      8: 25
    }
    weight = penalty.get(number_frozen_frames, 8 * (number_frozen_frames - 4))
    return weight

  def _IsRemoteStream(self, stream):
    """Check if stream is remote."""
    return stream % 2

  def _GetDrifTimeStats(self, relevant_events, cadence):
    """Get the drift time statistics.

    This method will calculate drift_time stats, that is to say :
    drift_time::= list(actual render begin - ideal render).
    rendering_length error::= the rendering length error.

    Args:
      relevant_events: events to get drift times stats from.
      cadence: list of frame persistence values.

    Returns:
      a tuple of (drift_time, rendering_length_error).
    """
    drift_time = []
    old_ideal_render = 0
    discrepancy = []
    index = 0
    for event in relevant_events:
      current_ideal_render = event.args[IDEAL_RENDER_INSTANT]
      if current_ideal_render == old_ideal_render:
        # Skip to next event because we're looking for a source frame.
        continue
      actual_render_begin = event.args[ACTUAL_RENDER_BEGIN]
      drift_time.append(actual_render_begin - current_ideal_render)
      discrepancy.append(abs(current_ideal_render - old_ideal_render
          - VSYNC_DURATION * cadence[index]))
      old_ideal_render = current_ideal_render
      index += 1
    discrepancy.pop(0)
    last_ideal_render = relevant_events[-1].args[IDEAL_RENDER_INSTANT]
    first_ideal_render = relevant_events[0].args[IDEAL_RENDER_INSTANT]
    rendering_length_error = 100.0 * (sum([x for x in discrepancy]) /
        (last_ideal_render - first_ideal_render))

    return drift_time, rendering_length_error

  def _GetSmoothnessStats(self, norm_drift_time):
    """Get the smoothness stats from the normalized drift time.

    This method will calculate the smoothness score, along with the percentage
    of frames badly out of sync and the percentage of frames out of sync. To be
    considered badly out of sync, a frame has to have missed rendering by at
    least 2*VSYNC_DURATION. To be considered out of sync, a frame has to have
    missed rendering by at least one VSYNC_DURATION.
    The smoothness score is a measure of how out of sync the frames are.

    Args:
      norm_drift_time: normalized drift time.

    Returns:
      a tuple of (percent_badly_oos, percent_out_of_sync, smoothness_score)
    """
    # How many times is a frame later/earlier than T=2*VSYNC_DURATION. Time is
    # in microseconds.
    frames_severely_out_of_sync = len(
        [x for x in norm_drift_time if abs(x) > 2 * VSYNC_DURATION])
    percent_badly_oos = (
        100.0 * frames_severely_out_of_sync / len(norm_drift_time))

    # How many times is a frame later/earlier than VSYNC_DURATION.
    frames_out_of_sync = len(
        [x for x in norm_drift_time if abs(x) > VSYNC_DURATION])
    percent_out_of_sync = (
        100.0 * frames_out_of_sync / len(norm_drift_time))

    frames_oos_only_once = frames_out_of_sync - frames_severely_out_of_sync

    # Calculate smoothness metric. From the formula, we can see that smoothness
    # score can be negative.
    smoothness_score = 100.0 - 100.0 * (frames_oos_only_once +
        SEVERITY * frames_severely_out_of_sync) / len(norm_drift_time)

    # Minimum smoothness_score value allowed is zero.
    if smoothness_score < 0:
      smoothness_score = 0

    return (percent_badly_oos, percent_out_of_sync, smoothness_score)

  def _GetFreezingScore(self, frame_distribution):
    """Get the freezing score."""

    # The freezing score is based on the source to output distribution.
    number_vsyncs = sum([n * frame_distribution[n]
        for n in frame_distribution])
    frozen_frames = self._GetFrozenFramesReports(frame_distribution)

    # Calculate freezing metric.
    # Freezing metric can be negative if things are really bad. In that case we
    # change it to zero as minimum valud.
    freezing_score = 100.0
    for frozen_report in frozen_frames:
      weight = self._FrozenPenaltyWeight(frozen_report['frozen_frames'])
      freezing_score -= (
          100.0 * frozen_report['occurrences'] / number_vsyncs * weight)
    if freezing_score < 0:
      freezing_score = 0

    return freezing_score

  def GetTimeStats(self):
    """Calculate time stamp stats for all remote stream events."""
    stats = {}
    for stream, relevant_events in self.stream_to_events.iteritems():
      if len(relevant_events) == 1:
        logging.debug('Found a stream=%s with just one event', stream)
        continue
      if not self._IsRemoteStream(stream):
        logging.info('Skipping processing of local stream: %s', stream)
        continue

      cadence = self._GetCadence(relevant_events)
      if not cadence:
        stats = TimeStats()
        stats.invalid_data = True
        return stats

      frame_distribution = self._GetSourceToOutputDistribution(cadence)
      fps = self._GetFpsFromCadence(frame_distribution)

      drift_time_stats = self._GetDrifTimeStats(relevant_events, cadence)
      (drift_time, rendering_length_error) = drift_time_stats

      # Drift time normalization.
      mean_drift_time = statistics.ArithmeticMean(drift_time)
      norm_drift_time = [abs(x - mean_drift_time) for x in drift_time]

      smoothness_stats = self._GetSmoothnessStats(norm_drift_time)
      (percent_badly_oos, percent_out_of_sync,
          smoothness_score) = smoothness_stats

      freezing_score = self._GetFreezingScore(frame_distribution)

      stats = TimeStats(drift_time=drift_time,
          percent_badly_out_of_sync=percent_badly_oos,
          percent_out_of_sync=percent_out_of_sync,
          smoothness_score=smoothness_score, freezing_score=freezing_score,
          rendering_length_error=rendering_length_error, fps=fps,
          frame_distribution=frame_distribution)
    return stats
