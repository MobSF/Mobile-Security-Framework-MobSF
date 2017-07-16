# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import itertools

from operator import attrgetter

from telemetry.web_perf.metrics import rendering_frame

# These are LatencyInfo component names indicating the various components
# that the input event has travelled through.
# This is when the input event first reaches chrome.
UI_COMP_NAME = 'INPUT_EVENT_LATENCY_UI_COMPONENT'
# This is when the input event was originally created by OS.
ORIGINAL_COMP_NAME = 'INPUT_EVENT_LATENCY_ORIGINAL_COMPONENT'
# This is when the input event was sent from browser to renderer.
BEGIN_COMP_NAME = 'INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT'
# This is when an input event is turned into a scroll update.
BEGIN_SCROLL_UPDATE_COMP_NAME = (
    'LATENCY_BEGIN_SCROLL_LISTENER_UPDATE_MAIN_COMPONENT')
# This is when a scroll update is forwarded to the main thread.
FORWARD_SCROLL_UPDATE_COMP_NAME = (
    'INPUT_EVENT_LATENCY_FORWARD_SCROLL_UPDATE_TO_MAIN_COMPONENT')
# This is when the input event has reached swap buffer.
END_COMP_NAME = 'INPUT_EVENT_GPU_SWAP_BUFFER_COMPONENT'

# Name for a main thread scroll update latency event.
MAIN_THREAD_SCROLL_UPDATE_EVENT_NAME = 'Latency::ScrollUpdate'
# Name for a gesture scroll update latency event.
GESTURE_SCROLL_UPDATE_EVENT_NAME = 'InputLatency::GestureScrollUpdate'

# These are keys used in the 'data' field dictionary located in
# BenchmarkInstrumentation::ImplThreadRenderingStats.
VISIBLE_CONTENT_DATA = 'visible_content_area'
APPROXIMATED_VISIBLE_CONTENT_DATA = 'approximated_visible_content_area'
CHECKERBOARDED_VISIBLE_CONTENT_DATA = 'checkerboarded_visible_content_area'
# These are keys used in the 'errors' field  dictionary located in
# RenderingStats in this file.
APPROXIMATED_PIXEL_ERROR = 'approximated_pixel_percentages'
CHECKERBOARDED_PIXEL_ERROR = 'checkerboarded_pixel_percentages'


def GetLatencyEvents(process, timeline_range):
  """Get LatencyInfo trace events from the process's trace buffer that are
     within the timeline_range.

  Input events dump their LatencyInfo into trace buffer as async trace event
  of name starting with "InputLatency". Non-input events with name starting
  with "Latency". The trace event has a member 'data' containing its latency
  history.

  """
  latency_events = []
  if not process:
    return latency_events
  for event in itertools.chain(
      process.IterAllAsyncSlicesStartsWithName('InputLatency'),
      process.IterAllAsyncSlicesStartsWithName('Latency')):
    if event.start >= timeline_range.min and event.end <= timeline_range.max:
      for ss in event.sub_slices:
        if 'data' in ss.args:
          latency_events.append(ss)
  return latency_events


def ComputeEventLatencies(input_events):
  """ Compute input event latencies.

  Input event latency is the time from when the input event is created to
  when its resulted page is swap buffered.
  Input event on different platforms uses different LatencyInfo component to
  record its creation timestamp. We go through the following component list
  to find the creation timestamp:
  1. INPUT_EVENT_LATENCY_ORIGINAL_COMPONENT -- when event is created in OS
  2. INPUT_EVENT_LATENCY_UI_COMPONENT -- when event reaches Chrome
  3. INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT -- when event reaches RenderWidget

  If the latency starts with a
  LATENCY_BEGIN_SCROLL_UPDATE_MAIN_COMPONENT component, then it is
  classified as a scroll update instead of a normal input latency measure.

  Returns:
    A list sorted by increasing start time of latencies which are tuples of
    (input_event_name, latency_in_ms).
  """
  input_event_latencies = []
  for event in input_events:
    data = event.args['data']
    if END_COMP_NAME in data:
      end_time = data[END_COMP_NAME]['time']
      if ORIGINAL_COMP_NAME in data:
        start_time = data[ORIGINAL_COMP_NAME]['time']
      elif UI_COMP_NAME in data:
        start_time = data[UI_COMP_NAME]['time']
      elif BEGIN_COMP_NAME in data:
        start_time = data[BEGIN_COMP_NAME]['time']
      elif BEGIN_SCROLL_UPDATE_COMP_NAME in data:
        start_time = data[BEGIN_SCROLL_UPDATE_COMP_NAME]['time']
      else:
        raise ValueError('LatencyInfo has no begin component')
      latency = (end_time - start_time) / 1000.0
      input_event_latencies.append((start_time, event.name, latency))

  input_event_latencies.sort()
  return [(name, latency) for _, name, latency in input_event_latencies]


def HasDrmStats(process):
  """ Return True if the process contains DrmEventFlipComplete event.
  """
  if not process:
    return False
  for event in process.IterAllSlicesOfName('DrmEventFlipComplete'):
    if 'data' in event.args and event.args['data']['frame_count'] == 1:
      return True
  return False

def HasRenderingStats(process):
  """ Returns True if the process contains at least one
      BenchmarkInstrumentation::*RenderingStats event with a frame.
  """
  if not process:
    return False
  for event in process.IterAllSlicesOfName(
      'BenchmarkInstrumentation::DisplayRenderingStats'):
    if 'data' in event.args and event.args['data']['frame_count'] == 1:
      return True
  for event in process.IterAllSlicesOfName(
      'BenchmarkInstrumentation::ImplThreadRenderingStats'):
    if 'data' in event.args and event.args['data']['frame_count'] == 1:
      return True
  return False

def GetTimestampEventName(process):
  """ Returns the name of the events used to count frame timestamps. """
  if process.name == 'SurfaceFlinger':
    return 'vsync_before'

  if process.name == 'GPU Process':
    return 'DrmEventFlipComplete'

  event_name = 'BenchmarkInstrumentation::DisplayRenderingStats'
  for event in process.IterAllSlicesOfName(event_name):
    if 'data' in event.args and event.args['data']['frame_count'] == 1:
      return event_name

  return 'BenchmarkInstrumentation::ImplThreadRenderingStats'

class RenderingStats(object):
  def __init__(self, renderer_process, browser_process, surface_flinger_process,
               gpu_process, timeline_ranges):
    """
    Utility class for extracting rendering statistics from the timeline (or
    other loggin facilities), and providing them in a common format to classes
    that compute benchmark metrics from this data.

    Stats are lists of lists of numbers. The outer list stores one list per
    timeline range.

    All *_time values are measured in milliseconds.
    """
    assert len(timeline_ranges) > 0
    self.refresh_period = None

    # Find the top level process with rendering stats (browser or renderer).
    if surface_flinger_process:
      timestamp_process = surface_flinger_process
      self._GetRefreshPeriodFromSurfaceFlingerProcess(surface_flinger_process)
    elif HasDrmStats(gpu_process):
      timestamp_process = gpu_process
    elif HasRenderingStats(browser_process):
      timestamp_process = browser_process
    else:
      timestamp_process = renderer_process

    timestamp_event_name = GetTimestampEventName(timestamp_process)

    # A lookup from list names below to any errors or exceptions encountered
    # in attempting to generate that list.
    self.errors = {}

    self.frame_timestamps = []
    self.frame_times = []
    self.approximated_pixel_percentages = []
    self.checkerboarded_pixel_percentages = []
    # End-to-end latency for input event - from when input event is
    # generated to when the its resulted page is swap buffered.
    self.input_event_latency = []
    self.frame_queueing_durations = []
    # Latency from when a scroll update is sent to the main thread until the
    # resulting frame is swapped.
    self.main_thread_scroll_latency = []
    # Latency for a GestureScrollUpdate input event.
    self.gesture_scroll_update_latency = []

    for timeline_range in timeline_ranges:
      self.frame_timestamps.append([])
      self.frame_times.append([])
      self.approximated_pixel_percentages.append([])
      self.checkerboarded_pixel_percentages.append([])
      self.input_event_latency.append([])
      self.main_thread_scroll_latency.append([])
      self.gesture_scroll_update_latency.append([])

      if timeline_range.is_empty:
        continue
      self._InitFrameTimestampsFromTimeline(
          timestamp_process, timestamp_event_name, timeline_range)
      self._InitImplThreadRenderingStatsFromTimeline(
          renderer_process, timeline_range)
      self._InitInputLatencyStatsFromTimeline(
          browser_process, renderer_process, timeline_range)
      self._InitFrameQueueingDurationsFromTimeline(
          renderer_process, timeline_range)

  def _GetRefreshPeriodFromSurfaceFlingerProcess(self, surface_flinger_process):
    for event in surface_flinger_process.IterAllEventsOfName('vsync_before'):
      self.refresh_period = event.args['data']['refresh_period']
      return

  def _InitInputLatencyStatsFromTimeline(
      self, browser_process, renderer_process, timeline_range):
    latency_events = GetLatencyEvents(browser_process, timeline_range)
    # Plugin input event's latency slice is generated in renderer process.
    latency_events.extend(GetLatencyEvents(renderer_process, timeline_range))
    event_latencies = ComputeEventLatencies(latency_events)
    # Don't include scroll updates in the overall input latency measurement,
    # because scroll updates can take much more time to process than other
    # input events and would therefore add noise to overall latency numbers.
    self.input_event_latency[-1] = [
        latency for name, latency in event_latencies
        if name != MAIN_THREAD_SCROLL_UPDATE_EVENT_NAME]
    self.main_thread_scroll_latency[-1] = [
        latency for name, latency in event_latencies
        if name == MAIN_THREAD_SCROLL_UPDATE_EVENT_NAME]
    self.gesture_scroll_update_latency[-1] = [
        latency for name, latency in event_latencies
        if name == GESTURE_SCROLL_UPDATE_EVENT_NAME]

  def _GatherEvents(self, event_name, process, timeline_range):
    events = []
    for event in process.IterAllSlicesOfName(event_name):
      if event.start >= timeline_range.min and event.end <= timeline_range.max:
        if 'data' not in event.args:
          continue
        events.append(event)
    events.sort(key=attrgetter('start'))
    return events

  def _AddFrameTimestamp(self, event):
    frame_count = event.args['data']['frame_count']
    if frame_count > 1:
      raise ValueError('trace contains multi-frame render stats')
    if frame_count == 1:
      if event.name == 'DrmEventFlipComplete':
        self.frame_timestamps[-1].append(
            event.args['data']['vblank.tv_sec'] * 1000.0 +
            event.args['data']['vblank.tv_usec'] / 1000.0)
      else:
        self.frame_timestamps[-1].append(
            event.start)
      if len(self.frame_timestamps[-1]) >= 2:
        self.frame_times[-1].append(
            self.frame_timestamps[-1][-1] - self.frame_timestamps[-1][-2])

  def _InitFrameTimestampsFromTimeline(
      self, process, timestamp_event_name, timeline_range):
    for event in self._GatherEvents(
        timestamp_event_name, process, timeline_range):
      self._AddFrameTimestamp(event)

  def _InitImplThreadRenderingStatsFromTimeline(self, process, timeline_range):
    event_name = 'BenchmarkInstrumentation::ImplThreadRenderingStats'
    for event in self._GatherEvents(event_name, process, timeline_range):
      data = event.args['data']
      if VISIBLE_CONTENT_DATA not in data:
        self.errors[APPROXIMATED_PIXEL_ERROR] = (
          'Calculating approximated_pixel_percentages not possible because '
          'visible_content_area was missing.')
        self.errors[CHECKERBOARDED_PIXEL_ERROR] = (
          'Calculating checkerboarded_pixel_percentages not possible because '
          'visible_content_area was missing.')
        return
      visible_content_area = data[VISIBLE_CONTENT_DATA]
      if visible_content_area == 0:
        self.errors[APPROXIMATED_PIXEL_ERROR] = (
          'Calculating approximated_pixel_percentages would have caused '
          'a divide-by-zero')
        self.errors[CHECKERBOARDED_PIXEL_ERROR] = (
          'Calculating checkerboarded_pixel_percentages would have caused '
          'a divide-by-zero')
        return
      if APPROXIMATED_VISIBLE_CONTENT_DATA in data:
        self.approximated_pixel_percentages[-1].append(
          round(float(data[APPROXIMATED_VISIBLE_CONTENT_DATA]) /
                float(data[VISIBLE_CONTENT_DATA]) * 100.0, 3))
      else:
        self.errors[APPROXIMATED_PIXEL_ERROR] = (
          'approximated_pixel_percentages was not recorded')
      if CHECKERBOARDED_VISIBLE_CONTENT_DATA in data:
        self.checkerboarded_pixel_percentages[-1].append(
          round(float(data[CHECKERBOARDED_VISIBLE_CONTENT_DATA]) /
                float(data[VISIBLE_CONTENT_DATA]) * 100.0, 3))
      else:
        self.errors[CHECKERBOARDED_PIXEL_ERROR] = (
          'checkerboarded_pixel_percentages was not recorded')

  def _InitFrameQueueingDurationsFromTimeline(self, process, timeline_range):
    try:
      events = rendering_frame.GetFrameEventsInsideRange(process,
                                                         timeline_range)
      new_frame_queueing_durations = [e.queueing_duration for e in events]
      self.frame_queueing_durations.append(new_frame_queueing_durations)
    except rendering_frame.NoBeginFrameIdException:
      self.errors['frame_queueing_durations'] = (
          'Current chrome version does not support the queueing delay metric.')
