# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import value
from telemetry.web_perf.metrics import timeline_based_metric

_PROCESS_CREATION = 'Startup.BrowserProcessCreation'
_MAIN_ENTRY_POINT = 'Startup.BrowserMainEntryPoint'

# A dictionary that maps metric names to a value, which can be either of
# the two:
#  1. A tuple of one event name if the event itself contains reported duration
#  2. A tuple of two event names if the value to report is the time difference
#     between starting these events
_METRICS = {
  'messageloop_start_time':
      ('Startup.BrowserMessageLoopStartTimeFromMainEntry2',),

  'window_display_time':
      ('Startup.BrowserWindowDisplay',),

  'open_tabs_time':
      ('Startup.BrowserOpenTabs',),

  'first_non_empty_paint_time':
      ('Startup.FirstWebContents.NonEmptyPaint2',),

  'first_main_frame_load_time':
      ('Startup.FirstWebContents.MainFrameLoad2',),

  'foreground_tab_load_complete':
      (_MAIN_ENTRY_POINT, 'loadEventEnd'),

  'foreground_tab_request_start':
      (_MAIN_ENTRY_POINT, 'requestStart'),
}

_TRACKED_EVENT_NAMES = set()
for i in _METRICS.values():
  _TRACKED_EVENT_NAMES.add(i[0])
  if len(i) == 2:
    _TRACKED_EVENT_NAMES.add(i[1])


class StartupTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """Reports summary stats from important startup events."""

  def __init__(self):
    super(StartupTimelineMetric, self).__init__()

  def AddResults(self, model, _renderer_thread, interactions, results):
    pass

  def AddWholeTraceResults(self, model, results):
    browser = model.browser_process

    if not browser:
      return

    # Produce a map of events to track.
    tracked_events = {}
    for event in browser.parent.IterAllEvents(
      event_predicate=lambda event: event.name in _TRACKED_EVENT_NAMES):
      # In case of a begin/end trace event, only track the begin that contain
      # the duration.
      if event.name in tracked_events:
        continue

      tracked_events[event.name] = event

    # Generate the metric values according to the tracked events.
    for display_name, event_names in _METRICS.iteritems():
      if event_names[0] not in tracked_events:
        continue

      duration = None
      if len(event_names) == 1:
        # The single event contains the duration to report.
        duration = tracked_events[event_names[0]].duration

      elif len(event_names) == 2:
        # The duration is defined as the difference between two event starts.
        if event_names[1] not in tracked_events:
          continue

        duration = (tracked_events[event_names[1]].start -
            tracked_events[event_names[0]].start)

      results.AddValue(value.scalar.ScalarValue(
        page=results.current_page,
        name=display_name,
        units='ms',
        value=duration,
        improvement_direction=value.improvement_direction.DOWN))
