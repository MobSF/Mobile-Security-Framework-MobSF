# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import collections
import math
import sys

from telemetry.timeline import model as model_module
from telemetry.value import improvement_direction
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.web_perf.metrics import timeline_based_metric

TOPLEVEL_GL_CATEGORY = 'gpu_toplevel'
TOPLEVEL_SERVICE_CATEGORY = 'disabled-by-default-gpu.service'
TOPLEVEL_DEVICE_CATEGORY = 'disabled-by-default-gpu.device'

SERVICE_FRAME_END_MARKER = (TOPLEVEL_SERVICE_CATEGORY, 'SwapBuffer')
DEVICE_FRAME_END_MARKER = (TOPLEVEL_DEVICE_CATEGORY, 'SwapBuffer')

TRACKED_GL_CONTEXT_NAME = {'RenderCompositor': 'render_compositor',
                           'BrowserCompositor': 'browser_compositor',
                           'Compositor': 'browser_compositor'}


def _CalculateFrameTimes(events_per_frame, event_data_func):
  """Given a list of events per frame and a function to extract event time data,
     returns a list of frame times."""
  times_per_frame = []
  for event_list in events_per_frame:
    event_times = [event_data_func(event) for event in event_list]
    times_per_frame.append(sum(event_times))
  return times_per_frame


def _CPUFrameTimes(events_per_frame):
  """Given a list of events per frame, returns a list of CPU frame times."""
  # CPU event frames are calculated using the event thread duration.
  # Some platforms do not support thread_duration, convert those to 0.
  return _CalculateFrameTimes(events_per_frame,
                              lambda event: event.thread_duration or 0)


def _GPUFrameTimes(events_per_frame):
  """Given a list of events per frame, returns a list of GPU frame times."""
  # GPU event frames are asynchronous slices which use the event duration.
  return _CalculateFrameTimes(events_per_frame,
                              lambda event: event.duration)


def TimelineName(name, source_type, value_type):
  """Constructs the standard name given in the timeline.

  Args:
    name: The name of the timeline, for example "total", or "render_compositor".
    source_type: One of "cpu", "gpu" or None. None is only used for total times.
    value_type: the type of value. For example "mean", "stddev"...etc.
  """
  if source_type:
    return '%s_%s_%s_time' % (name, value_type, source_type)
  else:
    return '%s_%s_time' % (name, value_type)


class GPUTimelineMetric(timeline_based_metric.TimelineBasedMetric):
  """Computes GPU based metrics."""

  def __init__(self):
    super(GPUTimelineMetric, self).__init__()

  def AddResults(self, model, _, interaction_records, results):
    self.VerifyNonOverlappedRecords(interaction_records)
    service_times = self._CalculateGPUTimelineData(model)
    for value_item, durations in service_times.iteritems():
      count = len(durations)
      avg = 0.0
      stddev = 0.0
      maximum = 0.0
      if count:
        avg = sum(durations) / count
        stddev = math.sqrt(sum((d - avg) ** 2 for d in durations) / count)
        maximum = max(durations)

      name, src = value_item

      if src:
        frame_times_name = '%s_%s_frame_times' % (name, src)
      else:
        frame_times_name = '%s_frame_times' % (name)

      if durations:
        results.AddValue(list_of_scalar_values.ListOfScalarValues(
            results.current_page, frame_times_name, 'ms', durations,
            tir_label=interaction_records[0].label,
            improvement_direction=improvement_direction.DOWN))

      results.AddValue(scalar.ScalarValue(
          results.current_page, TimelineName(name, src, 'max'), 'ms', maximum,
          tir_label=interaction_records[0].label,
          improvement_direction=improvement_direction.DOWN))
      results.AddValue(scalar.ScalarValue(
          results.current_page, TimelineName(name, src, 'mean'), 'ms', avg,
          tir_label=interaction_records[0].label,
          improvement_direction=improvement_direction.DOWN))
      results.AddValue(scalar.ScalarValue(
          results.current_page, TimelineName(name, src, 'stddev'), 'ms', stddev,
          tir_label=interaction_records[0].label,
          improvement_direction=improvement_direction.DOWN))

  def _CalculateGPUTimelineData(self, model):
    """Uses the model and calculates the times for various values for each
       frame. The return value will be a dictionary of the following format:
         {
           (EVENT_NAME1, SRC1_TYPE): [FRAME0_TIME, FRAME1_TIME...etc.],
           (EVENT_NAME2, SRC2_TYPE): [FRAME0_TIME, FRAME1_TIME...etc.],
         }

       Events:
         swap - The time in milliseconds between each swap marker.
         total - The amount of time spent in the renderer thread.
         TRACKED_NAMES: Using the TRACKED_GL_CONTEXT_NAME dict, we
                        include the traces per frame for the
                        tracked name.
       Source Types:
         None - This will only be valid for the "swap" event.
         cpu - For an event, the "cpu" source type signifies time spent on the
               gpu thread using the CPU. This uses the "gpu.service" markers.
         gpu - For an event, the "gpu" source type signifies time spent on the
               gpu thread using the GPU. This uses the "gpu.device" markers.
    """
    all_service_events = []
    current_service_frame_end = sys.maxint
    current_service_events = []

    all_device_events = []
    current_device_frame_end = sys.maxint
    current_device_events = []

    tracked_events = {}
    tracked_events.update(
        dict([((value, 'cpu'), [])
              for value in TRACKED_GL_CONTEXT_NAME.itervalues()]))
    tracked_events.update(
        dict([((value, 'gpu'), [])
              for value in TRACKED_GL_CONTEXT_NAME.itervalues()]))

    # These will track traces within the current frame.
    current_tracked_service_events = collections.defaultdict(list)
    current_tracked_device_events = collections.defaultdict(list)

    event_iter = model.IterAllEvents(
        event_type_predicate=model_module.IsSliceOrAsyncSlice)
    for event in event_iter:
      # Look for frame end markers
      if (event.category, event.name) == SERVICE_FRAME_END_MARKER:
        current_service_frame_end = event.end
      elif (event.category, event.name) == DEVICE_FRAME_END_MARKER:
        current_device_frame_end = event.end

      # Track all other toplevel gl category markers
      elif event.args.get('gl_category', None) == TOPLEVEL_GL_CATEGORY:
        base_name = event.name
        dash_index = base_name.rfind('-')
        if dash_index != -1:
          base_name = base_name[:dash_index]
        tracked_name = TRACKED_GL_CONTEXT_NAME.get(base_name, None)

        if event.category == TOPLEVEL_SERVICE_CATEGORY:
          # Check if frame has ended.
          if event.start >= current_service_frame_end:
            if current_service_events:
              all_service_events.append(current_service_events)
              for value in TRACKED_GL_CONTEXT_NAME.itervalues():
                tracked_events[(value, 'cpu')].append(
                    current_tracked_service_events[value])
            current_service_events = []
            current_service_frame_end = sys.maxint
            current_tracked_service_events.clear()

          current_service_events.append(event)
          if tracked_name:
            current_tracked_service_events[tracked_name].append(event)

        elif event.category == TOPLEVEL_DEVICE_CATEGORY:
          # Check if frame has ended.
          if event.start >= current_device_frame_end:
            if current_device_events:
              all_device_events.append(current_device_events)
              for value in TRACKED_GL_CONTEXT_NAME.itervalues():
                tracked_events[(value, 'gpu')].append(
                    current_tracked_device_events[value])
            current_device_events = []
            current_device_frame_end = sys.maxint
            current_tracked_device_events.clear()

          current_device_events.append(event)
          if tracked_name:
            current_tracked_device_events[tracked_name].append(event)

    # Append Data for Last Frame.
    if current_service_events:
      all_service_events.append(current_service_events)
      for value in TRACKED_GL_CONTEXT_NAME.itervalues():
        tracked_events[(value, 'cpu')].append(
            current_tracked_service_events[value])
    if current_device_events:
      all_device_events.append(current_device_events)
      for value in TRACKED_GL_CONTEXT_NAME.itervalues():
        tracked_events[(value, 'gpu')].append(
            current_tracked_device_events[value])

    # Calculate Mean Frame Time for the CPU side.
    frame_times = []
    if all_service_events:
      prev_frame_end = all_service_events[0][0].start
      for event_list in all_service_events:
        last_service_event_in_frame = event_list[-1]
        frame_times.append(last_service_event_in_frame.end - prev_frame_end)
        prev_frame_end = last_service_event_in_frame.end

    # Create the timeline data dictionary for service side traces.
    total_frame_value = ('swap', None)
    cpu_frame_value = ('total', 'cpu')
    gpu_frame_value = ('total', 'gpu')
    timeline_data = {}
    timeline_data[total_frame_value] = frame_times
    timeline_data[cpu_frame_value] = _CPUFrameTimes(all_service_events)
    for value in TRACKED_GL_CONTEXT_NAME.itervalues():
      cpu_value = (value, 'cpu')
      timeline_data[cpu_value] = _CPUFrameTimes(tracked_events[cpu_value])

    # Add in GPU side traces if it was supported (IE. device traces exist).
    if all_device_events:
      timeline_data[gpu_frame_value] = _GPUFrameTimes(all_device_events)
      for value in TRACKED_GL_CONTEXT_NAME.itervalues():
        gpu_value = (value, 'gpu')
        tracked_gpu_event = tracked_events[gpu_value]
        timeline_data[gpu_value] = _GPUFrameTimes(tracked_gpu_event)

    return timeline_data
