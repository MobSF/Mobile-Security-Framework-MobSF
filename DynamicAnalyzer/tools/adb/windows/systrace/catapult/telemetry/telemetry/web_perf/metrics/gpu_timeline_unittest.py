# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.testing import test_page_test_results
from telemetry.timeline import async_slice as async_slice_module
from telemetry.timeline import model as model_module
from telemetry.timeline import slice as slice_module
from telemetry.web_perf.metrics import gpu_timeline
from telemetry.web_perf import timeline_interaction_record as tir_module

SERVICE_FRAME_END_CATEGORY, SERVICE_FRAME_END_NAME = \
    gpu_timeline.SERVICE_FRAME_END_MARKER

DEVICE_FRAME_END_CATEGORY, DEVICE_FRAME_END_NAME = \
    gpu_timeline.DEVICE_FRAME_END_MARKER

INTERACTION_RECORDS = [tir_module.TimelineInteractionRecord("test-record",
                                                            0,
                                                            float('inf'))]


def _CreateGPUSlices(parent_thread, name, start_time, duration, offset=0):
  args = {'gl_category': gpu_timeline.TOPLEVEL_GL_CATEGORY}
  return (slice_module.Slice(parent_thread,
                             gpu_timeline.TOPLEVEL_SERVICE_CATEGORY,
                             name, start_time,
                             args=args,
                             duration=duration,
                             thread_duration=duration),
          async_slice_module.AsyncSlice(gpu_timeline.TOPLEVEL_DEVICE_CATEGORY,
                             name, start_time + offset,
                             args=args,
                             duration=duration))

def _CreateFrameEndSlices(parent_thread, start_time, duration, offset=0):
  args = {'gl_category': gpu_timeline.TOPLEVEL_GL_CATEGORY}
  return (slice_module.Slice(parent_thread,
                             SERVICE_FRAME_END_CATEGORY,
                             SERVICE_FRAME_END_NAME,
                             start_time,
                             args=args,
                             duration=duration,
                             thread_duration=duration),
          async_slice_module.AsyncSlice(DEVICE_FRAME_END_CATEGORY,
                             DEVICE_FRAME_END_NAME,
                             start_time + offset,
                             args=args,
                             duration=duration))


def _AddSliceToThread(parent_thread, slice_item):
  if isinstance(slice_item, slice_module.Slice):
    parent_thread.PushSlice(slice_item)
  elif isinstance(slice_item, async_slice_module.AsyncSlice):
    parent_thread.AddAsyncSlice(slice_item)
  else:
    assert False, "Invalid Slice Item Type: %s" % type(slice_item)


class GPUTimelineTest(unittest.TestCase):
  def GetResults(self, metric, model, renderer_thread, interaction_records):
    results = test_page_test_results.TestPageTestResults(self)
    metric.AddResults(model, renderer_thread, interaction_records, results)
    return results

  def testExpectedResults(self):
    """Test a simply trace will output all expected results."""
    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    for slice_item in _CreateGPUSlices(test_thread, 'test_item', 100, 10):
      _AddSliceToThread(test_thread, slice_item)
    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for name, src_type in (('swap', None), ('total', 'cpu'), ('total', 'gpu')):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'max'), 'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'mean'), 'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'stddev'), 'ms', 0)

    for tracked_name in gpu_timeline.TRACKED_GL_CONTEXT_NAME.values():
      for source_type in ('cpu', 'gpu'):
        results.AssertHasPageSpecificScalarValue(
            gpu_timeline.TimelineName(tracked_name, source_type, 'max'),
                                      'ms', 0)
        results.AssertHasPageSpecificScalarValue(
            gpu_timeline.TimelineName(tracked_name, source_type, 'mean'),
                                      'ms', 0)
        results.AssertHasPageSpecificScalarValue(
            gpu_timeline.TimelineName(tracked_name, source_type, 'stddev'),
                                      'ms', 0)

  def testNoDeviceTraceResults(self):
    """Test expected results when missing device traces."""
    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    service_slice, _ = _CreateGPUSlices(test_thread, 'test_item', 100, 10)
    _AddSliceToThread(test_thread, service_slice)
    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for name, source_type in (('swap', None), ('total', 'cpu')):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'max'), 'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'mean'), 'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'stddev'), 'ms', 0)

    self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                      gpu_timeline.TimelineName('total', 'gpu', 'max'))
    self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                      gpu_timeline.TimelineName('total', 'gpu', 'mean'))
    self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                      gpu_timeline.TimelineName('total', 'gpu', 'stddev'))

    for name in gpu_timeline.TRACKED_GL_CONTEXT_NAME.values():
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, 'cpu', 'max'), 'ms', 0)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, 'cpu', 'mean'), 'ms', 0)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, 'cpu', 'stddev'), 'ms', 0)

      self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                        gpu_timeline.TimelineName(name, 'gpu', 'max'))
      self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                        gpu_timeline.TimelineName(name, 'gpu', 'mean'))
      self.assertRaises(AssertionError, results.GetPageSpecificValueNamed,
                        gpu_timeline.TimelineName(name, 'gpu', 'stddev'))

  def testFrameSeparation(self):
    """Test frames are correctly calculated using the frame end marker."""
    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)

    # First frame is 10 seconds.
    for slice_item in _CreateGPUSlices(test_thread, 'test_item', 100, 10):
      _AddSliceToThread(test_thread, slice_item)

    # Mark frame end.
    for slice_item in _CreateFrameEndSlices(test_thread, 105, 5):
      _AddSliceToThread(test_thread, slice_item)

    # Second frame is 20 seconds.
    for slice_item in _CreateGPUSlices(test_thread, 'test_item', 110, 20):
      _AddSliceToThread(test_thread, slice_item)

    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for name, source_type in (('swap', None),
                              ('total', 'cpu'),
                              ('total', 'gpu')):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'max'), 'ms', 20)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'mean'), 'ms', 15)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, source_type, 'stddev'), 'ms', 5)

  def testFrameSeparationBeforeMarker(self):
    """Test frames are correctly calculated using the frame end marker."""
    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)

    # Mark frame end.
    for slice_item in _CreateFrameEndSlices(test_thread, 105, 5):
      _AddSliceToThread(test_thread, slice_item)

    # First frame is 10 seconds.
    for slice_item in _CreateGPUSlices(test_thread, 'test_item', 100, 10):
      _AddSliceToThread(test_thread, slice_item)

    # Second frame is 20 seconds.
    for slice_item in _CreateGPUSlices(test_thread, 'test_item', 110, 20):
      _AddSliceToThread(test_thread, slice_item)

    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for name, src_type in (('swap', None), ('total', 'cpu'), ('total', 'gpu')):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'max'), 'ms', 20)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'mean'), 'ms', 15)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(name, src_type, 'stddev'), 'ms', 5)

  def testTrackedNameTraces(self):
    """Be sure tracked names are being recorded correctly."""
    self.assertGreater(len(gpu_timeline.TRACKED_GL_CONTEXT_NAME), 0)

    marker, result = gpu_timeline.TRACKED_GL_CONTEXT_NAME.iteritems().next()

    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    for slice_item in _CreateGPUSlices(test_thread, marker, 100, 10):
      _AddSliceToThread(test_thread, slice_item)
    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for source_type in ('cpu', 'gpu'):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'max'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'mean'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'stddev'),
          'ms', 0)

  def testTrackedNameWithContextIDTraces(self):
    """Be sure tracked names with context IDs are recorded correctly."""
    self.assertGreater(len(gpu_timeline.TRACKED_GL_CONTEXT_NAME), 0)

    marker, result = gpu_timeline.TRACKED_GL_CONTEXT_NAME.iteritems().next()
    context_id = '-0x1234'

    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    for slice_item in _CreateGPUSlices(test_thread, marker + context_id,
                                       100, 10):
      _AddSliceToThread(test_thread, slice_item)
    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for source_type in ('cpu', 'gpu'):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'max'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'mean'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result, source_type, 'stddev'),
          'ms', 0)

  def testOutOfOrderDeviceTraces(self):
    """Out of order device traces are still matched up to correct services."""
    self.assertGreaterEqual(len(gpu_timeline.TRACKED_GL_CONTEXT_NAME), 2)

    tracked_names_iter = gpu_timeline.TRACKED_GL_CONTEXT_NAME.iteritems()
    marker1_name, result1_name = tracked_names_iter.next()
    result2_name = result1_name
    while result2_name == result1_name:
      marker2_name, result2_name = tracked_names_iter.next()

    model = model_module.TimelineModel()
    test_thread = model.GetOrCreateProcess(1).GetOrCreateThread(2)

    # marker1 lasts for 10 seconds.
    service_item1, device_item1 = _CreateGPUSlices(test_thread, marker1_name,
                                                   100, 10)
    # marker2 lasts for 20 seconds.
    service_item2, device_item2 = _CreateGPUSlices(test_thread, marker2_name,
                                                   200, 20)

    # Append out of order
    _AddSliceToThread(test_thread, service_item1)
    _AddSliceToThread(test_thread, service_item2)
    _AddSliceToThread(test_thread, device_item2)
    _AddSliceToThread(test_thread, device_item1)

    model.FinalizeImport()

    metric = gpu_timeline.GPUTimelineMetric()
    results = self.GetResults(metric, model=model, renderer_thread=test_thread,
                              interaction_records=INTERACTION_RECORDS)

    for source_type in ('cpu', 'gpu'):
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result1_name, source_type, 'max'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result1_name, source_type, 'mean'),
          'ms', 10)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result1_name, source_type, 'stddev'),
          'ms', 0)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result2_name, source_type, 'max'),
          'ms', 20)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result2_name, source_type, 'mean'),
          'ms', 20)
      results.AssertHasPageSpecificScalarValue(
          gpu_timeline.TimelineName(result2_name, source_type, 'stddev'),
          'ms', 0)
