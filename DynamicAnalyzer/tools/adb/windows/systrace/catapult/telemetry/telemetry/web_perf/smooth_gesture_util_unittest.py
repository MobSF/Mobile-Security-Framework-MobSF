# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import time
import unittest

from telemetry import decorators
from telemetry.page import page as page_module
from telemetry.page import legacy_page_test
from telemetry.testing import page_test_test_case
from telemetry.timeline import async_slice
from telemetry.timeline import model as model_module
from telemetry.timeline import tracing_config
from telemetry.web_perf import smooth_gesture_util as sg_util
from telemetry.web_perf import timeline_interaction_record as tir_module


class SmoothGestureUtilTest(unittest.TestCase):
  def testGetAdjustedInteractionIfContainGesture(self):
    model = model_module.TimelineModel()
    renderer_main = model.GetOrCreateProcess(1).GetOrCreateThread(2)
    renderer_main.name = 'CrRendererMain'

    #      [          X          ]                   [   Y  ]
    #      [  sub_async_slice_X  ]
    #          [   record_1]
    #          [   record_6]
    #  [  record_2 ]          [ record_3 ]
    #  [           record_4              ]
    #                                [ record_5 ]
    #
    # Note: X and Y are async slice with name
    # SyntheticGestureController::running

    async_slice_X = async_slice.AsyncSlice(
      'X', 'SyntheticGestureController::running', 10, duration=20,
      start_thread=renderer_main, end_thread=renderer_main)

    sub_async_slice_X = async_slice.AsyncSlice(
      'X', 'SyntheticGestureController::running', 10, duration=20,
      start_thread=renderer_main, end_thread=renderer_main)
    sub_async_slice_X.parent_slice = async_slice_X
    async_slice_X.AddSubSlice(sub_async_slice_X)

    async_slice_Y = async_slice.AsyncSlice(
      'X', 'SyntheticGestureController::running', 60, duration=20,
      start_thread=renderer_main, end_thread=renderer_main)

    renderer_main.AddAsyncSlice(async_slice_X)
    renderer_main.AddAsyncSlice(async_slice_Y)

    model.FinalizeImport(shift_world_to_zero=False)

    record_1 = tir_module.TimelineInteractionRecord('Gesture_included', 15, 25)
    record_2 = tir_module.TimelineInteractionRecord(
      'Gesture_overlapped_left', 5, 25)
    record_3 = tir_module.TimelineInteractionRecord(
      'Gesture_overlapped_right', 25, 35)
    record_4 = tir_module.TimelineInteractionRecord(
      'Gesture_containing', 5, 35)
    record_5 = tir_module.TimelineInteractionRecord(
      'Gesture_non_overlapped', 35, 45)
    record_6 = tir_module.TimelineInteractionRecord('Action_included', 15, 25)

    adjusted_record_1 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_1)
    self.assertEquals(adjusted_record_1.start, 10)
    self.assertEquals(adjusted_record_1.end, 30)
    self.assertTrue(adjusted_record_1 is not record_1)

    adjusted_record_2 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_2)
    self.assertEquals(adjusted_record_2.start, 10)
    self.assertEquals(adjusted_record_2.end, 30)

    adjusted_record_3 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_3)
    self.assertEquals(adjusted_record_3.start, 10)
    self.assertEquals(adjusted_record_3.end, 30)

    adjusted_record_4 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_4)
    self.assertEquals(adjusted_record_4.start, 10)
    self.assertEquals(adjusted_record_4.end, 30)

    adjusted_record_5 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_5)
    self.assertEquals(adjusted_record_5.start, 35)
    self.assertEquals(adjusted_record_5.end, 45)
    self.assertTrue(adjusted_record_5 is not record_5)

    adjusted_record_6 = sg_util.GetAdjustedInteractionIfContainGesture(
      model, record_6)
    self.assertEquals(adjusted_record_6.start, 15)
    self.assertEquals(adjusted_record_6.end, 25)
    self.assertTrue(adjusted_record_6 is not record_6)


class ScrollingPage(page_module.Page):
  def __init__(self, url, page_set, base_dir):
    super(ScrollingPage, self).__init__(url, page_set, base_dir)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      # Add 0.5s gap between when Gesture records are issued to when we actually
      # scroll the page.
      time.sleep(0.5)
      action_runner.ScrollPage()
      time.sleep(0.5)


class SmoothGestureTest(page_test_test_case.PageTestTestCase):

  @decorators.Disabled('chromeos')  # crbug.com/483212
  @decorators.Isolated  # Needed because of py_trace_event
  def testSmoothGestureAdjusted(self):
    ps = self.CreateEmptyPageSet()
    ps.AddStory(ScrollingPage(
      'file://scrollable_page.html', ps, base_dir=ps.base_dir))
    models = []
    tab_ids = []
    class ScrollingGestureTestMeasurement(legacy_page_test.LegacyPageTest):
      def __init__(self):
        # pylint: disable=bad-super-call
        super(ScrollingGestureTestMeasurement, self).__init__()

      def WillNavigateToPage(self, page, tab):
        del page  # unused
        config = tracing_config.TracingConfig()
        config.enable_chrome_trace = True
        tab.browser.platform.tracing_controller.StartTracing(config)

      def ValidateAndMeasurePage(self, page, tab, results):
        del page, results  # unused
        models.append(model_module.TimelineModel(
          tab.browser.platform.tracing_controller.StopTracing()))
        tab_ids.append(tab.id)

    self.RunMeasurement(ScrollingGestureTestMeasurement(), ps)
    timeline_model = models[0]
    renderer_thread = timeline_model.GetRendererThreadFromTabId(
        tab_ids[0])
    smooth_record = None
    for e in renderer_thread.async_slices:
      if tir_module.IsTimelineInteractionRecord(e.name):
        smooth_record = tir_module.TimelineInteractionRecord.FromAsyncEvent(e)
    self.assertIsNotNone(smooth_record)
    adjusted_smooth_gesture = (
      sg_util.GetAdjustedInteractionIfContainGesture(
        timeline_model, smooth_record))
    # Test that the scroll gesture starts at at least 500ms after the start of
    # the interaction record and ends at at least 500ms before the end of
    # interaction record.
    self.assertLessEqual(
      500, adjusted_smooth_gesture.start - smooth_record.start)
    self.assertLessEqual(
      500, smooth_record.end - adjusted_smooth_gesture.end)
