# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import mock
import unittest

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.internal.actions import action_runner as action_runner_module
from telemetry.internal.actions import page_action
from telemetry.testing import tab_test_case
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import model
from telemetry.timeline import tracing_config
from telemetry.web_perf import timeline_interaction_record as tir_module

import py_utils


class ActionRunnerInteractionTest(tab_test_case.TabTestCase):

  def GetInteractionRecords(self, trace_data):
    timeline_model = model.TimelineModel(trace_data)
    renderer_thread = timeline_model.GetRendererThreadFromTabId(self._tab.id)
    return [
        tir_module.TimelineInteractionRecord.FromAsyncEvent(e)
        for e in renderer_thread.async_slices
        if tir_module.IsTimelineInteractionRecord(e.name)
        ]

  def VerifyIssuingInteractionRecords(self, **interaction_kwargs):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('interaction_enabled_page.html')
    action_runner.Wait(1)
    config = tracing_config.TracingConfig()
    config.chrome_trace_config.SetLowOverheadFilter()
    config.enable_chrome_trace = True
    self._browser.platform.tracing_controller.StartTracing(config)
    with action_runner.CreateInteraction('InteractionName',
                                                 **interaction_kwargs):
      pass
    trace_data = self._browser.platform.tracing_controller.StopTracing()

    records = self.GetInteractionRecords(trace_data)
    self.assertEqual(
        1, len(records),
        'Failed to issue the interaction record on the tracing timeline.'
        ' Trace data:\n%s' % repr(trace_data._raw_data))
    self.assertEqual('InteractionName', records[0].label)
    for attribute_name in interaction_kwargs:
      self.assertTrue(getattr(records[0], attribute_name))

  # Test disabled for android: crbug.com/437057
  # Test disabled for linux: crbug.com/513874
  @decorators.Disabled('android', 'chromeos', 'linux')
  def testIssuingMultipleMeasurementInteractionRecords(self):
    self.VerifyIssuingInteractionRecords(repeatable=True)


class ActionRunnerMeasureMemoryTest(tab_test_case.TabTestCase):
  def setUp(self):
    super(ActionRunnerMeasureMemoryTest, self).setUp()
    self.action_runner = action_runner_module.ActionRunner(self._tab,
                                                           skip_waits=True)
    self.Navigate('blank.html')

  def testWithoutTracing(self):
    with mock.patch.object(self._tab.browser, 'DumpMemory') as mock_method:
      self.assertIsNone(self.action_runner.MeasureMemory())
      self.assertFalse(mock_method.called)  # No-op with no tracing.

  def _testWithTracing(self, deterministic_mode=False):
    trace_memory = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        filter_string='-*,blink.console,disabled-by-default-memory-infra')
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    config.chrome_trace_config.SetCategoryFilter(trace_memory)
    self._browser.platform.tracing_controller.StartTracing(config)
    try:
      dump_id = self.action_runner.MeasureMemory(deterministic_mode)
    finally:
      trace_data = self._browser.platform.tracing_controller.StopTracing()

    # If successful, i.e. we haven't balied out due to an exception, check
    # that we can find our dump in the trace.
    self.assertIsNotNone(dump_id)
    timeline_model = model.TimelineModel(trace_data)
    dump_ids = (d.dump_id for d in timeline_model.IterGlobalMemoryDumps())
    self.assertIn(dump_id, dump_ids)

  # TODO(perezju): Enable when reference browser is >= M53
  # https://github.com/catapult-project/catapult/issues/2610
  @decorators.Disabled('reference')
  def testDeterministicMode(self):
    self._testWithTracing(deterministic_mode=True)

  # TODO(perezju): Enable when reference browser is >= M53
  # https://github.com/catapult-project/catapult/issues/2610
  @decorators.Disabled('reference')
  def testRealisticMode(self):
    with mock.patch.object(
        self.action_runner, 'ForceGarbageCollection') as mock_method:
      self._testWithTracing(deterministic_mode=False)
      self.assertFalse(mock_method.called)  # No forced GC in "realistic" mode.

  def testWithFailedDump(self):
    with mock.patch.object(self._tab.browser, 'DumpMemory') as mock_method:
      mock_method.return_value = False  # Dump fails!
      with self.assertRaises(exceptions.Error):
        self._testWithTracing()


class ActionRunnerTest(tab_test_case.TabTestCase):
  def testExecuteJavaScript(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('blank.html')
    action_runner.ExecuteJavaScript('var testing = 42;')
    self.assertEqual(42, self._tab.EvaluateJavaScript('testing'))

  def testWaitForNavigate(self):
    self.Navigate('page_with_link.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    action_runner.ClickElement('#clickme')
    action_runner.WaitForNavigate()

    self.assertTrue(self._tab.EvaluateJavaScript(
        'document.readyState == "interactive" || '
        'document.readyState == "complete"'))
    self.assertEqual(
        self._tab.EvaluateJavaScript('document.location.pathname;'),
        '/blank.html')

  def testNavigateBack(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('page_with_link.html')
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/page_with_link.html"')

    # Test that after 3 navigations & 3 back navs, we have to be back at the
    # initial page
    self.Navigate('page_with_swipeables.html')
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/page_with_swipeables.html"')

    self.Navigate('blank.html')
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/blank.html"')

    self.Navigate('page_with_swipeables.html')
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/page_with_swipeables.html"')

    action_runner.NavigateBack()
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/blank.html"')

    action_runner.NavigateBack()
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/page_with_swipeables.html"')

    action_runner.NavigateBack()
    action_runner.WaitForJavaScriptCondition(
        'document.location.pathname === "/page_with_link.html"')

  def testWait(self):
    action_runner = action_runner_module.ActionRunner(self._tab)
    self.Navigate('blank.html')

    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() { window.testing = 101; }, 50);')
    action_runner.Wait(0.1)
    self.assertEqual(101, self._tab.EvaluateJavaScript('window.testing'))

    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() { window.testing = 102; }, 100);')
    action_runner.Wait(0.2)
    self.assertEqual(102, self._tab.EvaluateJavaScript('window.testing'))

  def testWaitForJavaScriptCondition(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('blank.html')

    action_runner.ExecuteJavaScript('window.testing = 219;')
    action_runner.WaitForJavaScriptCondition(
        'window.testing == 219', timeout=0.1)
    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() { window.testing = 220; }, 50);')
    action_runner.WaitForJavaScriptCondition(
        'window.testing == 220', timeout=0.1)
    self.assertEqual(220, self._tab.EvaluateJavaScript('window.testing'))

  def testWaitForJavaScriptCondition_returnsValue(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('blank.html')

    action_runner.ExecuteJavaScript('window.testing = 0;')
    action_runner.WaitForJavaScriptCondition(
        'window.testing == 0', timeout=0.1)
    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() { window.testing = 42; }, 50);')
    self.assertEqual(
        42,
        action_runner.WaitForJavaScriptCondition('window.testing', timeout=10))

  def testWaitForElement(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('blank.html')

    action_runner.ExecuteJavaScript(
        '(function() {'
        '  var el = document.createElement("div");'
        '  el.id = "test1";'
        '  el.textContent = "foo";'
        '  document.body.appendChild(el);'
        '})()')
    action_runner.WaitForElement('#test1', timeout_in_seconds=0.1)
    action_runner.WaitForElement(text='foo', timeout_in_seconds=0.1)
    action_runner.WaitForElement(
        element_function='document.getElementById("test1")')
    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() {'
        '  var el = document.createElement("div");'
        '  el.id = "test2";'
        '  document.body.appendChild(el);'
        '}, 50)')
    action_runner.WaitForElement('#test2', timeout_in_seconds=0.1)
    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() {'
        '  document.getElementById("test2").textContent = "bar";'
        '}, 50)')
    action_runner.WaitForElement(text='bar', timeout_in_seconds=0.1)
    action_runner.ExecuteJavaScript(
        'window.setTimeout(function() {'
        '  var el = document.createElement("div");'
        '  el.id = "test3";'
        '  document.body.appendChild(el);'
        '}, 50)')
    action_runner.WaitForElement(
        element_function='document.getElementById("test3")')

  def testWaitForElementWithWrongText(self):
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    self.Navigate('blank.html')

    action_runner.ExecuteJavaScript(
        '(function() {'
        '  var el = document.createElement("div");'
        '  el.id = "test1";'
        '  el.textContent = "foo";'
        '  document.body.appendChild(el);'
        '})()')
    action_runner.WaitForElement('#test1', timeout_in_seconds=0.2)
    def WaitForElement():
      action_runner.WaitForElement(text='oo', timeout_in_seconds=0.2)
    self.assertRaises(py_utils.TimeoutException, WaitForElement)

  def testClickElement(self):
    self.Navigate('page_with_clickables.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)

    action_runner.ExecuteJavaScript('valueSettableByTest = 1;')
    action_runner.ClickElement('#test')
    self.assertEqual(1, action_runner.EvaluateJavaScript('valueToTest'))

    action_runner.ExecuteJavaScript('valueSettableByTest = 2;')
    action_runner.ClickElement(text='Click/tap me')
    self.assertEqual(2, action_runner.EvaluateJavaScript('valueToTest'))

    action_runner.ExecuteJavaScript('valueSettableByTest = 3;')
    action_runner.ClickElement(
        element_function='document.body.firstElementChild;')
    self.assertEqual(3, action_runner.EvaluateJavaScript('valueToTest'))

    def WillFail():
      action_runner.ClickElement('#notfound')
    self.assertRaises(exceptions.EvaluateException, WillFail)

  @decorators.Disabled('android', 'debug',  # crbug.com/437068
                       'chromeos',          # crbug.com/483212
                       'win')               # catapult/issues/2282
  def testTapElement(self):
    self.Navigate('page_with_clickables.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)

    action_runner.ExecuteJavaScript('valueSettableByTest = 1;')
    action_runner.TapElement('#test')
    self.assertEqual(1, action_runner.EvaluateJavaScript('valueToTest'))

    action_runner.ExecuteJavaScript('valueSettableByTest = 2;')
    action_runner.TapElement(text='Click/tap me')
    self.assertEqual(2, action_runner.EvaluateJavaScript('valueToTest'))

    action_runner.ExecuteJavaScript('valueSettableByTest = 3;')
    action_runner.TapElement(
        element_function='document.body.firstElementChild')
    self.assertEqual(3, action_runner.EvaluateJavaScript('valueToTest'))

    def WillFail():
      action_runner.TapElement('#notfound')
    self.assertRaises(exceptions.EvaluateException, WillFail)

  # https://github.com/catapult-project/catapult/issues/3099
  @decorators.Disabled('android')
  def testScrollToElement(self):
    self.Navigate('page_with_swipeables.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)

    off_screen_element = 'document.querySelectorAll("#off-screen")[0]'
    top_bottom_element = 'document.querySelector("#top-bottom")'

    def viewport_comparator(element):
      return action_runner.EvaluateJavaScript('''
          (function(elem) {
            var rect = elem.getBoundingClientRect();

            if (rect.bottom < 0) {
              // The bottom of the element is above the viewport.
              return -1;
            }
            if (rect.top - window.innerHeight > 0) {
              // rect.top provides the pixel offset of the element from the
              // top of the page. Because that exceeds the viewport's height,
              // we know that the element is below the viewport.
              return 1;
            }
            return 0;
          })({{ @element }});
          ''', element=element)


    self.assertEqual(viewport_comparator(off_screen_element), 1)
    action_runner.ScrollPageToElement(selector='#off-screen',
                                      speed_in_pixels_per_second=5000)
    self.assertEqual(viewport_comparator(off_screen_element), 0)

    self.assertEqual(viewport_comparator(top_bottom_element), -1)
    action_runner.ScrollPageToElement(selector='#top-bottom',
                                      container_selector='body',
                                      speed_in_pixels_per_second=5000)
    self.assertEqual(viewport_comparator(top_bottom_element), 0)

  @decorators.Disabled('android',   # crbug.com/437065.
                       'chromeos')  # crbug.com/483212.
  def testScroll(self):
    if not page_action.IsGestureSourceTypeSupported(
        self._tab, 'touch'):
      return

    self.Navigate('page_with_swipeables.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)

    action_runner.ScrollElement(
        selector='#left-right', direction='right', left_start_ratio=0.9)
    self.assertTrue(action_runner.EvaluateJavaScript(
        'document.querySelector("#left-right").scrollLeft') > 75)
    action_runner.ScrollElement(
        selector='#top-bottom', direction='down', top_start_ratio=0.9)
    self.assertTrue(action_runner.EvaluateJavaScript(
        'document.querySelector("#top-bottom").scrollTop') > 75)

    action_runner.ScrollPage(direction='right', left_start_ratio=0.9,
                             distance=100)
    self.assertTrue(action_runner.EvaluateJavaScript(
        '(document.scrollingElement || document.body).scrollLeft') > 75)

  @decorators.Disabled('android',   # crbug.com/437065.
                       'chromeos')  # crbug.com/483212.
  def testSwipe(self):
    if not page_action.IsGestureSourceTypeSupported(
        self._tab, 'touch'):
      return

    self.Navigate('page_with_swipeables.html')
    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)

    action_runner.SwipeElement(
        selector='#left-right', direction='left', left_start_ratio=0.9)
    self.assertTrue(action_runner.EvaluateJavaScript(
        'document.querySelector("#left-right").scrollLeft') > 75)
    action_runner.SwipeElement(
        selector='#top-bottom', direction='up', top_start_ratio=0.9)
    self.assertTrue(action_runner.EvaluateJavaScript(
        'document.querySelector("#top-bottom").scrollTop') > 75)

    action_runner.SwipePage(direction='left', left_start_ratio=0.9)
    self.assertTrue(action_runner.EvaluateJavaScript(
        '(document.scrollingElement || document.body).scrollLeft') > 75)

  def testWaitForNetworkQuiescenceSmoke(self):
    self.Navigate('blank.html')
    action_runner = action_runner_module.ActionRunner(self._tab)
    action_runner.WaitForNetworkQuiescence()
    self.assertEqual(
        self._tab.EvaluateJavaScript('document.location.pathname;'),
        '/blank.html')

  def testEnterText(self):
    self.Navigate('blank.html')
    self._tab.ExecuteJavaScript(
        '(function() {'
        '  var elem = document.createElement("textarea");'
        '  document.body.appendChild(elem);'
        '  elem.focus();'
        '})();')

    action_runner = action_runner_module.ActionRunner(self._tab,
                                                      skip_waits=True)
    action_runner.EnterText('That is boring')  # That is boring|.
    action_runner.PressKey('Home')  # |That is boring.
    action_runner.PressKey('ArrowRight', repeat_count=2)  # Th|at is boring.
    action_runner.PressKey('Delete', repeat_count=2)  # Th| is boring.
    action_runner.EnterText('is')  # This| is boring.
    action_runner.PressKey('End')  # This is boring|.
    action_runner.PressKey('ArrowLeft', repeat_count=3)  # This is bor|ing.
    action_runner.PressKey('Backspace', repeat_count=3)  # This is |ing.
    action_runner.EnterText('interest')  # This is interest|ing.

    # Check that the contents of the textarea is correct. It might take a second
    # until all keystrokes have been handled by the browser (crbug.com/630017).
    self._tab.WaitForJavaScriptCondition(
        'document.querySelector("textarea").value === "This is interesting"',
        timeout=1)


class InteractionTest(unittest.TestCase):

  def setUp(self):
    self.mock_action_runner = mock.Mock(action_runner_module.ActionRunner)

    def expected_js_call(method):
      return mock.call.ExecuteJavaScript(
          '%s({{ marker }});' % method, marker='Interaction.ABC')

    self.expected_calls = [
        expected_js_call('console.time'),
        expected_js_call('console.timeEnd')]

  def testIssuingInteractionRecordCommand(self):
    with action_runner_module.Interaction(
        self.mock_action_runner, label='ABC', flags=[]):
      pass
    self.assertEqual(self.expected_calls, self.mock_action_runner.mock_calls)

  def testExceptionRaisedInWithInteraction(self):
    class FooException(Exception):
      pass
    # Test that the Foo exception raised in the with block is propagated to the
    # caller.
    with self.assertRaises(FooException):
      with action_runner_module.Interaction(
          self.mock_action_runner, label='ABC', flags=[]):
        raise FooException()

    # Test that the end console.timeEnd(...) isn't called because exception was
    # raised.
    self.assertEqual(
        self.expected_calls[:1], self.mock_action_runner.mock_calls)
