# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from py_trace_event import trace_event

from telemetry.core import exceptions
from telemetry.internal.actions import action_runner as action_runner_module

# Export story_test.Failure to this page_test module
from telemetry.web_perf.story_test import Failure


class TestNotSupportedOnPlatformError(Exception):
  """LegacyPageTest Exception raised when a required feature is unavailable.

  The feature required to run the test could be part of the platform,
  hardware configuration, or browser.
  """


class MultiTabTestAppCrashError(Exception):
  """Exception raised after browser or tab crash for multi-tab tests.

  Used to abort the test rather than try to recover from an unknown state.
  """


class MeasurementFailure(Failure):
  """Exception raised when an undesired but designed-for problem."""


class LegacyPageTest(object):
  """A class styled on unittest.TestCase for creating page-specific tests.

  Note that this method of measuring browser's performance is obsolete and only
  here for "historical" reason. For your performance measurement need, please
  use TimelineBasedMeasurement instead: https://goo.gl/eMvikK

  For correctness testing, please use
  serially_executed_browser_test_case.SeriallyExecutedBrowserTestCase
  instead. See examples in:
  https://github.com/catapult-project/catapult/tree/master/telemetry/examples/browser_tests

  Test should override ValidateAndMeasurePage to perform test
  validation and page measurement as necessary.

     class BodyChildElementMeasurement(LegacyPageTest):
       def ValidateAndMeasurePage(self, page, tab, results):
         body_child_count = tab.EvaluateJavaScript(
             'document.body.children.length')
         results.AddValue(scalar.ScalarValue(
             page, 'body_children', 'count', body_child_count))
  """

  __metaclass__ = trace_event.TracedMetaClass

  def __init__(self,
               needs_browser_restart_after_each_page=False,
               clear_cache_before_each_run=False):
    super(LegacyPageTest, self).__init__()

    self.options = None
    self._needs_browser_restart_after_each_page = (
        needs_browser_restart_after_each_page)
    self._clear_cache_before_each_run = clear_cache_before_each_run
    self._close_tabs_before_run = True

  @property
  def is_multi_tab_test(self):
    """Returns True if the test opens multiple tabs.

    If the test overrides TabForPage, it is deemed a multi-tab test.
    Multi-tab tests do not retry after tab or browser crashes, whereas,
    single-tab tests too. That is because the state of multi-tab tests
    (e.g., how many tabs are open, etc.) is unknown after crashes.
    """
    return self.TabForPage.__func__ is not LegacyPageTest.TabForPage.__func__

  @property
  def clear_cache_before_each_run(self):
    """When set to True, the browser's disk and memory cache will be cleared
    before each run."""
    return self._clear_cache_before_each_run

  @property
  def close_tabs_before_run(self):
    """When set to True, all tabs are closed before running the test for the
    first time."""
    return self._close_tabs_before_run

  @close_tabs_before_run.setter
  def close_tabs_before_run(self, close_tabs):
    self._close_tabs_before_run = close_tabs

  def RestartBrowserBeforeEachPage(self):
    """ Should the browser be restarted for the page?

    This returns true if the test needs to unconditionally restart the
    browser for each page. It may be called before the browser is started.
    """
    return self._needs_browser_restart_after_each_page

  def StopBrowserAfterPage(self, browser, page):
    """Should the browser be stopped after the page is run?

    This is called after a page is run to decide whether the browser needs to
    be stopped to clean up its state. If it is stopped, then it will be
    restarted to run the next page.

    A test that overrides this can look at both the page and the browser to
    decide whether it needs to stop the browser.
    """
    del browser, page  # unused
    return False

  def CustomizeBrowserOptions(self, options):
    """Override to add test-specific options to the BrowserOptions object"""

  def WillStartBrowser(self, platform):
    """Override to manipulate the browser environment before it launches."""

  def DidStartBrowser(self, browser):
    """Override to customize the browser right after it has launched."""

  def SetOptions(self, options):
    """Sets the BrowserFinderOptions instance to use."""
    self.options = options

  def WillNavigateToPage(self, page, tab):
    """Override to do operations before the page is navigated, notably Telemetry
    will already have performed the following operations on the browser before
    calling this function:
    * Ensure only one tab is open.
    * Call WaitForDocumentReadyStateToComplete on the tab."""

  def DidNavigateToPage(self, page, tab):
    """Override to do operations right after the page is navigated and after
    all waiting for completion has occurred."""

  def DidRunPage(self, platform):
    """Called after the test run method was run, even if it failed."""

  def TabForPage(self, page, browser):   # pylint: disable=unused-argument
    """Override to select a different tab for the page.  For instance, to
    create a new tab for every page, return browser.tabs.New()."""
    try:
      return browser.tabs[0]
    # The tab may have gone away in some case, so we create a new tab and retry
    # (See crbug.com/496280)
    except exceptions.DevtoolsTargetCrashException as e:
      logging.error('Tab may have crashed: %s' % str(e))
      browser.tabs.New()
      # See comment in shared_page_state.WillRunStory for why this waiting
      # is needed.
      browser.tabs[0].WaitForDocumentReadyStateToBeComplete()
      return browser.tabs[0]

  def ValidateAndMeasurePage(self, page, tab, results):
    """Override to check test assertions and perform measurement.

    When adding measurement results, call results.AddValue(...) for
    each result. Raise an exception or add a failure.FailureValue on
    failure. legacy_page_test.py also provides several base exception classes
    to use.

    Prefer metric value names that are in accordance with python
    variable style. e.g., metric_name. The name 'url' must not be used.

    Put together:
      def ValidateAndMeasurePage(self, page, tab, results):
        res = tab.EvaluateJavaScript('2+2')
        if res != 4:
          raise Exception('Oh, wow.')
        results.AddValue(scalar.ScalarValue(
            page, 'two_plus_two', 'count', res))

    Args:
      page: A telemetry.page.Page instance.
      tab: A telemetry.core.Tab instance.
      results: A telemetry.results.PageTestResults instance.
    """
    raise NotImplementedError

  # Deprecated: do not use this hook. (crbug.com/470147)
  def RunNavigateSteps(self, page, tab):
    """Navigates the tab to the page URL attribute.

    Runs the 'navigate_steps' page attribute as a compound action.
    """
    action_runner = action_runner_module.ActionRunner(
        tab, skip_waits=page.skip_waits)
    page.RunNavigateSteps(action_runner)
