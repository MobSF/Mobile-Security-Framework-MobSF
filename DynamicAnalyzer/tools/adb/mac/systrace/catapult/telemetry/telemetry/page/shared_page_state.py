# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import sys

from telemetry.core import exceptions
from telemetry.core import util
from telemetry import decorators
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_finder_exceptions
from telemetry.internal.browser import browser_info as browser_info_module
from telemetry.internal.platform.profiler import profiler_finder
from telemetry.internal.util import exception_formatter
from telemetry.internal.util import file_handle
from telemetry.page import cache_temperature
from telemetry.page import traffic_setting
from telemetry.page import legacy_page_test
from telemetry import story
from telemetry.util import screenshot
from telemetry.util import wpr_modes
from telemetry.web_perf import timeline_based_measurement


def _PrepareFinderOptions(finder_options, test, device_type):
  browser_options = finder_options.browser_options
  # Set up user agent.
  browser_options.browser_user_agent_type = device_type

  test.CustomizeBrowserOptions(finder_options.browser_options)
  if finder_options.profiler:
    profiler_class = profiler_finder.FindProfiler(finder_options.profiler)
    profiler_class.CustomizeBrowserOptions(browser_options.browser_type,
                                           finder_options)


class SharedPageState(story.SharedState):
  """
  This class contains all specific logic necessary to run a Chrome browser
  benchmark.
  """

  _device_type = None

  def __init__(self, test, finder_options, story_set):
    super(SharedPageState, self).__init__(test, finder_options, story_set)
    if isinstance(test, timeline_based_measurement.TimelineBasedMeasurement):
      if finder_options.profiler:
        assert not 'trace' in finder_options.profiler, (
            'This is a Timeline Based Measurement benchmark. You cannot run it '
            'with trace profiler enabled. If you need trace data, tracing is '
            'always enabled in Timeline Based Measurement benchmarks and you '
            'can get the trace data by adding --output-format=json.')
      # This is to avoid the cyclic-import caused by timeline_based_page_test.
      from telemetry.web_perf import timeline_based_page_test
      self._test = timeline_based_page_test.TimelineBasedPageTest(test)
    else:
      self._test = test
    _PrepareFinderOptions(finder_options, self._test, self._device_type)
    self._browser = None
    self._finder_options = finder_options
    self._possible_browser = self._GetPossibleBrowser(
        self._test, finder_options)

    self._first_browser = True
    self._did_login_for_current_page = False
    self._previous_page = None
    self._current_page = None
    self._current_tab = None

    self._test.SetOptions(self._finder_options)

    # TODO(crbug/404771): Move network controller options out of
    # browser_options and into finder_options.
    browser_options = self._finder_options.browser_options
    if self._finder_options.use_live_sites:
      wpr_mode = wpr_modes.WPR_OFF
    elif browser_options.wpr_mode == wpr_modes.WPR_RECORD:
      wpr_mode = wpr_modes.WPR_RECORD
    else:
      wpr_mode = wpr_modes.WPR_REPLAY

    use_live_traffic = wpr_mode == wpr_modes.WPR_OFF

    if self.platform.network_controller.is_open:
      self.platform.network_controller.Close()
    self.platform.network_controller.InitializeIfNeeded(
        use_live_traffic=use_live_traffic)
    self.platform.network_controller.Open(wpr_mode,
                                          browser_options.extra_wpr_args)
    self.platform.Initialize()

  @property
  def possible_browser(self):
    return self._possible_browser

  @property
  def browser(self):
    return self._browser

  def _FindBrowser(self, finder_options):
    possible_browser = browser_finder.FindBrowser(finder_options)
    if not possible_browser:
      raise browser_finder_exceptions.BrowserFinderException(
          'No browser found.\n\nAvailable browsers:\n%s\n' %
          '\n'.join(browser_finder.GetAllAvailableBrowserTypes(finder_options)))
    return possible_browser

  def _GetPossibleBrowser(self, test, finder_options):
    """Return a possible_browser with the given options for |test|. """
    possible_browser = self._FindBrowser(finder_options)
    finder_options.browser_options.browser_type = (
        possible_browser.browser_type)

    enabled, msg = decorators.IsEnabled(test, possible_browser)
    if not enabled and not finder_options.run_disabled_tests:
      logging.warning(msg)
      logging.warning('You are trying to run a disabled test.')

    if possible_browser.IsRemote():
      possible_browser.RunRemote()
      sys.exit(0)
    return possible_browser

  def DumpStateUponFailure(self, page, results):
    # Dump browser standard output and log.
    if self._browser:
      self._browser.DumpStateUponFailure()
    else:
      logging.warning('Cannot dump browser state: No browser.')

    # Capture a screenshot
    if self._finder_options.browser_options.take_screenshot_for_failed_page:
      fh = screenshot.TryCaptureScreenShot(self.platform, self._current_tab)
      if fh is not None:
        results.AddProfilingFile(page, fh)
    else:
      logging.warning('Taking screenshots upon failures disabled.')

  def DidRunStory(self, results):
    if self._finder_options.profiler:
      self._StopProfiling(results)
    # We might hang while trying to close the connection, and need to guarantee
    # the page will get cleaned up to avoid future tests failing in weird ways.
    try:
      if self._current_tab and self._current_tab.IsAlive():
        self._current_tab.CloseConnections()
      self._previous_page = self._current_page
    except Exception:
      if self._current_tab:
        self._current_tab.Close()
    finally:
      if self._current_page.credentials and self._did_login_for_current_page:
        self.browser.credentials.LoginNoLongerNeeded(
            self._current_tab, self._current_page.credentials)
      if self._test.StopBrowserAfterPage(self.browser, self._current_page):
        self._StopBrowser()
      self._current_page = None
      self._current_tab = None

  @property
  def platform(self):
    return self._possible_browser.platform

  def _StartBrowser(self, page):
    assert self._browser is None
    self._possible_browser.SetCredentialsPath(page.credentials_path)

    self._test.WillStartBrowser(self.platform)
    if page.startup_url:
      self._finder_options.browser_options.startup_url = page.startup_url
    self._browser = self._possible_browser.Create(self._finder_options)
    self._test.DidStartBrowser(self.browser)

    if self._first_browser:
      self._first_browser = False
      self.browser.credentials.WarnIfMissingCredentials(page)

  def WillRunStory(self, page):
    if not self.platform.tracing_controller.is_tracing_running:
      # For TimelineBasedMeasurement benchmarks, tracing has already started.
      # For PageTest benchmarks, tracing has not yet started. We need to make
      # sure no tracing state is left before starting the browser for PageTest
      # benchmarks.
      self.platform.tracing_controller.ClearStateIfNeeded()

    page_set = page.page_set
    self._current_page = page
    if self._browser and (self._test.RestartBrowserBeforeEachPage()
                          or page.startup_url):
      assert not self.platform.tracing_controller.is_tracing_running, (
          'Should not restart browser when tracing is already running. For '
          'TimelineBasedMeasurement (TBM) benchmarks, you should not use '
          'startup_url. Use benchmark.ShouldTearDownStateAfterEachStoryRun '
          'instead.')
      self._StopBrowser()
    started_browser = not self.browser

    archive_path = page_set.WprFilePathForStory(page, self.platform.GetOSName())
    # TODO(nednguyen, perezju): Ideally we should just let the network
    # controller raise an exception when the archive_path is not found.
    if archive_path is not None and not os.path.isfile(archive_path):
      logging.warning('WPR archive missing: %s', archive_path)
      archive_path = None
    self.platform.network_controller.StartReplay(
        archive_path, page.make_javascript_deterministic)

    if self.browser:
      # Set new credential path for browser.
      self.browser.credentials.credentials_path = page.credentials_path
    else:
      self._StartBrowser(page)
    if self.browser.supports_tab_control and self._test.close_tabs_before_run:
      # Create a tab if there's none.
      if len(self.browser.tabs) == 0:
        self.browser.tabs.New()

      # Ensure only one tab is open, unless the test is a multi-tab test.
      if not self._test.is_multi_tab_test:
        while len(self.browser.tabs) > 1:
          self.browser.tabs[-1].Close()

      # Must wait for tab to commit otherwise it can commit after the next
      # navigation has begun and RenderFrameHostManager::DidNavigateMainFrame()
      # will cancel the next navigation because it's pending. This manifests as
      # the first navigation in a PageSet freezing indefinitely because the
      # navigation was silently canceled when |self.browser.tabs[0]| was
      # committed. Only do this when we just started the browser, otherwise
      # there are cases where previous pages in a PageSet never complete
      # loading so we'll wait forever.
      if started_browser:
        self.browser.tabs[0].WaitForDocumentReadyStateToBeComplete()

    # Reset traffic shaping to speed up cache temperature setup.
    self.platform.network_controller.UpdateTrafficSettings(0, 0, 0)
    cache_temperature.EnsurePageCacheTemperature(
        self._current_page, self.browser, self._previous_page)
    if self._current_page.traffic_setting != traffic_setting.NONE:
      s = traffic_setting.NETWORK_CONFIGS[self._current_page.traffic_setting]
      self.platform.network_controller.UpdateTrafficSettings(
          round_trip_latency_ms=s.round_trip_latency_ms,
          download_bandwidth_kbps=s.download_bandwidth_kbps,
          upload_bandwidth_kbps=s.upload_bandwidth_kbps)

    # Start profiling if needed.
    if self._finder_options.profiler:
      self._StartProfiling(self._current_page)

  def CanRunStory(self, page):
    return self.CanRunOnBrowser(browser_info_module.BrowserInfo(self.browser),
                                page)

  def CanRunOnBrowser(self, browser_info,
                      page):  # pylint: disable=unused-argument
    """Override this to return whether the browser brought up by this state
    instance is suitable for running the given page.

    Args:
      browser_info: an instance of telemetry.core.browser_info.BrowserInfo
      page: an instance of telemetry.page.Page
    """
    del browser_info, page  # unused
    return True

  def _PreparePage(self):
    self._current_tab = self._test.TabForPage(self._current_page, self.browser)
    if self._current_page.is_file:
      self.platform.SetHTTPServerDirectories(
          self._current_page.page_set.serving_dirs |
          set([self._current_page.serving_dir]))

    if self._current_page.credentials:
      if not self.browser.credentials.LoginNeeded(
          self._current_tab, self._current_page.credentials):
        raise legacy_page_test.Failure(
            'Login as ' + self._current_page.credentials + ' failed')
      self._did_login_for_current_page = True

    if self._test.clear_cache_before_each_run:
      self._current_tab.ClearCache(force=True)

  @property
  def current_page(self):
    return self._current_page

  @property
  def current_tab(self):
    return self._current_tab

  @property
  def page_test(self):
    return self._test

  def RunStory(self, results):
    try:
      self._PreparePage()
      self._current_page.Run(self)
      self._test.ValidateAndMeasurePage(
          self._current_page, self._current_tab, results)
    except exceptions.Error:
      if self._test.is_multi_tab_test:
        # Avoid trying to recover from an unknown multi-tab state.
        exception_formatter.PrintFormattedException(
            msg='Telemetry Error during multi tab test:')
        raise legacy_page_test.MultiTabTestAppCrashError
      raise

  def TearDownState(self):
    self._StopBrowser()
    self.platform.StopAllLocalServers()
    self.platform.network_controller.Close()

  def _StopBrowser(self):
    if self._browser:
      self._browser.Close()
      self._browser = None

  def _StartProfiling(self, page):
    output_file = os.path.join(self._finder_options.output_dir,
                               page.file_safe_name)
    if self._finder_options.pageset_repeat != 1:
      output_file = util.GetSequentialFileName(output_file)
    self.browser.profiling_controller.Start(
        self._finder_options.profiler, output_file)

  def _StopProfiling(self, results):
    if self.browser:
      profiler_files = self.browser.profiling_controller.Stop()
      for f in profiler_files:
        if os.path.isfile(f):
          results.AddProfilingFile(self._current_page,
                                   file_handle.FromFilePath(f))


class SharedMobilePageState(SharedPageState):
  _device_type = 'mobile'


class SharedDesktopPageState(SharedPageState):
  _device_type = 'desktop'


class SharedTabletPageState(SharedPageState):
  _device_type = 'tablet'


class Shared10InchTabletPageState(SharedPageState):
  _device_type = 'tablet_10_inch'
