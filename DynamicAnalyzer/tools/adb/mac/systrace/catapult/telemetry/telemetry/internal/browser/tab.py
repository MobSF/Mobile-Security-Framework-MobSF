# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.internal.actions import action_runner
from telemetry.internal.browser import web_contents
from telemetry.internal.image_processing import video

DEFAULT_TAB_TIMEOUT = 60


class Tab(web_contents.WebContents):
  """Represents a tab in the browser

  The important parts of the Tab object are in the runtime and page objects.
  E.g.:
      # Navigates the tab to a given url.
      tab.Navigate('http://www.google.com/')

      # Evaluates 1+1 in the tab's JavaScript context.
      tab.Evaluate('1+1')
  """
  def __init__(self, inspector_backend, tab_list_backend, browser):
    super(Tab, self).__init__(inspector_backend)
    self._tab_list_backend = tab_list_backend
    self._browser = browser
    self._action_runner = action_runner.ActionRunner(self)

  @property
  def browser(self):
    """The browser in which this tab resides."""
    return self._browser

  @property
  def action_runner(self):
    return self._action_runner

  @property
  def url(self):
    """Returns the URL of the tab, as reported by devtools.

    Raises:
      devtools_http.DevToolsClientConnectionError
    """
    return self._inspector_backend.url

  @property
  def dom_stats(self):
    """A dictionary populated with measured DOM statistics.

    Currently this dictionary contains:
    {
      'document_count': integer,
      'node_count': integer,
      'event_listener_count': integer
    }

    Raises:
      inspector_memory.InspectorMemoryException
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    dom_counters = self._inspector_backend.GetDOMStats(
        timeout=DEFAULT_TAB_TIMEOUT)
    assert (len(dom_counters) == 3 and
            all([x in dom_counters for x in ['document_count', 'node_count',
                                             'event_listener_count']]))
    return dom_counters

  def Activate(self):
    """Brings this tab to the foreground asynchronously.

    Not all browsers or browser versions support this method.
    Be sure to check browser.supports_tab_control.

    Please note: this is asynchronous. There is a delay between this call
    and the page's documentVisibilityState becoming 'visible', and yet more
    delay until the actual tab is visible to the user. None of these delays
    are included in this call.

    Raises:
      devtools_http.DevToolsClientConnectionError
      devtools_client_backend.TabNotFoundError
      tab_list_backend.TabUnexpectedResponseException
    """
    self._tab_list_backend.ActivateTab(self.id)

  def Close(self):
    """Closes this tab.

    Not all browsers or browser versions support this method.
    Be sure to check browser.supports_tab_control.

    Raises:
      devtools_http.DevToolsClientConnectionError
      devtools_client_backend.TabNotFoundError
      tab_list_backend.TabUnexpectedResponseException
      exceptions.TimeoutException
    """
    self._tab_list_backend.CloseTab(self.id)

  @property
  def screenshot_supported(self):
    """True if the browser instance is capable of capturing screenshots."""
    return self._inspector_backend.screenshot_supported

  def Screenshot(self, timeout=DEFAULT_TAB_TIMEOUT):
    """Capture a screenshot of the tab's contents.

    Returns:
      A telemetry.core.Bitmap.
    Raises:
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.Screenshot(timeout)

  @property
  def video_capture_supported(self):
    """True if the browser instance is capable of capturing video."""
    return self.browser.platform.CanCaptureVideo()

  def Highlight(self, color):
    """Synchronously highlights entire tab contents with the given RgbaColor.

    TODO(tonyg): It is possible that the z-index hack here might not work for
    all pages. If this happens, DevTools also provides a method for this.

    Raises:
      exceptions.EvaluateException
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    screen_save = 'window.__telemetry_screen_%d' % int(color)
    self.ExecuteJavaScript("""
        (function() {
          var screen = document.createElement('div');
          screen.style.background = {{ color }};
          screen.style.position = 'fixed';
          screen.style.top = '0';
          screen.style.left = '0';
          screen.style.width = '100%';
          screen.style.height = '100%';
          screen.style.zIndex = '2147483638';
          document.body.appendChild(screen);
          requestAnimationFrame(function() {
            requestAnimationFrame(function() {
              {{ @screen_save }} = screen;
            });
          });
        })();
        """,
        color='rgba(%d, %d, %d, %d)' % (color.r, color.g, color.b, color.a),
        screen_save=screen_save)
    self.WaitForJavaScriptCondition(
        '!!{{ @screen_save }}', screen_save=screen_save, timeout=5)

  def ClearHighlight(self, color):
    """Clears a highlight of the given bitmap.RgbaColor.

    Raises:
      exceptions.EvaluateException
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    screen_save = 'window.__telemetry_screen_%d' % int(color)
    self.ExecuteJavaScript("""
        (function() {
          document.body.removeChild({{ @screen_save }});
          requestAnimationFrame(function() {
            requestAnimationFrame(function() {
              {{ @screen_save }} = null;
              console.time('__ClearHighlight.video_capture_start');
              console.timeEnd('__ClearHighlight.video_capture_start');
            });
          });
        })();
        """, screen_save=screen_save)
    self.WaitForJavaScriptCondition(
        '!{{ @screen_save }}', screen_save=screen_save, timeout=5)

  def StartVideoCapture(self, min_bitrate_mbps,
                        highlight_bitmap=video.HIGHLIGHT_ORANGE_FRAME):
    """Starts capturing video of the tab's contents.

    This works by flashing the entire tab contents to a arbitrary color and then
    starting video recording. When the frames are processed, we can look for
    that flash as the content bounds.

    Args:
      min_bitrate_mbps: The minimum caputre bitrate in MegaBits Per Second.
          The platform is free to deliver a higher bitrate if it can do so
          without increasing overhead.

    Raises:
      exceptions.EvaluateException
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
      ValueError: If the required |min_bitrate_mbps| can't be achieved.
    """
    self.Highlight(highlight_bitmap)
    self.browser.platform.StartVideoCapture(min_bitrate_mbps)
    self.ClearHighlight(highlight_bitmap)

  @property
  def is_video_capture_running(self):
    return self.browser.platform.is_video_capture_running

  def StopVideoCapture(self):
    """Stops recording video of the tab's contents.

    This looks for the initial color flash in the first frame to establish the
    tab content boundaries and then omits all frames displaying the flash.

    Returns:
      video: A video object which is a telemetry.core.Video
    """
    return self.browser.platform.StopVideoCapture()

  def GetCookieByName(self, name, timeout=DEFAULT_TAB_TIMEOUT):
    """Returns the value of the cookie by the given |name|.

    Raises:
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    return self._inspector_backend.GetCookieByName(name, timeout)

  def CollectGarbage(self):
    """Forces a garbage collection.

    Raises:
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
    """
    self._inspector_backend.CollectGarbage()

  def ClearCache(self, force):
    """Clears the browser's networking related disk, memory and other caches.

    Args:
      force: Iff true, navigates to about:blank which destroys the previous
          renderer, ensuring that even "live" resources in the memory cache are
          cleared.

    Raises:
      exceptions.EvaluateException
      exceptions.WebSocketDisconnected
      exceptions.TimeoutException
      exceptions.DevtoolsTargetCrashException
      errors.DeviceUnresponsiveError
    """
    self.browser.platform.FlushDnsCache()
    self.ExecuteJavaScript("""
        if (window.chrome && chrome.benchmarking &&
            chrome.benchmarking.clearCache) {
          chrome.benchmarking.clearCache();
          chrome.benchmarking.clearPredictorCache();
          chrome.benchmarking.clearHostResolverCache();
        }
    """)
    if force:
      self.Navigate('about:blank')
