# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

_check_webgl_supported_script = """
(function () {
  var c = document.createElement('canvas');
  var gl = c.getContext('webgl', { failIfMajorPerformanceCaveat: true });
  if (gl == null) {
    gl = c.getContext('experimental-webgl',
        { failIfMajorPerformanceCaveat: true });
    if (gl == null) {
      return false;
    }
  }
  return true;
})();
"""

class BrowserInfo(object):
  """A wrapper around browser object that allows looking up infos of the
  browser.
  """
  def __init__(self, browser):
    self._browser = browser

  def HasWebGLSupport(self):
    result = False
    # If no tab is opened, open one and close it after evaluate
    # _check_webgl_supported_script
    if len(self._browser.tabs) == 0 and self._browser.supports_tab_control:
      self._browser.tabs.New()
      tab = self._browser.tabs[0]
      result = tab.EvaluateJavaScript(_check_webgl_supported_script)
      tab.Close()
    elif len(self._browser.tabs) > 0:
      tab = self._browser.tabs[0]
      result = tab.EvaluateJavaScript(_check_webgl_supported_script)
    return result

  def HasFlingGestureSupport(self):
    # Synthetic fling gestures weren't properly tracked by telemetry until
    # Chromium branch number 2339 (see crrev.com/1003023002).
    # TODO(jdduke): Resolve lack of branch number support for content_shell
    # targets, see crbug.com/470273.
    branch_num = (
        self._browser._browser_backend.devtools_client.GetChromeBranchNumber())
    return branch_num >= 2339

  def HasDiagonalScrollingSupport(self):
    # Diagonal scrolling was not supported in the ScrollAction until
    # Chromium branch number 2332
    branch_num = (
        self._browser._browser_backend.devtools_client.GetChromeBranchNumber())
    return branch_num >= 2332

  def HasRepeatableSynthesizeScrollGesture(self):
    # Repeatable SynthesizeScrollGesture scrolling was not supported until
    # Chromium branch number 2480
    branch_num = (
        self._browser._browser_backend.devtools_client.GetChromeBranchNumber())
    return branch_num >= 2480

  @property
  def browser_type(self):
    return self._browser.browser_type

  @property
  def browser(self):
    return self._browser
