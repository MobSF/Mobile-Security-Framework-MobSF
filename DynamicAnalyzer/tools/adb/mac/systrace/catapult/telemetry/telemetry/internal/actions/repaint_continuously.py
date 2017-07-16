# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

from telemetry.internal.actions import page_action

import py_utils


class RepaintContinuouslyAction(page_action.PageAction):
  """Continuously repaints the visible content by requesting animation frames
  until self.seconds have elapsed AND at least three RAFs have been fired. Times
  out after max(60, self.seconds), if less than three RAFs were fired.
  """

  def __init__(self, seconds):
    super(RepaintContinuouslyAction, self).__init__()
    self._seconds = seconds

  def RunAction(self, tab):
    tab.ExecuteJavaScript(
        'window.__rafCount = 0;'
        'window.__rafFunction = function() {'
          'window.__rafCount += 1;'
          'window.webkitRequestAnimationFrame(window.__rafFunction);'
        '};'
        'window.webkitRequestAnimationFrame(window.__rafFunction);')

    # Wait until at least self.seconds have elapsed AND min_rafs have been
    # fired. Use a hard time-out after 60 seconds (or self.seconds).
    time.sleep(self._seconds)
    def HasMinRafs():
      return tab.EvaluateJavaScript('window.__rafCount;') >= 3
    py_utils.WaitFor(HasMinRafs, max(60 - self._seconds, 0))
