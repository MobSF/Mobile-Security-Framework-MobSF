# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import time

from telemetry.internal.actions import page_action


class NavigateAction(page_action.PageAction):
  def __init__(self, url, script_to_evaluate_on_commit=None,
               timeout_in_seconds=60):
    super(NavigateAction, self).__init__()
    assert url, 'Must specify url for navigate action'
    self._url = url
    self._script_to_evaluate_on_commit = script_to_evaluate_on_commit
    self._timeout_in_seconds = timeout_in_seconds

  def RunAction(self, tab):
    start_time = time.time()
    tab.Navigate(self._url,
                 self._script_to_evaluate_on_commit,
                 self._timeout_in_seconds)

    time_left_in_seconds = (start_time + self._timeout_in_seconds
        - time.time())
    time_left_in_seconds = max(0, time_left_in_seconds)
    tab.WaitForDocumentReadyStateToBeInteractiveOrBetter(
        time_left_in_seconds)
    tab.WaitForFrameToBeDisplayed()
