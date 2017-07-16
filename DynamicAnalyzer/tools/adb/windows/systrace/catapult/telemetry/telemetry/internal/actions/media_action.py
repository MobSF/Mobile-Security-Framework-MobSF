# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Common media action functions."""

import logging

from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils

import py_utils


class MediaAction(page_action.PageAction):
  def WillRunAction(self, tab):
    """Loads the common media action JS code prior to running the action."""
    utils.InjectJavaScript(tab, 'media_action.js')

  def RunAction(self, tab):
    super(MediaAction, self).RunAction(tab)

  def WaitForEvent(self, tab, selector, event_name, timeout_in_seconds):
    """Halts media action until the selector's event is fired.

    Args:
      tab: The tab to check for event on.
      selector: Media element selector.
      event_name: Name of the event to check if fired or not.
      timeout_in_seconds: Timeout to check for event, throws an exception if
          not fired.
    """
    py_utils.WaitFor(
        lambda: self.HasEventCompletedOrError(tab, selector, event_name),
        timeout=timeout_in_seconds)

  def HasEventCompletedOrError(self, tab, selector, event_name):
    if tab.EvaluateJavaScript(
        'window.__hasEventCompleted({{ selector }}, {{ event_name }});',
        selector=selector, event_name=event_name):
      return True
    error = tab.EvaluateJavaScript('window.__error')
    if error:
      logging.error('Detected media error while waiting for %s: %s', event_name,
                    error)
      return True
    return False
