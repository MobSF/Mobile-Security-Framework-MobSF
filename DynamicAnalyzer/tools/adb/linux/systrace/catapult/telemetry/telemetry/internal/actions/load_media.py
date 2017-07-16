# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import exceptions
from telemetry.internal.actions import media_action
from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils


class LoadMediaAction(media_action.MediaAction):
  """ For calling load() on media elements and waiting for an event to fire.
  """

  def __init__(self, selector=None, timeout_in_seconds=0,
               event_to_await='canplaythrough'):
    super(LoadMediaAction, self).__init__()
    self._selector = selector or ''
    self._timeout_in_seconds = timeout_in_seconds
    self._event_to_await = event_to_await

  def WillRunAction(self, tab):
    """Load the JS code prior to running the action."""
    super(LoadMediaAction, self).WillRunAction(tab)
    utils.InjectJavaScript(tab, 'load_media.js')

  def RunAction(self, tab):
    try:
      tab.ExecuteJavaScript(
          'window.__loadMediaAndAwait({{ selector }}, {{ event }});',
          selector=self._selector, event=self._event_to_await)
      if self._timeout_in_seconds > 0:
        self.WaitForEvent(tab, self._selector, self._event_to_await,
                          self._timeout_in_seconds)
    except exceptions.EvaluateException:
      raise page_action.PageActionFailed('Failed waiting for event "%s" on '
                                         'elements with selector = %s.' %
                                         (self._event_to_await, self._selector))
