# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A Telemetry page_action that performs the "play" action on media elements.

Media elements can be specified by a selector argument. If no selector is
defined then then the action attempts to play the first video element or audio
element on the page. A selector can also be 'all' to play all media elements.

Other arguments to use are: playing_event_timeout_in_seconds and
ended_event_timeout_in_seconds, which forces the action to wait until
playing and ended events get fired respectively.
"""

from telemetry.core import exceptions
from telemetry.internal.actions import media_action
from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils


class PlayAction(media_action.MediaAction):
  def __init__(self, selector=None,
               playing_event_timeout_in_seconds=0,
               ended_event_timeout_in_seconds=0):
    super(PlayAction, self).__init__()
    self._selector = selector if selector else ''
    self._playing_event_timeout_in_seconds = playing_event_timeout_in_seconds
    self._ended_event_timeout_in_seconds = ended_event_timeout_in_seconds

  def WillRunAction(self, tab):
    """Load the media metrics JS code prior to running the action."""
    super(PlayAction, self).WillRunAction(tab)
    utils.InjectJavaScript(tab, 'play.js')

  def RunAction(self, tab):
    try:
      tab.ExecuteJavaScript(
          'window.__playMedia({{ selector }});', selector=self._selector)
      # Check if we need to wait for 'playing' event to fire.
      if self._playing_event_timeout_in_seconds > 0:
        self.WaitForEvent(tab, self._selector, 'playing',
                          self._playing_event_timeout_in_seconds)
      # Check if we need to wait for 'ended' event to fire.
      if self._ended_event_timeout_in_seconds > 0:
        self.WaitForEvent(tab, self._selector, 'ended',
                          self._ended_event_timeout_in_seconds)
    except exceptions.EvaluateException:
      raise page_action.PageActionFailed('Cannot play media element(s) with '
                                         'selector = %s.' % self._selector)
