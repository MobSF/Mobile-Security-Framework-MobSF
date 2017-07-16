# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A Telemetry page_action that performs the "seek" action on media elements.

Action parameters are:
- seconds: The media time to seek to. Test fails if not provided.
- selector: If no selector is defined then the action attempts to seek the first
            media element on the page. If 'all' then seek all media elements.
- timeout_in_seconds: Maximum waiting time for the "seeked" event
                      (dispatched when the seeked operation completes)
                      to be fired.  0 means do not wait.
- log_time: If true the seek time is recorded, otherwise media
            measurement will not be aware of the seek action. Used to
            perform multiple seeks. Default true.
- label: A suffix string to name the seek perf measurement.
"""

from telemetry.core import exceptions
from telemetry.internal.actions import media_action
from telemetry.internal.actions import page_action
from telemetry.internal.actions import utils


class SeekAction(media_action.MediaAction):
  def __init__(self, seconds, selector=None, timeout_in_seconds=0,
               log_time=True, label=''):
    super(SeekAction, self).__init__()
    self._seconds = seconds
    self._selector = selector if selector else ''
    self._timeout_in_seconds = timeout_in_seconds
    self._log_time = log_time
    self._label = label

  def WillRunAction(self, tab):
    """Load the media metrics JS code prior to running the action."""
    super(SeekAction, self).WillRunAction(tab)
    utils.InjectJavaScript(tab, 'seek.js')

  def RunAction(self, tab):
    try:
      tab.ExecuteJavaScript(
          'window.__seekMedia('
              '{{ selector }}, {{ seconds }}, {{ log_time }}, {{ label}});',
          selector=self._selector,
          seconds=str(self._seconds),
          log_time=self._log_time,
          label=self._label)
      if self._timeout_in_seconds > 0:
        self.WaitForEvent(tab, self._selector, 'seeked',
                          self._timeout_in_seconds)
    except exceptions.EvaluateException:
      raise page_action.PageActionFailed('Cannot seek media element(s) with '
                                         'selector = %s.' % self._selector)
