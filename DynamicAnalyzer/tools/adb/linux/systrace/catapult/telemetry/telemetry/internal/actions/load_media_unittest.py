# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.internal.actions.load_media import LoadMediaAction
from telemetry.testing import tab_test_case

import py_utils


class LoadMediaActionTest(tab_test_case.TabTestCase):

  def setUp(self):
    tab_test_case.TabTestCase.setUp(self)
    self.Navigate('video_test.html')

  def eventFired(self, selector, event):
    return self._tab.EvaluateJavaScript(
        'window.__hasEventCompleted({{ selector }}, {{ event }});',
        selector=selector, event=event)

  @decorators.Disabled('linux',     # crbug.com/418577
                       'chromeos')  # crbug.com/632802
  def testAwaitedEventIsConfigurable(self):
    """It's possible to wait for different events."""
    action = LoadMediaAction(selector='#video_1', timeout_in_seconds=0.1,
                             event_to_await='loadedmetadata')
    action.WillRunAction(self._tab)
    action.RunAction(self._tab)
    self.assertTrue(self.eventFired('#video_1', 'loadedmetadata'))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testLoadWithNoSelector(self):
    """With no selector the first media element is loaded."""
    action = LoadMediaAction(timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    action.RunAction(self._tab)
    self.assertTrue(self.eventFired('#video_1', 'canplaythrough'))
    self.assertFalse(self.eventFired('#audio_1', 'canplaythrough'))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testLoadWithSelector(self):
    """Only the element matching the selector is loaded."""
    action = LoadMediaAction(selector='#audio_1', timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    action.RunAction(self._tab)
    self.assertFalse(self.eventFired('#video_1', 'canplaythrough'))
    self.assertTrue(self.eventFired('#audio_1', 'canplaythrough'))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testLoadWithAllSelector(self):
    """Both elements are loaded with selector='all'."""
    action = LoadMediaAction(selector='all', timeout_in_seconds=5)
    action.WillRunAction(self._tab)
    action.RunAction(self._tab)
    self.assertTrue(self.eventFired('#video_1', 'canplaythrough'))
    self.assertTrue(self.eventFired('#audio_1', 'canplaythrough'))

  @decorators.Disabled('linux')  # crbug.com/418577
  def testLoadRaisesAnExceptionOnTimeout(self):
    """The load action times out if the event does not fire."""
    action = LoadMediaAction(selector='#video_1', timeout_in_seconds=0.1,
                             event_to_await='a_nonexistent_event')
    action.WillRunAction(self._tab)
    self.assertRaises(py_utils.TimeoutException, action.RunAction, self._tab)
