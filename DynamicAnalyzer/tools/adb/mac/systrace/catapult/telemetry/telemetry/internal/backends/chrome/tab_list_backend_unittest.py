# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.core import exceptions
from telemetry import decorators
from telemetry.testing import tab_test_case


class TabListBackendTest(tab_test_case.TabTestCase):
  @decorators.Enabled('has tabs')
  def testNewTab(self):
    tabs = set(tab.id for tab in self.tabs)
    for _ in xrange(10):
      new_tab_id = self.tabs.New().id
      self.assertNotIn(new_tab_id, tabs)
      tabs.add(new_tab_id)
      new_tabs = set(tab.id for tab in self.tabs)
      self.assertEqual(tabs, new_tabs)

  @decorators.Enabled('has tabs')
  def testTabIdMatchesContextId(self):
    # Ensure that there are two tabs.
    while len(self.tabs) < 2:
      self.tabs.New()

    # Check that the tab.id matches context_id.
    tabs = []
    for context_id in self.tabs._tab_list_backend.IterContextIds():
      tab = self.tabs.GetTabById(context_id)
      self.assertEquals(tab.id, context_id)
      tabs.append(self.tabs.GetTabById(context_id))

  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  @decorators.Enabled('has tabs')
  @decorators.Disabled('android')
  def testTabIdStableAfterTabCrash(self):
    # Ensure that there are two tabs.
    while len(self.tabs) < 2:
      self.tabs.New()

    tabs = [t for t in self.tabs]

    # Crash the first tab.
    self.assertRaises(exceptions.DevtoolsTargetCrashException,
        lambda: tabs[0].Navigate('chrome://crash'))

    # Fetching the second tab by id should still work. Fetching the first tab
    # should raise an exception.
    self.assertEquals(tabs[1], self.tabs.GetTabById(tabs[1].id))
    self.assertRaises(KeyError, lambda: self.tabs.GetTabById(tabs[0].id))
