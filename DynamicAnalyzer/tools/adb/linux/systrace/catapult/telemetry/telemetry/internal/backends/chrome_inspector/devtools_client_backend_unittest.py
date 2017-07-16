# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry import decorators
from telemetry.testing import browser_test_case
from telemetry.timeline import model
from telemetry.timeline import tracing_config
from tracing.trace_data import trace_data


class DevToolsClientBackendTest(browser_test_case.BrowserTestCase):
  @property
  def _browser_backend(self):
    return self._browser._browser_backend

  @property
  def _devtools_client(self):
    return self._browser_backend.devtools_client

  def testGetChromeBranchNumber(self):
    branch_num = self._devtools_client.GetChromeBranchNumber()
    self.assertIsInstance(branch_num, int)
    self.assertGreater(branch_num, 0)

  def testIsAlive(self):
    self.assertTrue(self._devtools_client.IsAlive())

  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  # crbug.com/483212 (CrOS)
  @decorators.Enabled('has tabs')
  @decorators.Disabled('android', 'chromeos')
  def testGetUpdatedInspectableContexts(self):
    self._browser.tabs.New()
    c1 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c1.contexts), 2)
    backends1 = [c1.GetInspectorBackend(c['id']) for c in c1.contexts]
    tabs1 = list(self._browser.tabs)

    c2 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c2.contexts), 2)
    backends2 = [c2.GetInspectorBackend(c['id']) for c in c2.contexts]
    tabs2 = list(self._browser.tabs)
    self.assertEqual(backends2, backends1)
    self.assertEqual(tabs2, tabs1)

    self._browser.tabs.New()
    c3 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c3.contexts), 3)
    backends3 = [c3.GetInspectorBackend(c['id']) for c in c3.contexts]
    tabs3 = list(self._browser.tabs)
    self.assertEqual(backends3[1], backends1[0])
    self.assertEqual(backends3[2], backends1[1])
    self.assertEqual(tabs3[0], tabs1[0])
    self.assertEqual(tabs3[1], tabs1[1])

    self._browser.tabs[1].Close()
    c4 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c4.contexts), 2)
    backends4 = [c4.GetInspectorBackend(c['id']) for c in c4.contexts]
    tabs4 = list(self._browser.tabs)
    self.assertEqual(backends4[0], backends3[0])
    self.assertEqual(backends4[1], backends3[1])
    self.assertEqual(tabs4[0], tabs3[0])
    self.assertEqual(tabs4[1], tabs3[2])

  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  # crbug.com/483212 (CrOS)
  @decorators.Disabled('android', 'chromeos')
  def testGetUpdatedInspectableContextsUpdateContextsData(self):
    c1 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c1.contexts), 1)
    self.assertEqual(c1.contexts[0]['url'], 'about:blank')

    context_id = c1.contexts[0]['id']
    backend = c1.GetInspectorBackend(context_id)
    backend.Navigate(self.UrlOfUnittestFile('blank.html'), None, 10)
    c2 = self._devtools_client.GetUpdatedInspectableContexts()
    self.assertEqual(len(c2.contexts), 1)
    self.assertTrue('blank.html' in c2.contexts[0]['url'])
    self.assertEqual(c2.GetInspectorBackend(context_id), backend)

  def testTracing(self):
    devtools_client = self._devtools_client
    if not devtools_client.IsChromeTracingSupported():
      self.skipTest('Browser does not support tracing, skipping test.')

    # Start Chrome tracing.
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    devtools_client.StartChromeTracing(config)

    # Stop Chrome tracing and check that the resulting data is valid.
    builder = trace_data.TraceDataBuilder()
    devtools_client.StopChromeTracing()
    devtools_client.CollectChromeTracingData(builder)
    model.TimelineModel(builder.AsData())
