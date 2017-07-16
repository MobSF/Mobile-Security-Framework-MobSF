# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from profile_chrome import chrome_tracing_agent
from systrace import decorators
from systrace.tracing_agents import agents_unittest


class ChromeAgentTest(agents_unittest.BaseAgentTest):
  # TODO(washingtonp): This test seems to fail on the version of Android
  # currently on the Trybot servers (KTU84P), although it works on Android M.
  # Either upgrade the version of Android on the Trybot servers or determine
  # if there is a way to run this agent on Android KTU84P.
  @decorators.Disabled
  def testGetCategories(self):
    curr_browser = self.GetChromeProcessID()
    if curr_browser == None:
      self.StartBrowser()

    categories = \
        chrome_tracing_agent.ChromeTracingAgent.GetCategories(
            self.device, self.package_info)

    self.assertEquals(len(categories), 2)
    self.assertTrue(categories[0])
    self.assertTrue(categories[1])

  # TODO(washingtonp): This test is pretty flaky on the version of Android
  # currently on the Trybot servers (KTU84P), although it works on Android M.
  # Either upgrade the version of Android on the Trybot servers or determine
  # if there is a way to run this agent on Android KTU84P.
  @decorators.Disabled
  def testTracing(self):
    curr_browser = self.GetChromeProcessID()
    if curr_browser == None:
      self.StartBrowser()

    categories = '*'
    ring_buffer = False
    agent = chrome_tracing_agent.ChromeTracingAgent(self.device,
                                                    self.package_info,
                                                    ring_buffer)
    agent.StartAgentTracing(chrome_tracing_agent.ChromeConfig(categories, None,
        None, None, None, None, None, None, ring_buffer, self.device,
        self.package_info))
    agent.StopAgentTracing()
    result = agent.GetResults()
    json.loads(result.raw_data)
