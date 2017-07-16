# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from profile_chrome import chrome_startup_tracing_agent
from systrace import decorators
from systrace.tracing_agents import agents_unittest


class ChromeAgentTest(agents_unittest.BaseAgentTest):
  # TODO(washingtonp): This test seems to fail on the version of Android
  # currently on the Trybot servers (KTU84P), although it works on Android M.
  # Either upgrade the version of Android on the Trybot servers or determine
  # if there is a way to run this agent on Android KTU84P.
  @decorators.Disabled
  def testTracing(self):
    agent = chrome_startup_tracing_agent.ChromeStartupTracingAgent(
        self.device, self.package_info, False, 'https://www.google.com')

    try:
      agent.StartAgentTracing(None)
    finally:
      agent.StopAgentTracing()

    result = agent.GetResults()
    json.loads(result.raw_data)
