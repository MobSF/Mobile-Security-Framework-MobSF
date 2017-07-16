# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from profile_chrome import ddms_tracing_agent
from systrace import decorators
from systrace.tracing_agents import agents_unittest


class DdmsAgentTest(agents_unittest.BaseAgentTest):
  # TODO(washingtonp): The DDMS test is flaky on the Tryserver, but it
  # consistently passes on Android M. Need to figure out why the result data
  # does not start with '*version' and why the test is flaky.
  @decorators.Disabled
  def testTracing(self):
    agent = ddms_tracing_agent.DdmsAgent(self.device, self.package_info)

    try:
      agent.StartAgentTracing(None)
    finally:
      agent.StopAgentTracing()

    result = agent.GetResults()
    self.assertTrue(result.raw_data.startswith('*version'))
