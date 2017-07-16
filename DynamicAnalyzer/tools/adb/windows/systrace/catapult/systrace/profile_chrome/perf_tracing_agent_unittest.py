# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json

from profile_chrome import perf_tracing_agent
from profile_chrome import ui
from systrace import decorators
from systrace.tracing_agents import agents_unittest


class PerfProfilerAgentTest(agents_unittest.BaseAgentTest):
  @decorators.ClientOnlyTest
  def testGetCategories(self):
    if not perf_tracing_agent.PerfProfilerAgent.IsSupported():
      return
    categories = \
        perf_tracing_agent.PerfProfilerAgent.GetCategories(self.device)
    assert 'cycles' in ' '.join(categories)

  # TODO(washingtonp): Try enabling this test for the SimpleperfProfilerAgent,
  # which will be added later.
  @decorators.Disabled
  def testTracing(self):
    if not perf_tracing_agent.PerfProfilerAgent.IsSupported():
      return
    ui.EnableTestMode()
    categories = 'cycles'
    agent = perf_tracing_agent.PerfProfilerAgent(self.device)

    try:
      agent.StartAgentTracing(perf_tracing_agent.PerfConfig(categories,
                                                            self.device))
    finally:
      agent.StopAgentTracing()

    result = agent.GetResults()
    json.loads(result.raw_data)
