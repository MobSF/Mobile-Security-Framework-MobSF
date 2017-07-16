# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import model as model_module
from tracing.trace_data import trace_data


class TimelineModelUnittest(unittest.TestCase):
  def testEmptyImport(self):
    model_module.TimelineModel(trace_data.CreateTraceDataFromRawData({}))

  def testBrowserProcess(self):
    builder = trace_data.TraceDataBuilder()
    builder.AddTraceFor(trace_data.CHROME_TRACE_PART, {
      "traceEvents": [
        {"name": "process_name", "args": {"name": "Browser"},
         "pid": 5, "ph": "M"},
        {"name": "thread_name", "args": {"name": "CrBrowserMain"},
         "pid": 5, "tid": 32578, "ph": "M"}]})
    model = model_module.TimelineModel(builder.AsData())
    self.assertEquals(5, model.browser_process.pid)
