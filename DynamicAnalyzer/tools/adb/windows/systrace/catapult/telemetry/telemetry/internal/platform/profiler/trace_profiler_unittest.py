# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import shutil
import tempfile

from telemetry.internal.platform.profiler import trace_profiler
from telemetry.testing import tab_test_case


class TestTraceProfiler(tab_test_case.TabTestCase):

  def testTraceProfiler(self):
    try:
      out_dir = tempfile.mkdtemp()
      profiler = trace_profiler.TraceProfiler(
          self._browser._browser_backend,
          self._browser._platform_backend,
          os.path.join(out_dir, 'trace'),
          {})
      result = profiler.CollectProfile()[0]
      with open(result) as f:
        self.assertTrue(f.read())
    finally:
      shutil.rmtree(out_dir)
