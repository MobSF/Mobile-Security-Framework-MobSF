# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import tempfile

from telemetry import decorators
from telemetry.internal.platform.profiler import (
    android_screen_recorder_profiler)
from telemetry.testing import tab_test_case


class AndroidScreenRecorderProfilerTest(tab_test_case.TabTestCase):
  @decorators.Enabled('android')
  def testRecording(self):
    out_dir = tempfile.mkdtemp()
    try:
      # pylint: disable=protected-access
      profiler = (
          android_screen_recorder_profiler.AndroidScreenRecordingProfiler(
              self._browser._browser_backend,
              self._browser._platform_backend,
              os.path.join(out_dir, 'android_screen_recording'),
              {}))
      result = profiler.CollectProfile()[0]
      self.assertTrue(os.path.exists(result))
    finally:
      shutil.rmtree(out_dir)
