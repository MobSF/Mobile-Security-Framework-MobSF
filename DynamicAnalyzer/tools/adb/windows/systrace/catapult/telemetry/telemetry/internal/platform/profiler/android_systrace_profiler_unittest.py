# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import shutil
import tempfile
import zipfile

from telemetry import decorators
from telemetry.internal.platform.profiler import android_systrace_profiler
from telemetry.testing import tab_test_case


class TestAndroidSystraceProfiler(tab_test_case.TabTestCase):
  # https://github.com/catapult-project/catapult/issues/3099 (Android)
  @decorators.Disabled('all')
  def testSystraceProfiler(self):
    try:
      out_dir = tempfile.mkdtemp()
      # pylint: disable=protected-access
      profiler = android_systrace_profiler.AndroidSystraceProfiler(
          self._browser._browser_backend,
          self._browser._platform_backend,
          os.path.join(out_dir, 'systrace'),
          {},
          self._device)
      result = profiler.CollectProfile()[0]
      self.assertTrue(zipfile.is_zipfile(result))
      with zipfile.ZipFile(result) as z:
        self.assertEquals(len(z.namelist()), 2)
        self.assertIn('sched_wakeup', z.open('systrace').read())
    finally:
      shutil.rmtree(out_dir)
