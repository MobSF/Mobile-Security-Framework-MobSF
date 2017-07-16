# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from systrace import decorators
from systrace import update_systrace_trace_viewer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STABLE_VIEWER_PATH = os.path.join(SCRIPT_DIR, 'systrace_trace_viewer.html')

# Tests presence and content of static HTML files used not only for Python
# systrace capture, but also Java-based capture in the android SDK tools.
#
# NOTE: changes to this file should typically be accompanied by changes to the
# Android SDK's method of systrace capture.
class MonitorTest(unittest.TestCase):

  @decorators.HostOnlyTest
  def test_systrace_trace_viewer(self):
    self.assertEqual(STABLE_VIEWER_PATH,
      update_systrace_trace_viewer.SYSTRACE_TRACE_VIEWER_HTML_FILE)

    update_systrace_trace_viewer.update(force_update=True)

    with open(STABLE_VIEWER_PATH) as f:
      content = f.read().strip()

      # expect big html file
      self.assertGreater(5 * 1024 * 1024, len(content))
      self.assertEqual('<', content[0])
    os.remove(f.name)


  @decorators.HostOnlyTest
  def test_prefix(self):
    with open(os.path.join(SCRIPT_DIR, 'prefix.html')) as f:
      content = f.read().strip()

      self.assertTrue("<html>" in content)
      self.assertTrue("<title>Android System Trace</title>" in content)
      self.assertTrue("{{SYSTRACE_TRACE_VIEWER_HTML}}" in content)


  @decorators.HostOnlyTest
  def test_suffix(self):
    with open(os.path.join(SCRIPT_DIR, 'suffix.html')) as f:
      content = f.read().strip()

      self.assertTrue("</html>" in content)
