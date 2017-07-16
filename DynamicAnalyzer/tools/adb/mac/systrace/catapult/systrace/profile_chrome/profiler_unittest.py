# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest
import zipfile

from profile_chrome import profiler
from profile_chrome import ui
from profile_chrome import fake_agent_1
from profile_chrome import fake_agent_2
from systrace import decorators
from systrace import tracing_controller


class ProfilerTest(unittest.TestCase):
  def setUp(self):
    ui.EnableTestMode()
    self._tracing_options = tracing_controller.TracingControllerConfig(None,
        None, None, None, None, None, None, None, None)

  @decorators.ClientOnlyTest
  def testCaptureBasicProfile(self):
    result = profiler.CaptureProfile(self._tracing_options, 1, [fake_agent_1])

    try:
      self.assertTrue(os.path.exists(result))
      self.assertTrue(result.endswith('.html'))
    finally:
      if os.path.exists(result):
        os.remove(result)

  @decorators.ClientOnlyTest
  def testCaptureJsonProfile(self):
    result = profiler.CaptureProfile(self._tracing_options, 1,
                                     [fake_agent_2], write_json=True)

    try:
      self.assertFalse(result.endswith('.html'))
      with open(result) as f:
        self.assertEquals(f.read(), 'fake-contents')
    finally:
      if os.path.exists(result):
        os.remove(result)

  @decorators.ClientOnlyTest
  def testCaptureMultipleProfiles(self):
    result = profiler.CaptureProfile(self._tracing_options, 1,
                                     [fake_agent_1, fake_agent_2],
                                     write_json=True)

    try:
      self.assertTrue(result.endswith('.zip'))
      self.assertTrue(zipfile.is_zipfile(result))
    finally:
      if os.path.exists(result):
        os.remove(result)
