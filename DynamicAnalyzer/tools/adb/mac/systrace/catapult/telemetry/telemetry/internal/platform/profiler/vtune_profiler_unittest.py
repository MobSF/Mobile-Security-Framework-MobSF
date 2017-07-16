# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys
import unittest

from telemetry import decorators
from telemetry.internal.platform.profiler import vtune_profiler
from telemetry.testing import options_for_unittests
from telemetry.testing import simple_mock
from telemetry.testing import tab_test_case


class MockPopen(object):
  def __init__(self, returncode, stdout=None, stderr=None):
    self.returncode = returncode
    self.stdout = stdout
    self.stderr = stderr

  def communicate(self):
    return (self.stdout, self.stderr)

  def wait(self):
    return self.returncode


class MockSubprocess(object):
  def __init__(self):
    self.PIPE = simple_mock.MockObject()
    self.STDOUT = simple_mock.MockObject()
    self._num_collect_calls = 0
    self._num_stop_calls = 0

  @property
  def num_collect_calls(self):
    return self._num_collect_calls

  @property
  def num_stop_calls(self):
    return self._num_stop_calls

  def Popen(self, cmd, **_):
    self._AnalyzeCommand(cmd)
    return MockPopen(0)

  def call(self, cmd):
    self._AnalyzeCommand(cmd)

  def _AnalyzeCommand(self, cmd):
    if MockSubprocess._IsCollectCommand(cmd):
      self._num_collect_calls += 1
    elif MockSubprocess._IsStopCommand(cmd):
      self._num_stop_calls += 1

  @staticmethod
  def _IsCollectCommand(cmd):
    return '-collect' in cmd

  @staticmethod
  def _IsStopCommand(cmd):
    try:
      cmd_idx = cmd.index('-command') + 1
      return cmd_idx < len(cmd) and cmd[cmd_idx] == 'stop'
    except ValueError:
      return False


class TestVTuneProfiler(unittest.TestCase):

  def testVTuneProfilerIsSupported(self):
    options = options_for_unittests.GetCopy()

    mock_subprocess = simple_mock.MockObject()
    mock_subprocess.ExpectCall(
        'Popen').WithArgs(simple_mock.DONT_CARE).WillReturn(MockPopen(0))
    mock_subprocess.SetAttribute('PIPE', simple_mock.MockObject())
    mock_subprocess.SetAttribute('STDOUT', simple_mock.MockObject())

    real_subprocess = vtune_profiler.subprocess
    vtune_profiler.subprocess = mock_subprocess

    if options.browser_type.startswith('android'):
      # On Android we're querying if 'su' is available.
      mock_subprocess.ExpectCall('Popen').WithArgs(
          simple_mock.DONT_CARE).WillReturn(MockPopen(0, 'su', None))

    try:
      self.assertTrue(
          vtune_profiler.VTuneProfiler.is_supported(options.browser_type) or
          sys.platform != 'linux2' or
          options.browser_type.startswith('cros'))
    finally:
      vtune_profiler.subprocess = real_subprocess


class TestVTuneProfilerTabTestCase(tab_test_case.TabTestCase):

  # This test is only meant to be run if VTune is installed locally. Please
  # run it locally if you are modifying related code, but it's disabled on the
  # bots because they don't have VTune. See crbug.com/437085
  @decorators.Disabled('all')
  def testVTuneProfiler(self):
    mock_subprocess = MockSubprocess()
    real_subprocess = vtune_profiler.subprocess
    vtune_profiler.subprocess = mock_subprocess

    try:
      # pylint: disable=protected-access
      profiler = vtune_profiler.VTuneProfiler(self._browser._browser_backend,
                                              self._browser._platform_backend,
                                              'tmp',
                                              {})
      profiler.CollectProfile()
      self.assertEqual(mock_subprocess.num_collect_calls,
                       mock_subprocess.num_stop_calls)
    finally:
      vtune_profiler.subprocess = real_subprocess
