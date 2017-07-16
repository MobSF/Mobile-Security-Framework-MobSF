# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging
import os
import unittest

from telemetry.core import util
from telemetry.internal.platform.profiler import perf_profiler
from telemetry.testing import options_for_unittests
import mock

class TestPerfProfiler(unittest.TestCase):
  @mock.patch('telemetry.internal.platform.profiler.perf_profiler.subprocess')
  def testPerfProfiler(self, mock_subprocess):
    options = options_for_unittests.GetCopy()
    if not perf_profiler.PerfProfiler.is_supported(options.browser_type):
      logging.warning('PerfProfiler is not supported. Skipping test')
      return

    profile_file = os.path.join(
        util.GetUnittestDataDir(), 'perf_report_output.txt')
    with open(profile_file) as f:
      perf_report_output = f.read()

    mock_popen = mock.Mock()
    mock_popen.communicate.side_effect = [[perf_report_output]]
    mock_subprocess.Popen.side_effect = [mock_popen]
    mock_subprocess.PIPE = mock.Mock()

    perf_profiler.subprocess = mock_subprocess

    self.assertEqual(
        perf_profiler.PerfProfiler.GetTopSamples(profile_file, 10),
        {'v8::internal::StaticMarkingVisitor::MarkMapContents': 63615201,
         'v8::internal::RelocIterator::next': 38271931,
         'v8::internal::LAllocator::MeetConstraintsBetween': 42913933,
         'v8::internal::FlexibleBodyVisitor::Visit': 31909537,
         'v8::internal::LiveRange::CreateAssignedOperand': 42913933,
         'void v8::internal::RelocInfo::Visit': 96878864,
         'WebCore::HTMLTokenizer::nextToken': 48240439,
         'v8::internal::Scanner::ScanIdentifierOrKeyword': 46054550,
         'sk_memset32_SSE2': 45121317,
         'v8::internal::HeapObject::Size': 39786862
         })
    mock_popen.communicate.assert_called_once_with()
    mock_subprocess.Popen.assert_called_once_with(
        mock.ANY, stdout=mock.ANY, stderr=mock.ANY)
