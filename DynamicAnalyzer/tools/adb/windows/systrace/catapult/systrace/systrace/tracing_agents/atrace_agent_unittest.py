#!/usr/bin/env python

# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import logging
import os
import unittest

from systrace import decorators
from systrace import run_systrace
from systrace import util
from systrace.tracing_agents import atrace_agent

from devil.android import device_utils
from devil.android.sdk import intent


DEVICE_SERIAL = 'AG8404EC0444AGC'
ATRACE_ARGS = ['atrace', '-z', '-t', '10', '-b', '4096']
CATEGORIES = ['sched', 'gfx', 'view', 'wm']
ADB_SHELL = ['adb', '-s', DEVICE_SERIAL, 'shell']

SYSTRACE_CMD = ['./run_systrace.py', '--time', '10', '-o', 'out.html', '-e',
                DEVICE_SERIAL] + CATEGORIES
TRACE_ARGS = (ATRACE_ARGS + CATEGORIES)

TEST_DIR = os.path.join(os.path.dirname(__file__), os.pardir, 'test_data')
ATRACE_DATA = os.path.join(TEST_DIR, 'atrace_data')
ATRACE_DATA_RAW = os.path.join(TEST_DIR, 'atrace_data_raw')
ATRACE_DATA_STRIPPED = os.path.join(TEST_DIR, 'atrace_data_stripped')
ATRACE_DATA_THREAD_FIXED = os.path.join(TEST_DIR, 'atrace_data_thread_fixed')
ATRACE_DATA_WITH_THREAD_LIST = os.path.join(TEST_DIR,
                                            'atrace_data_with_thread_list')
ATRACE_THREAD_NAMES = os.path.join(TEST_DIR, 'atrace_thread_names')
ATRACE_PS_DUMPS = [os.path.join(TEST_DIR, psdump) for psdump in
        ['atrace_ps_dump', 'atrace_ps_dump_2', 'atrace_ps_dump_3']]
ATRACE_EXTRACTED_THREADS = os.path.join(TEST_DIR, 'atrace_extracted_threads')
ATRACE_PROCFS_DUMP = os.path.join(TEST_DIR, 'atrace_procfs_dump')
ATRACE_EXTRACTED_TGIDS = os.path.join(TEST_DIR, 'atrace_extracted_tgids')
ATRACE_MISSING_TGIDS = os.path.join(TEST_DIR, 'atrace_missing_tgids')
ATRACE_FIXED_TGIDS = os.path.join(TEST_DIR, 'atrace_fixed_tgids')


class AtraceAgentTest(unittest.TestCase):

  # TODO(washingtonp): These end-to-end tests do not work on the Trybot server
  # because adb cannot be found on the Trybot servers. Figure out what the
  # issue is and update this test.
  @decorators.Disabled
  def test_tracing(self):
    TRACE_BUFFER_SIZE = '16384'
    TRACE_TIME = '5'

    devices = device_utils.DeviceUtils.HealthyDevices()
    package_info = util.get_supported_browsers()['stable']
    device = devices[0]
    output_file_name = util.generate_random_filename_for_test()

    try:
      # Launch the browser before tracing.
      device.StartActivity(
          intent.Intent(activity=package_info.activity,
                        package=package_info.package,
                        data='about:blank',
                        extras={'create_new_tab': True}),
          blocking=True, force_stop=True)

      # Run atrace agent.
      run_systrace.main_impl(['./run_systrace.py',
                              '-b',
                              TRACE_BUFFER_SIZE,
                              '-t',
                              TRACE_TIME,
                              '-o',
                              output_file_name,
                              '-e',
                              str(device),
                              '--atrace-categories=gfx,input,view'])

      # Verify results.
      with open(output_file_name, 'r') as f:
        full_trace = f.read()
        self.assertTrue('CPU#'in full_trace)
    except:
      raise
    finally:
      if os.path.exists(output_file_name):
        os.remove(output_file_name)

  @decorators.HostOnlyTest
  def test_construct_atrace_args(self):
    options, categories = run_systrace.parse_options(SYSTRACE_CMD)
    options.atrace_categories = categories
    tracer_args = atrace_agent._construct_atrace_args(options, categories)
    self.assertEqual(' '.join(TRACE_ARGS), ' '.join(tracer_args))

  @decorators.HostOnlyTest
  def test_extract_thread_list(self):
    with open(ATRACE_EXTRACTED_THREADS, 'r') as expected_file:
      expected = expected_file.read().strip()
      for dump_file_name in ATRACE_PS_DUMPS:
        with open(dump_file_name, 'r') as dump_file:
          ps_dump = dump_file.read()
          thread_names = atrace_agent.extract_thread_list(ps_dump.splitlines())
          self.assertEqual(expected, str(thread_names))

  @decorators.HostOnlyTest
  def test_strip_and_decompress_trace(self):
    with contextlib.nested(open(ATRACE_DATA_RAW, 'r'),
                           open(ATRACE_DATA_STRIPPED, 'r')) as (f1, f2):
      atrace_data_raw = f1.read()
      atrace_data_stripped = f2.read()

      trace_data = atrace_agent.strip_and_decompress_trace(atrace_data_raw)
      self.assertEqual(atrace_data_stripped, trace_data)

  @decorators.HostOnlyTest
  def test_fix_thread_names(self):
    with contextlib.nested(
        open(ATRACE_DATA_STRIPPED, 'r'),
        open(ATRACE_THREAD_NAMES, 'r'),
        open(ATRACE_DATA_THREAD_FIXED, 'r')) as (f1, f2, f3):
      atrace_data_stripped = f1.read()
      atrace_thread_names = f2.read()
      atrace_data_thread_fixed = f3.read()
      thread_names = eval(atrace_thread_names)

      trace_data = atrace_agent.fix_thread_names(
          atrace_data_stripped, thread_names)
      self.assertEqual(atrace_data_thread_fixed, trace_data)

  @decorators.HostOnlyTest
  def test_extract_tgids(self):
    with contextlib.nested(open(ATRACE_PROCFS_DUMP, 'r'),
                           open(ATRACE_EXTRACTED_TGIDS, 'r')) as (f1, f2):

      atrace_procfs_dump = f1.read()
      atrace_procfs_extracted = f2.read()

      tgids = eval(atrace_procfs_extracted)
      result = atrace_agent.extract_tgids(atrace_procfs_dump.splitlines())

      self.assertEqual(result, tgids)

  @decorators.HostOnlyTest
  def test_fix_missing_tgids(self):
    with contextlib.nested(open(ATRACE_EXTRACTED_TGIDS, 'r'),
                           open(ATRACE_MISSING_TGIDS, 'r'),
                           open(ATRACE_FIXED_TGIDS, 'r')) as (f1, f2, f3):

      atrace_data = f2.read()
      tgid_map = eval(f1.read())
      fixed = f3.read()

      res = atrace_agent.fix_missing_tgids(atrace_data, tgid_map)
      self.assertEqual(res, fixed)


if __name__ == "__main__":
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
