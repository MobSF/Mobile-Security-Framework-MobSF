#!/usr/bin/env python

# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import os
import unittest

from systrace import decorators
from systrace import run_systrace
from systrace import util

TEST_DIR = os.path.join(os.path.dirname(__file__), '..', 'test_data')

COMPRESSED_ATRACE_DATA = os.path.join(TEST_DIR, 'compressed_atrace_data.txt')
DECOMPRESSED_ATRACE_DATA = os.path.join(TEST_DIR,
                                        'decompressed_atrace_data.txt')
NON_EXISTENT_DATA = os.path.join(TEST_DIR, 'THIS_FILE_DOES_NOT_EXIST.txt')

class AtraceFromFileAgentTest(unittest.TestCase):
  # TODO(ccraik): fix test on windows
  @decorators.LinuxMacTest
  def test_from_file(self):
    output_file_name = util.generate_random_filename_for_test()
    try:
      # use from-file to create a specific expected output
      run_systrace.main_impl(['./run_systrace.py',
                              '--from-file',
                              COMPRESSED_ATRACE_DATA,
                              '-o',
                              output_file_name])
      # and verify file contents
      with contextlib.nested(open(output_file_name, 'r'),
                             open(DECOMPRESSED_ATRACE_DATA, 'r')) as (f1, f2):
        full_trace = f1.read()
        expected_contents = f2.read()
        self.assertTrue(expected_contents in full_trace)
    except:
      raise
    finally:
      if os.path.exists(output_file_name):
        os.remove(output_file_name)


  # TODO(ccraik): fix test on windows
  @decorators.LinuxMacTest
  def test_missing_file(self):
    try:
      run_systrace.main_impl(['./run_systrace.py',
                              '--from-file',
                              NON_EXISTENT_DATA])
      self.fail('should not get here')
    except IOError:
      pass
