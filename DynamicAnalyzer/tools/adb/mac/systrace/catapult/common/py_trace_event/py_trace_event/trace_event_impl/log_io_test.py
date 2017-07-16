#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging
import os
import sys
import tempfile
import unittest

from log import *
from parsed_trace_events import *


class LogIOTest(unittest.TestCase):
  def test_enable_with_file(self):
    file = tempfile.NamedTemporaryFile()
    trace_enable(open(file.name, 'w+'))
    trace_disable()
    e = ParsedTraceEvents(trace_filename = file.name)
    file.close()
    self.assertTrue(len(e) > 0)

  def test_enable_with_filename(self):
    file = tempfile.NamedTemporaryFile()
    trace_enable(file.name)
    trace_disable()
    e = ParsedTraceEvents(trace_filename = file.name)
    file.close()
    self.assertTrue(len(e) > 0)

  def test_enable_with_implicit_filename(self):
    expected_filename = "%s.json" % sys.argv[0]
    def do_work():
      file = tempfile.NamedTemporaryFile()
      trace_enable()
      trace_disable()
      e = ParsedTraceEvents(trace_filename = expected_filename)
      file.close()
      self.assertTrue(len(e) > 0)
    try:
      do_work()
    finally:
      if os.path.exists(expected_filename):
        os.unlink(expected_filename)

if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)

