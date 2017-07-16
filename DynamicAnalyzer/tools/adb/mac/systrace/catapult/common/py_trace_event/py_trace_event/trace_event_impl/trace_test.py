# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import tempfile
import unittest

#from .log import *
#from .parsed_trace_events import *

from log import *
from parsed_trace_events import *

class TraceTest(unittest.TestCase):
  def __init__(self, *args):
    """
    Infrastructure for running tests of the tracing system.

    Does not actually run any tests. Look at subclasses for those.
    """
    unittest.TestCase.__init__(self, *args)
    self._file = None

  def go(self, cb):
    """
    Enables tracing, runs the provided callback, and if successful, returns a
    TraceEvents object with the results.
    """
    self._file = tempfile.NamedTemporaryFile()
    trace_enable(open(self._file.name, 'a+'))

    try:
      cb()
    finally:
      trace_disable()
    e = ParsedTraceEvents(trace_filename = self._file.name)
    self._file.close()
    self._file = None
    return e

  @property
  def trace_filename(self):
    return self._file.name

  def tearDown(self):
    if trace_is_enabled():
      trace_disable()
    if self._file:
      self._file.close()
