#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import contextlib
import json
import logging
import math
import multiprocessing
import os
import tempfile
import time
import unittest

from py_trace_event import trace_event
from py_trace_event import trace_time
from py_trace_event.trace_event_impl import log


class TraceEventTests(unittest.TestCase):

  def setUp(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    self._log_path = tf.name
    tf.close()

  def tearDown(self):
    if os.path.exists(self._log_path):
      os.remove(self._log_path)

  @contextlib.contextmanager
  def _test_trace(self, disable=True):
    try:
      trace_event.trace_enable(self._log_path)
      yield
    finally:
      if disable:
        trace_event.trace_disable()

  def testNoImpl(self):
    orig_impl = trace_event.trace_event_impl
    try:
      trace_event.trace_event_impl = None
      self.assertFalse(trace_event.trace_can_enable())
    finally:
      trace_event.trace_event_impl = orig_impl

  def testImpl(self):
    self.assertTrue(trace_event.trace_can_enable())

  def testIsEnabledFalse(self):
    self.assertFalse(trace_event.trace_is_enabled())

  def testIsEnabledTrue(self):
    with self._test_trace():
      self.assertTrue(trace_event.trace_is_enabled())

  def testEnable(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 1)
        self.assertTrue(trace_event.trace_is_enabled())
        log_output = log_output.pop()
        self.assertEquals(log_output['category'], 'process_argv')
        self.assertEquals(log_output['name'], 'process_argv')
        self.assertTrue(log_output['args']['argv'])
        self.assertEquals(log_output['ph'], 'M')

  def testDoubleEnable(self):
    try:
      with self._test_trace():
        with self._test_trace():
          pass
    except log.TraceException:
      return
    assert False

  def testDisable(self):
    with self._test_trace(disable=False):
      with open(self._log_path, 'r') as f:
        self.assertTrue(trace_event.trace_is_enabled())
        trace_event.trace_disable()
        self.assertEquals(len(json.loads(f.read() + ']')), 1)
        self.assertFalse(trace_event.trace_is_enabled())

  def testDoubleDisable(self):
    with self._test_trace():
      pass
    trace_event.trace_disable()

  def testFlushChanges(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.clock_sync('1')
        self.assertEquals(len(json.loads(f.read() + ']')), 1)
        f.seek(0)
        trace_event.trace_flush()
        self.assertEquals(len(json.loads(f.read() + ']')), 2)

  def testFlushNoChanges(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        self.assertEquals(len(json.loads(f.read() + ']')),1)
        f.seek(0)
        trace_event.trace_flush()
        self.assertEquals(len(json.loads(f.read() + ']')), 1)

  def testDoubleFlush(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.clock_sync('1')
        self.assertEquals(len(json.loads(f.read() + ']')), 1)
        f.seek(0)
        trace_event.trace_flush()
        trace_event.trace_flush()
        self.assertEquals(len(json.loads(f.read() + ']')), 2)

  def testTraceBegin(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.trace_begin('test_event', this='that')
        trace_event.trace_flush()
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 2)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue( current_entry['args']['argv'])
        self.assertEquals( current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'test_event')
        self.assertEquals(current_entry['args']['this'], '\'that\'')
        self.assertEquals(current_entry['ph'], 'B')

  def testTraceEnd(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.trace_end('test_event')
        trace_event.trace_flush()
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 2)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue(current_entry['args']['argv'])
        self.assertEquals(current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'test_event')
        self.assertEquals(current_entry['args'], {})
        self.assertEquals(current_entry['ph'], 'E')

  def testTrace(self):
   with self._test_trace():
      with trace_event.trace('test_event', this='that'):
        pass
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 3)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue(current_entry['args']['argv'])
        self.assertEquals(current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'test_event')
        self.assertEquals(current_entry['args']['this'], '\'that\'')
        self.assertEquals(current_entry['ph'], 'B')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'test_event')
        self.assertEquals(current_entry['args'], {})
        self.assertEquals(current_entry['ph'], 'E')

  def testTracedDecorator(self):
    @trace_event.traced("this")
    def test_decorator(this="that"):
      pass

    with self._test_trace():
      test_decorator()
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 3)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue(current_entry['args']['argv'])
        self.assertEquals(current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], '__main__.test_decorator')
        self.assertEquals(current_entry['args']['this'], '\'that\'')
        self.assertEquals(current_entry['ph'], 'B')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], '__main__.test_decorator')
        self.assertEquals(current_entry['args'], {})
        self.assertEquals(current_entry['ph'], 'E')

  def testClockSyncWithTs(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.clock_sync('id', issue_ts=trace_time.Now())
        trace_event.trace_flush()
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 2)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue(current_entry['args']['argv'])
        self.assertEquals(current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'clock_sync')
        self.assertTrue(current_entry['args']['issue_ts'])
        self.assertEquals(current_entry['ph'], 'c')

  def testClockSyncWithoutTs(self):
    with self._test_trace():
      with open(self._log_path, 'r') as f:
        trace_event.clock_sync('id')
        trace_event.trace_flush()
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 2)
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'process_argv')
        self.assertEquals(current_entry['name'], 'process_argv')
        self.assertTrue(current_entry['args']['argv'])
        self.assertEquals(current_entry['ph'], 'M')
        current_entry = log_output.pop(0)
        self.assertEquals(current_entry['category'], 'python')
        self.assertEquals(current_entry['name'], 'clock_sync')
        self.assertFalse(current_entry['args'].get('issue_ts'))
        self.assertEquals(current_entry['ph'], 'c')

  def testTime(self):
    actual_diff = []
    def func1():
      trace_begin("func1")
      start = time.time()
      time.sleep(0.25)
      end = time.time()
      actual_diff.append(end-start) # Pass via array because of Python scoping
      trace_end("func1")

    with self._test_trace():
      start_ts = time.time()
      trace_event.trace_begin('test')
      end_ts = time.time()
      trace_event.trace_end('test')
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 3)
        meta_data = log_output[0]
        open_data = log_output[1]
        close_data = log_output[2]
        self.assertEquals(meta_data['category'], 'process_argv')
        self.assertEquals(meta_data['name'], 'process_argv')
        self.assertTrue(meta_data['args']['argv'])
        self.assertEquals(meta_data['ph'], 'M')
        self.assertEquals(open_data['category'], 'python')
        self.assertEquals(open_data['name'], 'test')
        self.assertEquals(open_data['ph'], 'B')
        self.assertEquals(close_data['category'], 'python')
        self.assertEquals(close_data['name'], 'test')
        self.assertEquals(close_data['ph'], 'E')
        event_time_diff = close_data['ts'] - open_data['ts']
        recorded_time_diff = (end_ts - start_ts) * 1000000
        self.assertLess(math.fabs(event_time_diff - recorded_time_diff), 1000)

  def testNestedCalls(self):
    with self._test_trace():
      trace_event.trace_begin('one')
      trace_event.trace_begin('two')
      trace_event.trace_end('two')
      trace_event.trace_end('one')
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 5)
        meta_data = log_output[0]
        one_open = log_output[1]
        two_open = log_output[2]
        two_close = log_output[3]
        one_close = log_output[4]
        self.assertEquals(meta_data['category'], 'process_argv')
        self.assertEquals(meta_data['name'], 'process_argv')
        self.assertTrue(meta_data['args']['argv'])
        self.assertEquals(meta_data['ph'], 'M')

        self.assertEquals(one_open['category'], 'python')
        self.assertEquals(one_open['name'], 'one')
        self.assertEquals(one_open['ph'], 'B')
        self.assertEquals(one_close['category'], 'python')
        self.assertEquals(one_close['name'], 'one')
        self.assertEquals(one_close['ph'], 'E')

        self.assertEquals(two_open['category'], 'python')
        self.assertEquals(two_open['name'], 'two')
        self.assertEquals(two_open['ph'], 'B')
        self.assertEquals(two_close['category'], 'python')
        self.assertEquals(two_close['name'], 'two')
        self.assertEquals(two_close['ph'], 'E')

        self.assertLessEqual(one_open['ts'], two_open['ts'])
        self.assertGreaterEqual(one_close['ts'], two_close['ts'])

  def testInterleavedCalls(self):
    with self._test_trace():
      trace_event.trace_begin('one')
      trace_event.trace_begin('two')
      trace_event.trace_end('one')
      trace_event.trace_end('two')
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 5)
        meta_data = log_output[0]
        one_open = log_output[1]
        two_open = log_output[2]
        two_close = log_output[4]
        one_close = log_output[3]
        self.assertEquals(meta_data['category'], 'process_argv')
        self.assertEquals(meta_data['name'], 'process_argv')
        self.assertTrue(meta_data['args']['argv'])
        self.assertEquals(meta_data['ph'], 'M')

        self.assertEquals(one_open['category'], 'python')
        self.assertEquals(one_open['name'], 'one')
        self.assertEquals(one_open['ph'], 'B')
        self.assertEquals(one_close['category'], 'python')
        self.assertEquals(one_close['name'], 'one')
        self.assertEquals(one_close['ph'], 'E')

        self.assertEquals(two_open['category'], 'python')
        self.assertEquals(two_open['name'], 'two')
        self.assertEquals(two_open['ph'], 'B')
        self.assertEquals(two_close['category'], 'python')
        self.assertEquals(two_close['name'], 'two')
        self.assertEquals(two_close['ph'], 'E')

        self.assertLessEqual(one_open['ts'], two_open['ts'])
        self.assertLessEqual(one_close['ts'], two_close['ts'])

  def testMultiprocess(self):
    def child_function():
      with trace_event.trace('child_event'):
        pass

    with self._test_trace():
      trace_event.trace_begin('parent_event')
      trace_event.trace_flush()
      p = multiprocessing.Process(target=child_function)
      p.start()
      self.assertTrue(hasattr(p, "_shimmed_by_trace_event"))
      p.join()
      trace_event.trace_end('parent_event')
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 5)
        meta_data = log_output[0]
        parent_open = log_output[1]
        child_open = log_output[2]
        child_close = log_output[3]
        parent_close = log_output[4]
        self.assertEquals(meta_data['category'], 'process_argv')
        self.assertEquals(meta_data['name'], 'process_argv')
        self.assertTrue(meta_data['args']['argv'])
        self.assertEquals(meta_data['ph'], 'M')

        self.assertEquals(parent_open['category'], 'python')
        self.assertEquals(parent_open['name'], 'parent_event')
        self.assertEquals(parent_open['ph'], 'B')

        self.assertEquals(child_open['category'], 'python')
        self.assertEquals(child_open['name'], 'child_event')
        self.assertEquals(child_open['ph'], 'B')

        self.assertEquals(child_close['category'], 'python')
        self.assertEquals(child_close['name'], 'child_event')
        self.assertEquals(child_close['ph'], 'E')

        self.assertEquals(parent_close['category'], 'python')
        self.assertEquals(parent_close['name'], 'parent_event')
        self.assertEquals(parent_close['ph'], 'E')

  def testMultiprocessExceptionInChild(self):
    def bad_child():
      trace_event.trace_disable()

    with self._test_trace():
      p = multiprocessing.Pool(1)
      trace_event.trace_begin('parent')
      self.assertRaises(Exception, lambda: p.apply(bad_child, ()))
      p.close()
      p.terminate()
      p.join()
      trace_event.trace_end('parent')
      trace_event.trace_flush()
      with open(self._log_path, 'r') as f:
        log_output = json.loads(f.read() + ']')
        self.assertEquals(len(log_output), 3)
        meta_data = log_output[0]
        parent_open = log_output[1]
        parent_close = log_output[2]
        self.assertEquals(parent_open['category'], 'python')
        self.assertEquals(parent_open['name'], 'parent')
        self.assertEquals(parent_open['ph'], 'B')
        self.assertEquals(parent_close['category'], 'python')
        self.assertEquals(parent_close['name'], 'parent')
        self.assertEquals(parent_close['ph'], 'E')

if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
