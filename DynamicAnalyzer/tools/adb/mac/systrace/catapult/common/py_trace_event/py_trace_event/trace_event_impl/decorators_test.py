#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import decorators
import logging
import unittest

from trace_test import TraceTest
#from .trace_test import TraceTest

def generator():
  yield 1
  yield 2

class DecoratorTests(unittest.TestCase):
  def test_tracing_object_fails(self):
    self.assertRaises(Exception, lambda: decorators.trace(1))
    self.assertRaises(Exception, lambda: decorators.trace(""))
    self.assertRaises(Exception, lambda: decorators.trace([]))

  def test_tracing_generators_fail(self):
    self.assertRaises(Exception, lambda: decorators.trace(generator))

class ClassToTest(object):
  @decorators.traced
  def method1(self):
    return 1

  @decorators.traced
  def method2(self):
    return 1

@decorators.traced
def traced_func():
  return 1

class DecoratorTests(TraceTest):
  def _get_decorated_method_name(self, f):
    res = self.go(f)
    events = res.findEventsOnThread(res.findThreadIds()[0])

    # Sanity checks.
    self.assertEquals(2, len(events))
    self.assertEquals(events[0]["name"], events[1]["name"])
    return events[1]["name"]


  def test_func_names_work(self):
    self.assertEquals('__main__.traced_func',
                      self._get_decorated_method_name(traced_func))

  def test_method_names_work(self):
    ctt = ClassToTest()
    self.assertEquals('ClassToTest.method1',
                      self._get_decorated_method_name(ctt.method1))
    self.assertEquals('ClassToTest.method2',
                      self._get_decorated_method_name(ctt.method2))

if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  unittest.main(verbosity=2)
