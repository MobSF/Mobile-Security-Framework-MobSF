# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import types
import unittest

from telemetry.timeline import counter as counter_module


class FakeProcess(object):
  pass


class CounterIterEventsInThisContainerTest(unittest.TestCase):

  def setUp(self):
    parent = FakeProcess()
    self.counter = counter_module.Counter(parent, 'cat', 'name')

  def assertIsEmptyIterator(self, itr):
    self.assertIsInstance(itr, types.GeneratorType)
    self.assertRaises(StopIteration, itr.next)

  def testEmptyTimestamps(self):
    self.assertIsEmptyIterator(self.counter.IterEventsInThisContainer(
        event_type_predicate=lambda x: True,
        event_predicate=lambda x: True))

  def testEventTypeMismatch(self):
    self.counter.timestamps = [111, 222]
    self.assertIsEmptyIterator(self.counter.IterEventsInThisContainer(
        event_type_predicate=lambda x: False,
        event_predicate=lambda x: True))

  def testNoEventMatch(self):
    self.counter.timestamps = [111, 222]
    self.assertIsEmptyIterator(self.counter.IterEventsInThisContainer(
        event_type_predicate=lambda x: True,
        event_predicate=lambda x: False))

  def testAllMatch(self):
    self.counter.timestamps = [111, 222]
    self.counter.samples = [100, 200]
    events = self.counter.IterEventsInThisContainer(
        event_type_predicate=lambda x: True,
        event_predicate=lambda x: True)
    self.assertIsInstance(events, types.GeneratorType)
    eventlist = list(events)
    self.assertEqual([111, 222], [s.start for s in eventlist])
    self.assertEqual(['cat.name', 'cat.name'], [s.name for s in eventlist])
    self.assertEqual([100, 200], [s.value for s in eventlist])

  def testPartialMatch(self):
    self.counter.timestamps = [111, 222]
    self.counter.samples = [100, 200]
    events = self.counter.IterEventsInThisContainer(
        event_type_predicate=lambda x: True,
        event_predicate=lambda x: x.start > 200)
    self.assertIsInstance(events, types.GeneratorType)
    eventlist = list(events)
    self.assertEqual([222], [s.start for s in eventlist])
    self.assertEqual(['cat.name'], [s.name for s in eventlist])
    self.assertEqual([200], [s.value for s in eventlist])
