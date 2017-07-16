# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry import decorators

_counter = 0


class Foo(object):
  @decorators.Cache
  def GetCountCached(self, _):
    global _counter
    _counter = _counter + 1
    return _counter


def CreateFooUncached(_):
  return Foo()


@decorators.Cache
def CreateFooCached(_):
  return Foo()


class DecoratorsUnitTest(unittest.TestCase):
  # pylint: disable=blacklisted-name

  def testCacheDecorator(self):
    self.assertNotEquals(CreateFooUncached(1), CreateFooUncached(2))
    self.assertNotEquals(CreateFooCached(1), CreateFooCached(2))

    self.assertNotEquals(CreateFooUncached(1), CreateFooUncached(1))
    self.assertEquals(CreateFooCached(1), CreateFooCached(1))

  def testCacheableMemberCachesOnlyForSameArgs(self):
    foo = Foo()
    value_of_one = foo.GetCountCached(1)

    self.assertEquals(value_of_one, foo.GetCountCached(1))
    self.assertNotEquals(value_of_one, foo.GetCountCached(2))

  def testCacheableMemberHasSeparateCachesForSiblingInstances(self):
    foo = Foo()
    sibling_foo = Foo()

    self.assertNotEquals(foo.GetCountCached(1), sibling_foo.GetCountCached(1))

  def testCacheableMemberHasSeparateCachesForNextGenerationInstances(self):
    foo = Foo()
    last_generation_count = foo.GetCountCached(1)
    foo = None
    foo = Foo()

    self.assertNotEquals(last_generation_count, foo.GetCountCached(1))
