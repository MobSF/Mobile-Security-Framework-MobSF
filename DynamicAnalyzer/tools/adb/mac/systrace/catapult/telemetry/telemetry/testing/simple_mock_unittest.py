# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from telemetry.testing import simple_mock

_ = simple_mock.DONT_CARE

# pylint: disable=no-member
class SimpleMockUnitTest(unittest.TestCase):
  def testBasic(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo')

    mock.foo()

  def testReturn(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo').WillReturn(7)

    ret = mock.foo()
    self.assertEquals(ret, 7)

  def testArgs(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo').WithArgs(3, 4)

    mock.foo(3, 4)

  def testArgs2(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo', 3, 4)

    mock.foo(3, 4)

  def testArgsMismatch(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo').WithArgs(3, 4)

    self.assertRaises(Exception,
                      lambda: mock.foo(4, 4))


  def testArgsDontCare(self):
    mock = simple_mock.MockObject()
    mock.ExpectCall('foo').WithArgs(_, 4)

    mock.foo(4, 4)

  def testOnCall(self):
    mock = simple_mock.MockObject()

    handler_called = []
    def Handler(arg0):
      assert arg0 == 7
      handler_called.append(True)
    mock.ExpectCall('baz', 7).WhenCalled(Handler)

    mock.baz(7)
    self.assertTrue(len(handler_called) > 0)


  def testSubObject(self):
    mock = simple_mock.MockObject()
    mock.bar = simple_mock.MockObject(mock)

    mock.ExpectCall('foo').WithArgs(_, 4)
    mock.bar.ExpectCall('baz')

    mock.foo(0, 4)
    mock.bar.baz()

  def testSubObjectMismatch(self):
    mock = simple_mock.MockObject()
    mock.bar = simple_mock.MockObject(mock)

    mock.ExpectCall('foo').WithArgs(_, 4)
    mock.bar.ExpectCall('baz')

    self.assertRaises(
      Exception,
      lambda: mock.bar.baz()) # pylint: disable=unnecessary-lambda
