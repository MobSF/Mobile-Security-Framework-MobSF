# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import mock

from telemetry.core import platform
from telemetry import decorators
from telemetry.internal.browser import possible_browser


class FakeTest(object):

  def SetEnabledStrings(self, enabled_strings):
    enabled_attr_name = decorators.EnabledAttributeName(self)
    setattr(self, enabled_attr_name, enabled_strings)

  def SetDisabledStrings(self, disabled_strings):
    # pylint: disable=attribute-defined-outside-init
    disabled_attr_name = decorators.DisabledAttributeName(self)
    setattr(self, disabled_attr_name, disabled_strings)


class TestDisableDecorators(unittest.TestCase):

  def testDisabledStringOnFunction(self):

    @decorators.Disabled('bar')
    def Sum():
      return 1 + 1

    self.assertEquals({'bar'}, decorators.GetDisabledAttributes(Sum))

    @decorators.Disabled('bar')
    @decorators.Disabled('baz')
    @decorators.Disabled('bart', 'baz')
    def Product():
      return 1 * 1

    self.assertEquals({'bar', 'bart', 'baz'},
                      decorators.GetDisabledAttributes(Product))

  def testDisabledStringOnClass(self):

    @decorators.Disabled('windshield')
    class Ford(object):
      pass

    self.assertEquals({'windshield'}, decorators.GetDisabledAttributes(Ford))

    @decorators.Disabled('windows', 'Drive')
    @decorators.Disabled('wheel')
    @decorators.Disabled('windows')
    class Honda(object):
      pass

    self.assertEquals({'windshield'}, decorators.GetDisabledAttributes(Ford))
    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetDisabledAttributes(Honda))

  def testDisabledStringOnSubClass(self):

    @decorators.Disabled('windshield')
    class Car(object):
      pass

    class Ford(Car):
      pass

    self.assertEquals({'windshield'}, decorators.GetDisabledAttributes(Car))
    self.assertFalse(decorators.GetDisabledAttributes(Ford))

    @decorators.Disabled('windows', 'Drive')
    @decorators.Disabled('wheel')
    @decorators.Disabled('windows')
    class Honda(Car):
      pass

    self.assertFalse(decorators.GetDisabledAttributes(Ford))
    self.assertEquals({'windshield'}, decorators.GetDisabledAttributes(Car))
    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetDisabledAttributes(Honda))

  def testDisabledStringOnMethod(self):

    class Ford(object):

      @decorators.Disabled('windshield')
      def Drive(self):
        pass

    self.assertEquals({'windshield'},
                      decorators.GetDisabledAttributes(Ford().Drive))

    class Honda(object):

      @decorators.Disabled('windows', 'Drive')
      @decorators.Disabled('wheel')
      @decorators.Disabled('windows')
      def Drive(self):
        pass

    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetDisabledAttributes(Honda().Drive))
    self.assertEquals({'windshield'},
                      decorators.GetDisabledAttributes(Ford().Drive))

    class Accord(Honda):

      def Drive(self):
        pass

    class Explorer(Ford):
      pass

    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetDisabledAttributes(Honda().Drive))
    self.assertEquals({'windshield'},
                      decorators.GetDisabledAttributes(Ford().Drive))
    self.assertEquals({'windshield'},
                      decorators.GetDisabledAttributes(Explorer().Drive))
    self.assertFalse(decorators.GetDisabledAttributes(Accord().Drive))


class TestEnableDecorators(unittest.TestCase):

  def testEnabledStringOnFunction(self):

    @decorators.Enabled('minus', 'power')
    def Sum():
      return 1 + 1

    self.assertEquals({'minus', 'power'}, decorators.GetEnabledAttributes(Sum))

    @decorators.Enabled('dot')
    @decorators.Enabled('product')
    @decorators.Enabled('product', 'dot')
    def Product():
      return 1 * 1

    self.assertEquals({'dot', 'product'},
                      decorators.GetEnabledAttributes(Product))

  def testEnabledStringOnClass(self):

    @decorators.Enabled('windshield', 'light')
    class Ford(object):
      pass

    self.assertEquals({'windshield', 'light'},
                      decorators.GetEnabledAttributes(Ford))

    @decorators.Enabled('wheel', 'Drive')
    @decorators.Enabled('wheel')
    @decorators.Enabled('windows')
    class Honda(object):
      pass

    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetEnabledAttributes(Honda))
    self.assertEquals({'windshield', 'light'},
                      decorators.GetEnabledAttributes(Ford))

  def testEnabledStringOnSubClass(self):

    @decorators.Enabled('windshield')
    class Car(object):
      pass

    class Ford(Car):
      pass

    self.assertEquals({'windshield'}, decorators.GetEnabledAttributes(Car))
    self.assertFalse(decorators.GetEnabledAttributes(Ford))

    @decorators.Enabled('windows', 'Drive')
    @decorators.Enabled('wheel')
    @decorators.Enabled('windows')
    class Honda(Car):
      pass

    self.assertFalse(decorators.GetEnabledAttributes(Ford))
    self.assertEquals({'windshield'}, decorators.GetEnabledAttributes(Car))
    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetEnabledAttributes(Honda))

  def testEnabledStringOnMethod(self):

    class Ford(object):

      @decorators.Enabled('windshield')
      def Drive(self):
        pass

    self.assertEquals({'windshield'},
                      decorators.GetEnabledAttributes(Ford().Drive))

    class Honda(object):

      @decorators.Enabled('windows', 'Drive')
      @decorators.Enabled('wheel', 'Drive')
      @decorators.Enabled('windows')
      def Drive(self):
        pass

    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetEnabledAttributes(Honda().Drive))

    class Accord(Honda):

      def Drive(self):
        pass

    class Explorer(Ford):
      pass

    self.assertEquals({'wheel', 'Drive', 'windows'},
                      decorators.GetEnabledAttributes(Honda().Drive))
    self.assertEquals({'windshield'},
                      decorators.GetEnabledAttributes(Ford().Drive))
    self.assertEquals({'windshield'},
                      decorators.GetEnabledAttributes(Explorer().Drive))
    self.assertFalse(decorators.GetEnabledAttributes(Accord().Drive))


class TestOwnerDecorators(unittest.TestCase):

  def testOwnerStringOnClass(self):

    @decorators.Owner(emails=['owner@chromium.org'])
    class Ford(object):
      pass

    self.assertEquals(['owner@chromium.org'], decorators.GetEmails(Ford))

    @decorators.Owner(emails=['owner2@chromium.org'])
    @decorators.Owner(component='component')
    class Honda(object):
      pass

    self.assertEquals(['owner2@chromium.org'], decorators.GetEmails(Honda))
    self.assertEquals('component', decorators.GetComponent(Honda))
    self.assertEquals(['owner@chromium.org'], decorators.GetEmails(Ford))


  def testOwnerStringOnSubClass(self):

    @decorators.Owner(emails=['owner@chromium.org'], component='comp')
    class Car(object):
      pass

    class Ford(Car):
      pass

    self.assertEquals(['owner@chromium.org'], decorators.GetEmails(Car))
    self.assertEquals('comp', decorators.GetComponent(Car))
    self.assertFalse(decorators.GetEmails(Ford))
    self.assertFalse(decorators.GetComponent(Ford))


  def testOwnerWithDuplicateAttributeSetting(self):

    with self.assertRaises(AssertionError):
      @decorators.Owner(emails=['owner2@chromium.org'])
      @decorators.Owner(emails=['owner@chromium.org'], component='comp')
      class Car(object):
        pass

      self.assertEquals(['owner@chromium.org'], decorators.GetEmails(Car))


class TestShouldSkip(unittest.TestCase):

  def setUp(self):
    fake_platform = mock.Mock(spec_set=platform.Platform)
    fake_platform.GetOSName.return_value = 'os_name'
    fake_platform.GetOSVersionName.return_value = 'os_version_name'

    self.possible_browser = mock.Mock(spec_set=possible_browser.PossibleBrowser)
    self.possible_browser.browser_type = 'browser_type'
    self.possible_browser.platform = fake_platform
    self.possible_browser.supports_tab_control = False

  def testEnabledStrings(self):
    test = FakeTest()

    # When no enabled_strings is given, everything should be enabled.
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_version_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name', 'another_os_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name', 'os_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name', 'another_os_version_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_version_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name-reference', 'another_os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference', 'os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference',
                            'another_os_version_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

  def testDisabledStrings(self):
    test = FakeTest()

    # When no disabled_strings is given, nothing should be disabled.
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_version_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name', 'another_os_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name', 'os_name'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name', 'another_os_version_name'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_version_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name-reference', 'another_os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference', 'os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference',
                             'another_os_version_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

  def testReferenceEnabledStrings(self):
    self.possible_browser.browser_type = 'reference'
    test = FakeTest()

    # When no enabled_strings is given, everything should be enabled.
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_version_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['os_name-reference', 'another_os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference', 'os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetEnabledStrings(['another_os_name-reference',
                            'another_os_version_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

  def testReferenceDisabledStrings(self):
    self.possible_browser.browser_type = 'reference'
    test = FakeTest()

    # When no disabled_strings is given, nothing should be disabled.
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_version_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['os_name-reference', 'another_os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference', 'os_name-reference'])
    self.assertTrue(decorators.ShouldSkip(test, self.possible_browser)[0])

    test.SetDisabledStrings(['another_os_name-reference',
                             'another_os_version_name-reference'])
    self.assertFalse(decorators.ShouldSkip(test, self.possible_browser)[0])


class TestDeprecation(unittest.TestCase):

  @mock.patch('warnings.warn')
  def testFunctionDeprecation(self, warn_mock):

    @decorators.Deprecated(2015, 12, 1)
    def Foo(x):
      return x

    Foo(1)
    warn_mock.assert_called_with(
        'Function Foo is deprecated. It will no longer be supported on '
        'December 01, 2015. Please remove it or switch to an alternative '
        'before that time. \n',
        stacklevel=4)

  @mock.patch('warnings.warn')
  def testMethodDeprecated(self, warn_mock):

    class Bar(object):

      @decorators.Deprecated(2015, 12, 1, 'Testing only.')
      def Foo(self, x):
        return x

    Bar().Foo(1)
    warn_mock.assert_called_with(
        'Function Foo is deprecated. It will no longer be supported on '
        'December 01, 2015. Please remove it or switch to an alternative '
        'before that time. Testing only.\n',
        stacklevel=4)

  @mock.patch('warnings.warn')
  def testClassWithoutInitDefinedDeprecated(self, warn_mock):

    @decorators.Deprecated(2015, 12, 1)
    class Bar(object):

      def Foo(self, x):
        return x

    Bar().Foo(1)
    warn_mock.assert_called_with(
        'Class Bar is deprecated. It will no longer be supported on '
        'December 01, 2015. Please remove it or switch to an alternative '
        'before that time. \n',
        stacklevel=4)

  @mock.patch('warnings.warn')
  def testClassWithInitDefinedDeprecated(self, warn_mock):

    @decorators.Deprecated(2015, 12, 1)
    class Bar(object):

      def __init__(self):
        pass

      def Foo(self, x):
        return x

    Bar().Foo(1)
    warn_mock.assert_called_with(
        'Class Bar is deprecated. It will no longer be supported on '
        'December 01, 2015. Please remove it or switch to an alternative '
        'before that time. \n',
        stacklevel=4)

  @mock.patch('warnings.warn')
  def testInheritedClassDeprecated(self, warn_mock):

    class Ba(object):
      pass

    @decorators.Deprecated(2015, 12, 1)
    class Bar(Ba):

      def Foo(self, x):
        return x

    class Baz(Bar):
      pass

    Baz().Foo(1)
    warn_mock.assert_called_with(
        'Class Bar is deprecated. It will no longer be supported on '
        'December 01, 2015. Please remove it or switch to an alternative '
        'before that time. \n',
        stacklevel=4)

  def testReturnValue(self):

    class Bar(object):

      @decorators.Deprecated(2015, 12, 1, 'Testing only.')
      def Foo(self, x):
        return x

    self.assertEquals(5, Bar().Foo(5))
