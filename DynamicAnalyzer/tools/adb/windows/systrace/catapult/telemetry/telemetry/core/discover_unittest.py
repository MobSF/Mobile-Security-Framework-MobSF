# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
import unittest

from telemetry.core import discover
from telemetry.core import util


class DiscoverTest(unittest.TestCase):

  def setUp(self):
    self._base_dir = util.GetUnittestDataDir()
    self._start_dir = os.path.join(self._base_dir, 'discoverable_classes')
    self._base_class = Exception

  def testDiscoverClassesWithIndexByModuleName(self):
    classes = discover.DiscoverClasses(self._start_dir,
                                       self._base_dir,
                                       self._base_class,
                                       index_by_class_name=False)

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'another_discover_dummyclass': 'DummyExceptionWithParameterImpl1',
        'discover_dummyclass': 'DummyException',
        'parameter_discover_dummyclass': 'DummyExceptionWithParameterImpl2'
    }
    self.assertEqual(actual_classes, expected_classes)

  def testDiscoverDirectlyConstructableClassesWithIndexByClassName(self):
    classes = discover.DiscoverClasses(self._start_dir,
                                       self._base_dir,
                                       self._base_class,
                                       directly_constructable=True)

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'dummy_exception': 'DummyException',
        'dummy_exception_impl1': 'DummyExceptionImpl1',
        'dummy_exception_impl2': 'DummyExceptionImpl2',
    }
    self.assertEqual(actual_classes, expected_classes)

  def testDiscoverClassesWithIndexByClassName(self):
    classes = discover.DiscoverClasses(self._start_dir, self._base_dir,
                                       self._base_class)

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'dummy_exception': 'DummyException',
        'dummy_exception_impl1': 'DummyExceptionImpl1',
        'dummy_exception_impl2': 'DummyExceptionImpl2',
        'dummy_exception_with_parameter_impl1':
            'DummyExceptionWithParameterImpl1',
        'dummy_exception_with_parameter_impl2':
            'DummyExceptionWithParameterImpl2'
    }
    self.assertEqual(actual_classes, expected_classes)

  def testDiscoverClassesWithPatternAndIndexByModule(self):
    classes = discover.DiscoverClasses(self._start_dir,
                                       self._base_dir,
                                       self._base_class,
                                       pattern='another*',
                                       index_by_class_name=False)

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'another_discover_dummyclass': 'DummyExceptionWithParameterImpl1'
    }
    self.assertEqual(actual_classes, expected_classes)

  def testDiscoverDirectlyConstructableClassesWithPatternAndIndexByClassName(
      self):
    classes = discover.DiscoverClasses(self._start_dir,
                                       self._base_dir,
                                       self._base_class,
                                       pattern='another*',
                                       directly_constructable=True)

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'dummy_exception_impl1': 'DummyExceptionImpl1',
        'dummy_exception_impl2': 'DummyExceptionImpl2',
    }
    self.assertEqual(actual_classes, expected_classes)

  def testDiscoverClassesWithPatternAndIndexByClassName(self):
    classes = discover.DiscoverClasses(self._start_dir,
                                       self._base_dir,
                                       self._base_class,
                                       pattern='another*')

    actual_classes = dict((name, cls.__name__)
                          for name, cls in classes.iteritems())
    expected_classes = {
        'dummy_exception_impl1': 'DummyExceptionImpl1',
        'dummy_exception_impl2': 'DummyExceptionImpl2',
        'dummy_exception_with_parameter_impl1':
            'DummyExceptionWithParameterImpl1',
    }
    self.assertEqual(actual_classes, expected_classes)
