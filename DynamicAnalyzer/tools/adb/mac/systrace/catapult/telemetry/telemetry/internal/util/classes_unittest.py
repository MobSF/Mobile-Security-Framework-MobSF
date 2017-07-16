# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.internal.util import classes


class ClassWithoutInitDefOne: # pylint: disable=old-style-class, no-init
  pass


class ClassWithoutInitDefTwo(object):
  pass


class ClassWhoseInitOnlyHasSelf(object):
  def __init__(self):
    pass


class ClassWhoseInitWithDefaultArguments(object):
  def __init__(self, dog=1, cat=None, cow=None, fud='a'):
    pass


class ClassWhoseInitWithDefaultArgumentsAndNonDefaultArguments(object):
  def __init__(self, x, dog=1, cat=None, fish=None, fud='a'):
    pass


class ClassesUnitTest(unittest.TestCase):

  def testIsDirectlyConstructableReturnsTrue(self):
    self.assertTrue(classes.IsDirectlyConstructable(ClassWithoutInitDefOne))
    self.assertTrue(classes.IsDirectlyConstructable(ClassWithoutInitDefTwo))
    self.assertTrue(classes.IsDirectlyConstructable(ClassWhoseInitOnlyHasSelf))
    self.assertTrue(
        classes.IsDirectlyConstructable(ClassWhoseInitWithDefaultArguments))

  def testIsDirectlyConstructableReturnsFalse(self):
    self.assertFalse(
        classes.IsDirectlyConstructable(
            ClassWhoseInitWithDefaultArgumentsAndNonDefaultArguments))
