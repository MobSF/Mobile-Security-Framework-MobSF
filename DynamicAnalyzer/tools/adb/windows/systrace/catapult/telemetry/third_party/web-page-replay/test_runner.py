#!/usr/bin/env python
# Copyright (c) 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest
import sys
import os
import optparse

__all__ = []

def FilterSuite(suite, predicate):
  new_suite = suite.__class__()

  for x in suite:
    if isinstance(x, unittest.TestSuite):
      subsuite = FilterSuite(x, predicate)
      if subsuite.countTestCases() == 0:
        continue

      new_suite.addTest(subsuite)
      continue

    assert isinstance(x, unittest.TestCase)
    if predicate(x):
      new_suite.addTest(x)

  return new_suite

class _TestLoader(unittest.TestLoader):
  def __init__(self, *args):
    super(_TestLoader, self).__init__(*args)
    self.discover_calls = []

  def loadTestsFromModule(self, module, use_load_tests=True):
    if module.__file__ != __file__:
      return super(_TestLoader, self).loadTestsFromModule(
          module, use_load_tests)

    suite = unittest.TestSuite()
    for discover_args in self.discover_calls:
      subsuite = self.discover(*discover_args)
      suite.addTest(subsuite)
    return suite

class _RunnerImpl(unittest.TextTestRunner):
  def __init__(self, filters):
    super(_RunnerImpl, self).__init__(verbosity=2)
    self.filters = filters

  def ShouldTestRun(self, test):
    return not self.filters or any(name in test.id() for name in self.filters)

  def run(self, suite):
    filtered_test = FilterSuite(suite, self.ShouldTestRun)
    return super(_RunnerImpl, self).run(filtered_test)


class TestRunner(object):
  def __init__(self):
    self._loader = _TestLoader()

  def AddDirectory(self, dir_path, test_file_pattern="*test.py"):
    assert os.path.isdir(dir_path)

    self._loader.discover_calls.append((dir_path, test_file_pattern, dir_path))

  def Main(self, argv=None):
    if argv is None:
      argv = sys.argv

    parser = optparse.OptionParser()
    options, args = parser.parse_args(argv[1:])

    runner = _RunnerImpl(filters=args)
    return unittest.main(module=__name__, argv=[sys.argv[0]],
                         testLoader=self._loader,
                         testRunner=runner)
