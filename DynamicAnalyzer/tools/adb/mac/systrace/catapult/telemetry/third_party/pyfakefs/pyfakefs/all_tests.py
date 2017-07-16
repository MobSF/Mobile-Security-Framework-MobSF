#! /usr/bin/env python
#
# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A test suite that runs all tests for pyfakefs at once."""

import unittest

import fake_filesystem_glob_test
import fake_filesystem_shutil_test
import fake_filesystem_test
import fake_filesystem_vs_real_test
import fake_tempfile_test
import fake_filesystem_unittest_test
import example_test


class AllTests(unittest.TestSuite):
  """A test suite that runs all tests for pyfakefs at once."""

  def suite(self):  # pylint: disable-msg=C6409
    loader = unittest.defaultTestLoader
    self.addTests([
        loader.loadTestsFromModule(fake_filesystem_test),
        loader.loadTestsFromModule(fake_filesystem_glob_test),
        loader.loadTestsFromModule(fake_filesystem_shutil_test),
        loader.loadTestsFromModule(fake_tempfile_test),
        loader.loadTestsFromModule(fake_filesystem_vs_real_test),
        loader.loadTestsFromModule(fake_filesystem_unittest_test),
        loader.loadTestsFromModule(example_test),
    ])
    return self

if __name__ == '__main__':
  unittest.TextTestRunner(verbosity=2).run(AllTests().suite())
