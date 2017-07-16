#!/usr/bin/env python
# Copyright 2016 Google Inc. All Rights Reserved.
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

import unittest
import urllib2


def _IsInternetOn():
  try:
    urllib2.urlopen('https://example.com', timeout=10)
    return True
  except urllib2.URLError as err:
    return False


class RealNetworkFetchTest(unittest.TestCase):
  def setUp(self):
    if not _IsInternetOn():
      self.skipTest('No internet, skip test')
