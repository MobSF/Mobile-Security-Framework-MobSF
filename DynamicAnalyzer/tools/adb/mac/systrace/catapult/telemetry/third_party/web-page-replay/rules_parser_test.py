# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Unit tests for rules_parser.  Usage: ./rules_parser_test.py"""

import collections
import logging
from StringIO import StringIO
import unittest

import rules_parser


class RuleParserTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    if not logging.root.handlers:
      logging.basicConfig(level=logging.DEBUG,  # Enable log_url stdout.
                          format='%(asctime)s %(levelname)s %(message)s')

  def testCall(self):
    my_rules = rules_parser.Rules(StringIO(r'''
        [{"comment": "ignore me"},
         {"LogUrl": {"url": "example\\.com/ss.*"}},
         {"LogUrl": {"url": "example\\.com/blah$"}}]'''))
    log_url = my_rules.Find('log_url')
    self.assertEquals(True, log_url(FakeRequest(full_path='/ss'), None))
    self.assertEquals(True, log_url(FakeRequest(full_path='/ssxxxx'), None))
    self.assertEquals(True, log_url(FakeRequest(full_path='/blah'), None))
    self.assertEquals(None, log_url(FakeRequest(full_path='/blahxxx'), None))
    self.assertEquals(None, log_url(FakeRequest(full_path='/'), None))

  def testImport(self):
    my_rules = rules_parser.Rules(StringIO(r'''
        [{"rules.LogUrl": {"url": "example\\.com/ss.*"}}]'''))
    self.assertTrue(my_rules.Contains('log_url'))

  def testRaises(self):
    input_pairs = [
        'bad_json',
        '123',
        '{}',
        '[42]',
        '[{12:34}]',
        '[{"a":"b","c":"d"}]',
        '[{"bad+rule@name":{}}]',
        '["unallowed.Path":{}]',
        '["NoSuchRule":{}]',
        '["LogUrl":"bad"]',
        '["LogUrl":{}]',
        '["LogUrl":{"url":123}]',
        '["LogUrl":{"url":"", "bad_arg":123}]',
    ]
    for input_text in input_pairs:
      self.assertRaises(Exception, rules_parser.Rules, StringIO(input_text))


class FakeRequest(collections.namedtuple(
    'FakeRequest', ('command', 'host', 'full_path', 'request_body',
                    'headers', 'is_ssl'))):

  def __new__(cls, command='GET', host='example.com', full_path='/',
              request_body=None, headers=None, is_ssl=False):
    return super(FakeRequest, cls).__new__(
        cls, command, host, full_path, request_body, headers or {}, is_ssl)


if __name__ == '__main__':
  unittest.main()
