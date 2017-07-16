#!/usr/bin/env python
# Copyright 2013 Google Inc. All Rights Reserved.
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

import datetime
import httparchive
import mock
import script_injector
import unittest


LONG_COMMENT = '<!--' + 'comment,' * 200 + '-->'
COMMENT_OR_NOT = ('', LONG_COMMENT)
SCRIPT_TO_INJECT = 'var flag = 0;'
EXPECTED_SCRIPT = '<script>' + SCRIPT_TO_INJECT + '</script>'
TEXT_HTML = 'text/html'
TEXT_CSS = 'text/css'
APPLICATION = 'application/javascript'
SEPARATOR = httparchive.ArchivedHttpResponse.CHUNK_EDIT_SEPARATOR
SEPARATORS_OR_NOT = ('', SEPARATOR, SEPARATOR*3)

TEMPLATE_HEAD = """\
{boundary_at_start}\
<!doc{boundary_in_doctype}type html>{boundary_after_doctype}\
<ht{boundary_in_html}ml>{boundary_after_html}\
<he{boundary_in_head}ad>{injection}{boundary_after_head}\
</head></html>\
"""
TEMPLATE_HTML = """\
{boundary_at_start}\
<!doc{boundary_in_doctype}type html>{boundary_after_doctype}\
<ht{boundary_in_html}ml>{injection}{boundary_after_html}\
</html>\
"""
TEMPLATE_DOCTYPE = """\
{boundary_at_start}\
<!doc{boundary_in_doctype}type html>{injection}{boundary_after_doctype}\
<body></body>\
"""
TEMPLATE_RAW = """\
{boundary_at_start}\
{injection}<body></body>\
"""
NORMAL_TEMPLATES = (TEMPLATE_HEAD, TEMPLATE_HTML,
                    TEMPLATE_DOCTYPE, TEMPLATE_RAW)
TEMPLATE_COMMENT = """\
{comment_before_doctype}<!doctype html>{comment_after_doctype}\
<html>{comment_after_html}<head>{injection}</head></html>\
"""


def _wrap_inject_script(source, application, script_to_inject):
  text_chunks = source.split(SEPARATOR)
  text_chunks, just_injected = script_injector.InjectScript(
      text_chunks, application, script_to_inject)
  result = SEPARATOR.join(text_chunks)
  return result, just_injected


class ScriptInjectorTest(unittest.TestCase):

  def _assert_no_injection(self, source, application):
    new_source, just_injected = _wrap_inject_script(
        source, application, SCRIPT_TO_INJECT)
    self.assertEqual(new_source, source)
    self.assertFalse(just_injected)

  def _assert_successful_injection(self, template):
    source, just_injected = _wrap_inject_script(
        template.format(injection=''), TEXT_HTML, SCRIPT_TO_INJECT)
    self.assertEqual(source, template.format(injection=EXPECTED_SCRIPT))
    self.assertTrue(just_injected)

  def test_unsupported_content_type(self):
    self._assert_no_injection('abc', TEXT_CSS)
    self._assert_no_injection('abc', APPLICATION)

  def test_empty_content_as_already_injected(self):
    self._assert_no_injection('', TEXT_HTML)

  def test_non_html_content_with_html_content_type(self):
    self._assert_no_injection('{"test": 1"}', TEXT_HTML)

  def test_already_injected(self):
    parameters = {'injection': SCRIPT_TO_INJECT}
    for template in NORMAL_TEMPLATES:
      for parameters['boundary_at_start'] in SEPARATORS_OR_NOT:
        for parameters['boundary_in_doctype'] in SEPARATORS_OR_NOT:
          for parameters['boundary_after_doctype'] in SEPARATORS_OR_NOT:
            for parameters['boundary_in_html'] in SEPARATORS_OR_NOT:
              for parameters['boundary_after_html'] in SEPARATORS_OR_NOT:
                for parameters['boundary_in_head'] in SEPARATORS_OR_NOT:
                  for parameters['boundary_after_head'] in SEPARATORS_OR_NOT:
                    source = template.format(**parameters)
                    self._assert_no_injection(source, TEXT_HTML)

  def test_normal(self):
    parameters = {'injection': '{injection}'}
    for template in NORMAL_TEMPLATES:
      for parameters['boundary_at_start'] in SEPARATORS_OR_NOT:
        for parameters['boundary_in_doctype'] in SEPARATORS_OR_NOT:
          for parameters['boundary_after_doctype'] in SEPARATORS_OR_NOT:
            for parameters['boundary_in_html'] in SEPARATORS_OR_NOT:
              for parameters['boundary_after_html'] in SEPARATORS_OR_NOT:
                for parameters['boundary_in_head'] in SEPARATORS_OR_NOT:
                  for parameters['boundary_after_head'] in SEPARATORS_OR_NOT:
                    template = template.format(**parameters)
                    self._assert_successful_injection(template)

  def test_comments(self):
    parameters = {'injection': '{injection}'}
    for parameters['comment_before_doctype'] in COMMENT_OR_NOT:
      for parameters['comment_after_doctype'] in COMMENT_OR_NOT:
        for parameters['comment_after_html'] in COMMENT_OR_NOT:
          template = TEMPLATE_COMMENT.format(**parameters)
          self._assert_successful_injection(template)

  @mock.patch('script_injector.os.path.exists', return_value=True)
  @mock.patch('script_injector.open',
              mock.mock_open(read_data='var time_seed = 123;'))
  def test_injection_function(self, _):
    injector = script_injector.GetScriptInjector('to_inject.js')
    self.assertEqual('var time_seed=123;',
                     injector(datetime.datetime.utcnow()))

  @mock.patch('script_injector.os.path.exists', return_value=True)
  @mock.patch('script_injector.open',
              mock.mock_open(
                  read_data='var time_seed = {{WPR_TIME_SEED_TIMESTAMP}};'))
  def test_time_seed_replacement(self, _):
    date = datetime.datetime(2016, 11, 17)
    injector = script_injector.GetScriptInjector('date.js')
    self.assertEqual('var time_seed=1479340800000;', injector(date))


if __name__ == '__main__':
  unittest.main()
