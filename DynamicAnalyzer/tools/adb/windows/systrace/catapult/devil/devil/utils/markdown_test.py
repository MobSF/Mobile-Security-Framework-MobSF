#! /usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import textwrap
import unittest

if __name__ == '__main__':
  sys.path.append(
      os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from devil.utils import markdown


class MarkdownTest(unittest.TestCase):

  def testBold(self):
    raw = 'foo'
    self.assertEquals('**foo**', markdown.md_bold(raw))

  def testBoldContainsStars(self):
    raw = '*foo*'
    self.assertEquals('**\\*foo\\***', markdown.md_bold(raw))

  def testCode(self):
    raw = textwrap.dedent("""\
        class MarkdownTest(unittest.TestCase):
          def testCode(self):
            pass""")

    expected = textwrap.dedent("""\
        ```python
        class MarkdownTest(unittest.TestCase):
          def testCode(self):
            pass
        ```
        """)
    actual = markdown.md_code(raw, language='python')
    self.assertEquals(expected, actual)

  def testCodeContainsTicks(self):
    raw = textwrap.dedent("""\
        This is sample markdown.
        ```c
        // This is a sample code block.
        int main(int argc, char** argv) {
          return 0;
        }
        ```""")

    expected = textwrap.dedent("""\
        ```
        This is sample markdown.
        \\`\\`\\`c
        // This is a sample code block.
        int main(int argc, char** argv) {
          return 0;
        }
        \\`\\`\\`
        ```
        """)
    actual = markdown.md_code(raw, language=None)
    self.assertEquals(expected, actual)

  def testEscape(self):
    raw = 'text_with_underscores *and stars*'
    expected = 'text\\_with\\_underscores \\*and stars\\*'
    actual = markdown.md_escape(raw)
    self.assertEquals(expected, actual)

  def testHeading1(self):
    raw = 'Heading 1'
    self.assertEquals('# Heading 1', markdown.md_heading(raw, level=1))

  def testHeading5(self):
    raw = 'Heading 5'
    self.assertEquals('##### Heading 5', markdown.md_heading(raw, level=5))

  def testHeading10(self):
    raw = 'Heading 10'
    self.assertEquals('###### Heading 10', markdown.md_heading(raw, level=10))

  def testInlineCode(self):
    raw = 'devil.utils.markdown_test'
    self.assertEquals(
        '`devil.utils.markdown_test`', markdown.md_inline_code(raw))

  def testInlineCodeContainsTicks(self):
    raw = 'this contains `backticks`'
    self.assertEquals(
        '`this contains \\`backticks\\``', markdown.md_inline_code(raw))

  def testItalic(self):
    raw = 'bar'
    self.assertEquals('*bar*', markdown.md_italic(raw))

  def testItalicContainsStars(self):
    raw = '*bar*'
    self.assertEquals('*\\*bar\\**', markdown.md_italic(raw))

  def testLink(self):
    link_text = 'Devil home'
    link_target = (
        'https://github.com/catapult-project/catapult/tree/master/devil')
    expected = (
        '[Devil home]'
        '(https://github.com/catapult-project/catapult/tree/master/devil)')
    self.assertEquals(expected, markdown.md_link(link_text, link_target))

  def testLinkTextContainsBracket(self):
    link_text = 'foo [] bar'
    link_target = 'https://www.google.com'
    expected = '[foo [\\] bar](https://www.google.com)'
    self.assertEquals(expected, markdown.md_link(link_text, link_target))


if __name__ == '__main__':
  unittest.main(verbosity=2)
