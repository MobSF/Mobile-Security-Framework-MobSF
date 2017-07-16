# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.util import js_template


class JavaScriptTemplateTest(unittest.TestCase):
  def testRenderSimple(self):
    self.assertEquals(
        js_template.Render(
            'foo({{ a }}, {{ b }}, {{ c }})',
            a=42, b='hello', c=['x', 'y']),
        'foo(42, "hello", ["x", "y"])')

  def testRenderWithSpecialCharts(self):
    self.assertEquals(
        js_template.Render(
            'function(elem) { return elem.find({{ selector }}); }',
            selector='.r > a[href*="wikipedia"]'),
        r'function(elem) { return elem.find(".r > a[href*=\"wikipedia\"]"); }')

  def testRenderWithLiteralValues(self):
    self.assertEquals(
        js_template.Render(
            'var {{ @var_name }} = {{ x }} + {{ y }};',
            var_name='foo', x='bar', y=None),
        'var foo = "bar" + null;')

  def testRenderWithArgumentExpansion(self):
    self.assertEquals(
        js_template.Render(
            '{{ @f }}({{ *args }})', f='foo', args=(1, 'hi!', None)),
        'foo(1, "hi!", null)')

  def testRenderRaisesWithUnknownIdentifier(self):
    with self.assertRaises(KeyError):
      js_template.Render('foo({{ some_name }})', another_name='bar')

  def testRenderRaisesWithBadIdentifier(self):
    with self.assertRaises(KeyError):
      js_template.Render('foo({{ bad identifier name }})', name='bar')

  def testRenderRaisesWithBadLiteralValue(self):
    with self.assertRaises(ValueError):
      js_template.Render('function() { {{ @code }} }', code=['foo', 'bar'])

  def testRenderRaisesWithUnusedKeywordArgs(self):
    with self.assertRaises(TypeError):
      js_template.Render('foo = {{ x }};', x=4, y=5, timemout=6)
