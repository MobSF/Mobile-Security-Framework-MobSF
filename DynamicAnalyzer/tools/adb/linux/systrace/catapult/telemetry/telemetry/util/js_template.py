# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import re


RE_REPLACEMENT_FIELD = re.compile(r'{{(?P<field_spec>[^}]*)}}')
RE_FIELD_IDENTIFIER = re.compile(r'(?P<modifier>[@*])?(?P<name>\w+)$')


def RenderValue(value):
  """Convert a Python value to a string with its JavaScript representation."""
  return json.dumps(value, sort_keys=True)


def Render(template, **kwargs):
  """Helper method to interpolate Python values into JavaScript snippets.

  Placeholders in the template, field names enclosed in double curly braces,
  are replaced with the value of the corresponding named argument.

  Prefixing a field name with '*' causes the value, expected to be a
  sequence of individual values, to be all interpolated and separated by
  commas.

  Prefixing a field name with '@' causes the value to be inserted literally.


  For example:

    js_template.Render(
      'var {{ @var_name }} = f({{ x }}, {{ *args }});',
      var_name='foo', x=42, args=('hello', 'there'))

  Returns:

    'var foo = f(42, "hello", "there");'

  Args:
    template: A string with a JavaScript template, tagged with {{ fields }}
      to interpolate with values.
    **kwargs: Values to be interpolated in the template.
  """
  unused = set(kwargs)

  def interpolate(m):
    field_spec = m.group('field_spec').strip()
    field = RE_FIELD_IDENTIFIER.match(field_spec)
    if not field:
      raise KeyError(field_spec)
    key = field.group('name')
    value = kwargs[key]
    unused.discard(key)
    if field.group('modifier') == '@':
      if not isinstance(value, str):
        raise ValueError('Literal value for %s must be a string' % field_spec)
      return value
    elif field.group('modifier') == '*':
      return ', '.join(RenderValue(v) for v in value)
    else:
      return RenderValue(value)

  result = RE_REPLACEMENT_FIELD.sub(interpolate, template)
  if unused:
    raise TypeError('Unexpected arguments not used in template: %s.' % (
      ', '.join(repr(str(k)) for k in sorted(unused))))
  return result
